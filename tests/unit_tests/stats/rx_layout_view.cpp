/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "config.h"
#include <gtest/gtest.h>
#include "stats/rx_layout_view.h"
#include "core/util/rx_layout_capture.h"
#include "core/util/xlio_stats.h"
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <iterator>
#include <chrono>
#include <thread>
#include <cstring>
using namespace xlio_rx_layout;

class rx_layout_view : public ::testing::Test {
protected:
    std::string directory, path, output;
    int fd = -1;
    void *memory = MAP_FAILED;
    size_t offset = extension_offset(SHMEM_STATS_SIZE(64));
    size_t bytes = offset + sizeof(region);
    region *capture = nullptr;
    pid_t child = -1;
    void SetUp() override
    {
        char name[] = "/tmp/xlio-rx-layout-XXXXXX";
        ASSERT_NE(nullptr, mkdtemp(name));
        directory = name;
        path = directory + "/xliostat." + std::to_string(getpid());
        output = directory + "/output";
        fd = open(path.c_str(), O_CREAT | O_RDWR, 0600);
        ASSERT_GE(fd, 0);
        ASSERT_EQ(0, ftruncate(fd, bytes));
        memory = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        ASSERT_NE(MAP_FAILED, memory);
        auto *header = static_cast<sh_mem_t *>(memory);
        memcpy(header->stats_protocol_ver, STATS_PROTOCOL_VER,
               std::min(sizeof(header->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER)));
        header->max_skt_inst_num = 64;
        capture = new (static_cast<char *>(memory) + offset) region;
        ASSERT_TRUE(register_slot(capture->slots[0], 123, 7));
    }
    void TearDown() override
    {
        if (child > 0) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
        }
        if (memory != MAP_FAILED) {
            munmap(memory, bytes);
        }
        if (fd >= 0) {
            ::close(fd);
        }
        unlink(output.c_str());
        unlink(path.c_str());
        rmdir(directory.c_str());
    }
    void launch(unsigned samples, int cycles)
    {
        pid_t target_pid = getpid();
        fflush(nullptr);
        child = fork();
        ASSERT_GE(child, 0);
        if (child == 0) {
            int out = open(output.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
            if (out < 0) {
                _exit(3);
            }
            dup2(out, STDOUT_FILENO);
            dup2(out, STDERR_FILENO);
            ::close(out);
            int result = print_rx_layout(target_pid, directory, samples, 1, cycles);
            fflush(nullptr);
            _exit(result);
        }
    }
    std::string text()
    {
        std::ifstream in(output);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    bool await_text(const std::string &wanted)
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(6);
        while (std::chrono::steady_clock::now() < deadline) {
            if (text().find(wanted) != std::string::npos) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    }
    int finish()
    {
        int status = 0;
        if (waitpid(child, &status, 0) != child) {
            return -1;
        }
        child = -1;
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
};
TEST_F(rx_layout_view, no_traffic_then_partial_then_complete)
{
    launch(2, 3);
    ASSERT_TRUE(await_text("No traffic"));
    auto &s = capture->slots[0];
    record r {};
    r.frame_bytes = 128;
    r.payload_bytes = 64;
    r.payload_offset = 64;
    publish_attempt(s, begin(s), &r);
    ASSERT_TRUE(await_text("Collecting samples (1/2)"));
    publish_attempt(s, begin(s), &r);
    ASSERT_EQ(0, finish());
    EXPECT_NE(std::string::npos, text().find("2/2 samples"));
    EXPECT_NE(std::string::npos, text().find("length%64=0 100.00%"));
    EXPECT_EQ(phase::idle, state(s.control.load()));
}
TEST_F(rx_layout_view, exclusive_lock_rejects_second_reader)
{
    ASSERT_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
    launch(1, 1);
    EXPECT_EQ(1, finish());
    EXPECT_NE(std::string::npos, text().find("busy"));
    EXPECT_EQ(0, flock(fd, LOCK_UN));
}
TEST_F(rx_layout_view, rejects_old_extension_and_wrong_version)
{
    ASSERT_EQ(0, ftruncate(fd, offset));
    launch(1, 1);
    EXPECT_EQ(1, finish());
    EXPECT_NE(std::string::npos, text().find("not supported"));
    ASSERT_EQ(0, ftruncate(fd, bytes));
    capture = new (static_cast<char *>(memory) + offset) region;
    capture->abi_version = version + 1;
    launch(1, 1);
    EXPECT_EQ(1, finish());
    EXPECT_NE(std::string::npos, text().find("unsupported RX capture version"));
}
TEST_F(rx_layout_view, adopts_interrupted_reader_and_closed_batch)
{
    auto &s = capture->slots[0];
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    r.payload_bytes = 64;
    publish_attempt(s, begin(s), &r);
    uint64_t token;
    ASSERT_TRUE(reader_claim(s, token));
    xlio_rx_layout::close(s);
    launch(1, 1);
    EXPECT_EQ(0, finish());
    EXPECT_NE(std::string::npos, text().find("1/1 samples"));
    EXPECT_NE(std::string::npos, text().find("(closed)"));
    EXPECT_EQ(phase::free, state(s.control.load()));
}
