/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "util/rx_layout_capture.h"
#include <chrono>
#include <gtest/gtest.h>
#include <new>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
using namespace xlio_rx_layout;

TEST(rx_layout_capture, idle_then_exact_bounded_batch)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 123, 7));
    EXPECT_EQ(0U, begin(s));
    ASSERT_TRUE(arm(s, s.control.load(), 2));
    record r {};
    r.payload_bytes = 8960;
    auto token = begin(s);
    ASSERT_NE(0U, token);
    publish_attempt(s, token, &r);
    EXPECT_EQ(1U, s.progress.load());
    batch b;
    EXPECT_FALSE(reader_copy(s, b));
    token = begin(s);
    ASSERT_NE(0U, token);
    r.payload_bytes = 17920;
    publish_attempt(s, token, &r);
    EXPECT_EQ(0U, begin(s));
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(2U, b.count);
    EXPECT_EQ(8960U, b.records[0].payload_bytes);
    EXPECT_EQ(17920U, b.records[1].payload_bytes);
    EXPECT_EQ(123U, b.ring_id);
    EXPECT_EQ(7U, b.if_index);
    EXPECT_EQ(phase::idle, state(s.control.load()));
}
TEST(rx_layout_capture, cannot_rearm_or_read_partial_capture)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    ASSERT_FALSE(arm(s, s.control.load(), 0));
    ASSERT_FALSE(arm(s, s.control.load(), capacity + 1));
    ASSERT_TRUE(arm(s, s.control.load(), 3));
    EXPECT_FALSE(arm(s, s.control.load(), 2));
    record r {};
    publish_attempt(s, begin(s), &r);
    EXPECT_FALSE(arm(s, s.control.load(), 2));
    batch b;
    EXPECT_FALSE(reader_copy(s, b));
    EXPECT_EQ(1U, s.progress.load());
}
TEST(rx_layout_capture, unsupported_traffic_has_bounded_work)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 2));
    for (unsigned i = 0; i < 8; ++i) {
        auto token = begin(s);
        ASSERT_NE(0U, token);
        publish_attempt(s, token, nullptr);
    }
    EXPECT_EQ(0U, begin(s));
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(0U, b.count);
    EXPECT_EQ(8U, b.excluded);
}
TEST(rx_layout_capture, close_publishes_partial_and_reuse_changes_generation)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    auto old = s.control.load();
    ASSERT_TRUE(arm(s, old, 2));
    record r {};
    r.payload_bytes = 42;
    publish_attempt(s, begin(s), &r);
    xlio_rx_layout::close(s);
    EXPECT_FALSE(register_slot(s, 2, 2));
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_TRUE(b.closed);
    EXPECT_EQ(1U, b.count);
    EXPECT_EQ(42U, b.records[0].payload_bytes);
    ASSERT_TRUE(register_slot(s, 2, 2));
    EXPECT_FALSE(arm(s, old, 1));
    EXPECT_NE(old >> 32, s.control.load() >> 32);
}
TEST(rx_layout_capture, close_armed_does_not_publish_previous_records)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    publish_attempt(s, begin(s), &r);
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    xlio_rx_layout::close(s);
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(0U, b.count);
    EXPECT_TRUE(b.closed);
}
TEST(rx_layout_capture, close_during_read_keeps_records_pinned)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    r.payload_bytes = 99;
    publish_attempt(s, begin(s), &r);
    uint64_t token;
    ASSERT_TRUE(reader_claim(s, token));
    xlio_rx_layout::close(s);
    EXPECT_FALSE(register_slot(s, 2, 2));
    EXPECT_EQ(99U, s.records[0].payload_bytes);
    reader_release(s);
    EXPECT_TRUE(register_slot(s, 2, 2));
}
TEST(rx_layout_capture, new_exclusive_reader_recovers_interrupted_copy)
{
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    ASSERT_TRUE(arm(s, s.control.load(), 1));
    record r {};
    publish_attempt(s, begin(s), &r);
    uint64_t token;
    ASSERT_TRUE(reader_claim(s, token));
    recover_reader(s);
    batch b;
    ASSERT_TRUE(reader_copy(s, b));
    EXPECT_EQ(1U, b.count);
    EXPECT_EQ(1U, b.sequence);
}
TEST(rx_layout_capture, shared_mapping_publishes_complete_records_between_processes)
{
    void *memory =
        mmap(nullptr, sizeof(slot), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, memory);
    auto *s = new (memory) slot;
    ASSERT_TRUE(register_slot(*s, 123, 7));
    ASSERT_TRUE(arm(*s, s->control.load(), capacity));
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        for (unsigned i = 0; i < capacity; ++i) {
            record r {};
            r.frame_bytes = i;
            r.payload_bytes = i ^ 0x12345678U;
            r.payload_offset = i ^ 0x87654321U;
            publish_attempt(*s, begin(*s), &r);
        }
        _exit(0);
    }
    batch b;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool copied = false;
    while (!(copied = reader_copy(*s, b)) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    int status;
    ASSERT_EQ(child, waitpid(child, &status, 0));
    ASSERT_TRUE(copied);
    EXPECT_EQ(0, status);
    ASSERT_EQ(capacity, b.count);
    for (unsigned i = 0; i < capacity; ++i) {
        EXPECT_EQ(i, b.records[i].frame_bytes);
        EXPECT_EQ(i ^ 0x12345678U, b.records[i].payload_bytes);
        EXPECT_EQ(i ^ 0x87654321U, b.records[i].payload_offset);
    }
    s->~slot();
    EXPECT_EQ(0, munmap(memory, sizeof(slot)));
}

TEST(rx_layout_capture, repeated_process_handoffs_do_not_mix_batches)
{
    void *memory =
        mmap(nullptr, sizeof(slot), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, memory);
    auto *s = new (memory) slot;
    ASSERT_TRUE(register_slot(*s, 123, 7));
    constexpr unsigned rounds = 512;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        for (unsigned round = 0; round < rounds; ++round) {
            uint64_t token = 0;
            while (!(token = begin(*s))) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    _exit(2);
                }
                std::this_thread::yield();
            }
            for (unsigned i = 0; i < capacity; ++i) {
                record r {};
                r.frame_bytes = round;
                r.payload_bytes = i;
                r.payload_offset = round ^ i ^ 0x87654321U;
                publish_attempt(*s, token, &r);
            }
        }
        _exit(0);
    }
    bool valid = true;
    for (unsigned round = 0; round < rounds && valid; ++round) {
        valid = arm(*s, s->control.load(), capacity);
        batch b;
        bool copied = false;
        while (valid && !(copied = reader_copy(*s, b)) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        valid = valid && copied && b.count == capacity && b.sequence == round + 1;
        for (unsigned i = 0; i < b.count && valid; ++i) {
            const auto &r = b.records[i];
            valid = r.frame_bytes == round && r.payload_bytes == i &&
                r.payload_offset == (round ^ i ^ 0x87654321U);
        }
    }
    if (!valid) {
        kill(child, SIGKILL);
    }
    int status = 0;
    EXPECT_EQ(child, waitpid(child, &status, 0));
    EXPECT_EQ(0, status);
    EXPECT_TRUE(valid);
    s->~slot();
    EXPECT_EQ(0, munmap(memory, sizeof(slot)));
}
