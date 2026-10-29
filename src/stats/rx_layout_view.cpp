/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "core/util/xlio_stats.h"
#include "rx_layout_summary.h"
#include "rx_layout_view.h"
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <signal.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace {
volatile sig_atomic_t capture_stopped = 0;
void stop_capture(int)
{
    capture_stopped = 1;
}
struct mapping {
    int fd = -1;
    void *address = MAP_FAILED;
    size_t size = 0;
    ~mapping()
    {
        if (address != MAP_FAILED) {
            munmap(address, size);
        }
        if (fd >= 0) {
            close(fd);
        }
    }
};
struct signals {
    struct sigaction old_int {
    }, old_term {};
    signals()
    {
        capture_stopped = 0;
        struct sigaction action {};
        action.sa_handler = stop_capture;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, &old_int);
        sigaction(SIGTERM, &action, &old_term);
    }
    ~signals()
    {
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
    }
};

void print_batch(unsigned index, const xlio_rx_layout::batch &b)
{
    using namespace xlio_rx_layout;
    printf("Ring %u id=0x%" PRIx64 " ifindex=%u generation=%" PRIu64 " batch=%" PRIu64
           ": %u/%u samples, inspected=%u excluded=%u%s\n",
           index, b.ring_id, b.if_index, b.generation, b.sequence, b.count, b.requested,
           b.inspected, b.excluded, b.closed ? " (closed)" : "");
    if (!b.count) {
        printf("  No traffic (no eligible TCP samples)\n");
        return;
    }
    auto s = summarize(b);
    printf(" Count   Share RQ   IP LRO Prefix Hdr L2/IP/TCP   Frame Payload "
           "Offset A%%64 L%%64 Flags\n");
    for (const auto &row : s.rows) {
        const auto &r = row.layout;
        printf(" %5u %6.2f%% %-4s %u %3u %6u %3u %2u/%2u/%2u %8u %7u %6u %4u %4u "
               "0x%02x\n",
               row.count, 100.0 * row.count / b.count, r.striding ? "STRQ" : "RQ", r.ip_version,
               r.lro_segments, r.prefix_bytes, r.l2_bytes + r.l3_bytes + r.tcp_bytes, r.l2_bytes,
               r.l3_bytes, r.tcp_bytes, r.frame_bytes, r.payload_bytes, r.payload_offset,
               r.payload_mod64, r.payload_bytes % 64, r.tcp_flags);
    }
    printf(" Data=%u, control-only=%u", s.data, s.control);
    if (s.data) {
        printf("; data alignment: offset=64 %.2f%%, address%%64=0 %.2f%%, "
               "length%%64=0 %.2f%%",
               100.0 * s.offset64 / s.data, 100.0 * s.address64 / s.data,
               100.0 * s.length64 / s.data);
    }
    printf("\n");
}
} // namespace

int print_rx_layout(int pid, const std::string &directory, unsigned samples, int interval,
                    int cycles)
{
    using namespace xlio_rx_layout;
    if (interval < 1 || samples < 1 || samples > capacity || cycles < 0) {
        fprintf(stderr, "xliostat: RX layout needs interval >= 1 and samples in [1, %u]\n",
                capacity);
        return 1;
    }
    const std::string path = directory + "/xliostat." + std::to_string(pid);
    mapping m;
    m.fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (m.fd < 0) {
        fprintf(stderr, "xliostat: RX capture needs read/write access to %s: %s\n", path.c_str(),
                strerror(errno));
        return 1;
    }
    if (flock(m.fd, LOCK_EX | LOCK_NB) != 0) {
        fprintf(stderr, "xliostat: RX capture is busy or cannot be locked: %s\n", strerror(errno));
        return 1;
    }
    struct stat info {};
    if (fstat(m.fd, &info) || info.st_size < static_cast<off_t>(sizeof(sh_mem_t))) {
        fprintf(stderr, "xliostat: incomplete statistics header\n");
        return 1;
    }
    m.size = sizeof(sh_mem_t);
    m.address = mmap(nullptr, m.size, PROT_READ, MAP_SHARED, m.fd, 0);
    if (m.address == MAP_FAILED) {
        fprintf(stderr, "xliostat: cannot map statistics header: %s\n", strerror(errno));
        return 1;
    }
    auto *header = static_cast<const sh_mem_t *>(m.address);
    if (memcmp(header->stats_protocol_ver, STATS_PROTOCOL_VER,
               std::min(sizeof(header->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER))) != 0) {
        fprintf(stderr, "xliostat: incompatible statistics protocol\n");
        return 1;
    }
    size_t sockets = header->max_skt_inst_num;
    const size_t limit =
        (std::numeric_limits<size_t>::max() - sizeof(sh_mem_t) - sizeof(region) - 63U) /
        sizeof(socket_instance_block_t);
    if (sockets > limit) {
        fprintf(stderr, "xliostat: invalid statistics size\n");
        return 1;
    }
    size_t offset = extension_offset(SHMEM_STATS_SIZE(sockets));
    size_t full_size = offset + sizeof(region);
    if (static_cast<uint64_t>(info.st_size) < full_size) {
        fprintf(stderr, "xliostat: RX layout capture is not supported by this library\n");
        return 1;
    }
    munmap(m.address, m.size);
    m.size = full_size;
    m.address = mmap(nullptr, m.size, PROT_READ | PROT_WRITE, MAP_SHARED, m.fd, 0);
    if (m.address == MAP_FAILED) {
        fprintf(stderr, "xliostat: cannot map RX capture: %s\n", strerror(errno));
        return 1;
    }
    auto *capture = reinterpret_cast<region *>(static_cast<char *>(m.address) + offset);
    if (!valid_region(*capture)) {
        fprintf(stderr, "xliostat: unsupported RX capture version or record layout\n");
        return 1;
    }
    signals signal_guard;
    for (auto &s : capture->slots) {
        recover_reader(s);
        arm(s, s.control.load(std::memory_order_acquire), samples);
    }
    printf("xliostat: RX layout samples for pid %d; up to %u records/ring every "
           "%ds\n",
           pid, samples, interval);
    printf("Sizes describe RX completions; LRO aggregates do not reveal every "
           "wire segment.\n");
    fflush(stdout);
    for (int cycle = 0; !capture_stopped && (!cycles || cycle < cycles); ++cycle) {
        struct timespec delay {
            interval, 0
        };
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR && !capture_stopped) {
        }
        if (capture_stopped) {
            break;
        }
        printf("\nCapture update %d\n", cycle + 1);
        bool shown = false;
        for (unsigned i = 0; i < max_rings; ++i) {
            auto &s = capture->slots[i];
            batch b;
            if (reader_copy(s, b)) {
                print_batch(i, b);
                shown = true;
            } else {
                auto token = s.control.load(std::memory_order_acquire);
                if (state(token) == phase::idle && arm(s, token, samples)) {
                    token = s.control.load(std::memory_order_acquire);
                }
                if (state(token) == phase::armed || state(token) == phase::filling) {
                    // Slot identity stays pinned until this request has been consumed.
                    auto n = s.progress.load(std::memory_order_acquire);
                    printf("Ring %u ifindex=%u: %s (excluded=%u)\n", i, s.if_index,
                           progress_text(state(token), n, target(token)).c_str(),
                           state(token) == phase::armed
                               ? 0
                               : s.excluded.load(std::memory_order_relaxed));
                    shown = true;
                }
            }
            if (!cycles || cycle + 1 < cycles) {
                arm(s, s.control.load(std::memory_order_acquire), samples);
            }
        }
        if (!shown) {
            printf("No traffic (no active capture rings)\n");
        }
        auto failures = capture->registration_failures.load(std::memory_order_relaxed);
        if (failures) {
            printf("Capture coverage limited: %u ring registrations had no free "
                   "capture slot\n",
                   failures);
        }
        fflush(stdout);
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            printf("xliostat: target process exited\n");
            break;
        }
    }
    return 0;
}
