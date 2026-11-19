/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#pragma once

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace tx_snapshot {
constexpr size_t limit = 1000;

constexpr unsigned event_limit = 100000;

struct output_state {
    pthread_once_t once = PTHREAD_ONCE_INIT;
    int fd = -1;
    std::atomic<unsigned> events {0};
};

inline output_state &output()
{
    static output_state state;
    return state;
}

inline void reset_child_output()
{
    auto &state = output();
    if (state.fd >= 0) {
        syscall(SYS_close, state.fd);
    }
    state.fd = -1;
    state.once = PTHREAD_ONCE_INIT;
    state.events.store(0, std::memory_order_relaxed);
}

inline void open_output()
{
    char path[80];
    snprintf(path, sizeof(path), "/tmp/xlio-tx-%ld-XXXXXX.log", (long)getpid());
    auto &state = output();
    state.fd = mkostemps(path, 4, O_CLOEXEC | O_APPEND);
    if (state.fd < 0) {
        perror(path);
        state.events.store(event_limit, std::memory_order_relaxed);
    }
}

// Claim a slot before reading the application buffer or decoding a WQE.
inline bool reserve_event()
{
    auto &state = output();
    unsigned used = state.events.load(std::memory_order_relaxed);
    if (used >= event_limit) {
        return false;
    }
    static const int fork_handler = pthread_atfork(nullptr, nullptr, reset_child_output);
    (void)fork_handler;
    int saved = errno;
    pthread_once(&state.once, open_output);
    errno = saved;
    while (used < event_limit) {
        if (state.events.compare_exchange_weak(used, used + 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

inline void record(const char *event, unsigned qp, unsigned wqe, const unsigned char *bytes,
                   size_t size, const char *storage, const size_t *requested_bytes = nullptr)
{
    const char hex[] = "0123456789abcdef";
    constexpr size_t group_size = 16;
    char line[2 * limit + (limit - 1) / group_size + 160];
    int n =
        snprintf(line, sizeof(line), "%s pid=%ld qp=%u wqe=%u ", event, (long)getpid(), qp, wqe);
    if (requested_bytes) {
        n += snprintf(line + n, sizeof(line) - n, "requested_bytes=%zu ", *requested_bytes);
    }
    n += snprintf(line + n, sizeof(line) - n, "storage=%s bytes=%zu hex=", storage, size);
    for (size_t i = 0; i < size; ++i) {
        if (i && i % group_size == 0) {
            line[n++] = ' ';
        }
        line[n++] = hex[bytes[i] >> 4];
        line[n++] = hex[bytes[i] & 15];
    }
    line[n++] = '\n';
    int saved = errno;
    while (syscall(SYS_write, output().fd, line, n) < 0 && errno == EINTR) {
    }
    errno = saved;
}
} //namespace tx_snapshot
