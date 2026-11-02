/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_LAYOUT_CAPTURE_H
#define XLIO_RX_LAYOUT_CAPTURE_H
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
namespace xlio_rx_layout {
constexpr unsigned capacity = 256;
constexpr unsigned max_rings = 16;
enum class phase : uint8_t { free, initializing, idle, armed, filling, ready, reading };
constexpr uint64_t closed_bit = 1ULL << 24;
inline phase state(uint64_t token)
{
    return static_cast<phase>(token & 0xffU);
}
inline unsigned target(uint64_t token)
{
    return (token >> 8) & 0xffffU;
}
inline uint64_t with_state(uint64_t token, phase p)
{
    return (token & ~0xffULL) | uint64_t(p);
}
// Fixed, bounded header snapshots. Packet and CQE byte arrays retain wire/device
// byte order. No payload, inferred disqualifier or flow state is collected here.
struct record {
    uint64_t sw_time_ns = 0;
    uint32_t frame_bytes = 0;
    uint16_t prefix_bytes = 0, l3_bytes = 0;
    uint8_t frame_mod64 = 0, striding = 0, headers_64 = 0, incomplete = 0;
    uint8_t eth_len = 0, ip_len = 0, tcp_len = 0, ext_count = 0;
    uint8_t cqe_valid = 0;
    uint8_t ethernet[30] = {}, ip[40] = {}, tcp[60] = {}, extensions[8] = {}, cqe[64] = {};
};
struct receive_context {
    uint32_t max_lro_bytes = 0, timeout_us = 0;
    uint16_t min_mss = 0;
    uint8_t enable_mask = 0, psh = 0, timestamp = 0, max_size_mode = 0;
    uint8_t caps_known = 0, tir_known = 0;
};
struct alignas(64) slot {
    std::atomic<uint64_t> control {0};
    std::atomic<uint32_t> progress {0}, inspected {0}, excluded {0};
    uint32_t if_index = 0;
    uint64_t ring_id = 0, sequence = 0;
    receive_context context {};
    std::array<record, capacity> records {};
};
struct batch {
    uint64_t ring_id = 0, generation = 0, sequence = 0;
    uint32_t if_index = 0;
    unsigned count = 0, requested = 0, inspected = 0, excluded = 0;
    bool closed = false;
    receive_context context {};
    std::array<record, capacity> records {};
};

static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr),
              "Lock-free shared control required");
static_assert(__atomic_always_lock_free(sizeof(uint32_t), nullptr),
              "Lock-free shared counters required");

inline bool register_slot(slot &s, uint64_t id, uint32_t if_index)
{
    auto token = s.control.load(std::memory_order_acquire);
    if (state(token) != phase::free) {
        return false;
    }
    auto next = (((token >> 32) + 1U) << 32) | uint64_t(phase::initializing);
    if (!s.control.compare_exchange_strong(token, next, std::memory_order_acq_rel)) {
        return false;
    }
    s.ring_id = id;
    s.if_index = if_index;
    s.sequence = 0;
    s.progress.store(0, std::memory_order_relaxed);
    s.inspected.store(0, std::memory_order_relaxed);
    s.excluded.store(0, std::memory_order_relaxed);
    s.control.store(with_state(next, phase::idle), std::memory_order_release);
    return true;
}

// Reader functions require the exclusive process capture file lock.
inline bool arm(slot &s, uint64_t observed, unsigned count)
{
    if (state(observed) != phase::idle || (observed & closed_bit) || !count || count > capacity) {
        return false;
    }
    auto next =
        (observed & 0xffffffff00000000ULL) | (uint64_t(count) << 8) | uint64_t(phase::armed);
    return s.control.compare_exchange_strong(observed, next, std::memory_order_acq_rel);
}

// The existing RX ring serialization protects the sole producer. close() needs
// RX quiescence.
inline uint64_t begin(slot &s)
{
    auto token = s.control.load(std::memory_order_acquire);
    if (state(token) == phase::armed) {
        s.progress.store(0, std::memory_order_relaxed);
        s.inspected.store(0, std::memory_order_relaxed);
        s.excluded.store(0, std::memory_order_relaxed);
        ++s.sequence;
        token = with_state(token, phase::filling);
        s.control.store(token, std::memory_order_release);
    }
    return state(token) == phase::filling ? token : 0;
}

// token must be the nonzero value returned by begin() for this completion.
inline void publish_attempt(slot &s, uint64_t token, const record *sample)
{
    auto count = s.progress.load(std::memory_order_relaxed);
    if (!sample || count >= target(token) || count >= capacity) {
        return;
    }
    s.records[count++] = *sample;
    s.progress.store(count, std::memory_order_release);
    s.inspected.store(count, std::memory_order_relaxed);
    if (count == target(token)) {
        s.control.store(with_state(token, phase::ready), std::memory_order_release);
    }
}

inline void close(slot &s)
{
    auto token = s.control.load(std::memory_order_acquire);
    for (;;) {
        auto p = state(token);
        if (p == phase::free || p == phase::initializing) {
            return;
        }
        auto next = token | closed_bit;
        if (p == phase::idle) {
            next = with_state(next, phase::free);
        } else if (p == phase::armed || p == phase::filling) {
            if (p == phase::armed) {
                s.progress.store(0, std::memory_order_relaxed);
                s.inspected.store(0, std::memory_order_relaxed);
                s.excluded.store(0, std::memory_order_relaxed);
                ++s.sequence;
            }
            next = with_state(next, phase::ready);
        }
        if (s.control.compare_exchange_weak(token, next, std::memory_order_acq_rel)) {
            return;
        }
    }
}

inline bool reader_claim(slot &s, uint64_t &token)
{
    token = s.control.load(std::memory_order_acquire);
    while (state(token) == phase::ready) {
        auto next = with_state(token, phase::reading);
        if (s.control.compare_exchange_weak(token, next, std::memory_order_acq_rel)) {
            token = next;
            return true;
        }
    }
    return false;
}
inline void reader_release(slot &s)
{
    auto token = s.control.load(std::memory_order_acquire);
    while (state(token) == phase::reading) {
        auto next = with_state(token, (token & closed_bit) ? phase::free : phase::idle);
        if (s.control.compare_exchange_weak(token, next, std::memory_order_acq_rel)) {
            return;
        }
    }
}
inline bool reader_copy(slot &s, batch &out)
{
    uint64_t token;
    if (!reader_claim(s, token)) {
        return false;
    }
    out.context = s.context;
    out.ring_id = s.ring_id;
    out.if_index = s.if_index;
    out.generation = token >> 32;
    out.sequence = s.sequence;
    out.count = s.progress.load(std::memory_order_relaxed);
    out.requested = target(token);
    out.inspected = s.inspected.load(std::memory_order_relaxed);
    out.excluded = s.excluded.load(std::memory_order_relaxed);
    out.closed = (s.control.load(std::memory_order_acquire) & closed_bit) != 0;
    if (out.count > capacity) {
        reader_release(s);
        return false;
    }
    for (unsigned i = 0; i < out.count; ++i) {
        out.records[i] = s.records[i];
    }
    reader_release(s);
    return true;
}
// Safe only after obtaining the file lock: the previous reader cannot still be
// copying.
inline void recover_reader(slot &s)
{
    auto token = s.control.load(std::memory_order_acquire);
    while (state(token) == phase::reading) {
        if (s.control.compare_exchange_weak(token, with_state(token, phase::ready),
                                            std::memory_order_acq_rel)) {
            return;
        }
    }
}

constexpr uint64_t magic = 0x584c494f52584c31ULL;
constexpr uint32_t version = 2;
struct alignas(64) region {
    std::atomic<uint64_t> signature {0};
    uint32_t abi_version = version;
    uint32_t region_bytes = sizeof(region);
    uint32_t record_bytes = sizeof(record);
    uint32_t slot_count = max_rings;
    uint32_t samples_per_slot = capacity;
    std::atomic<uint32_t> registration_failures {0};
    std::array<slot, max_rings> slots {};
    region() { signature.store(magic, std::memory_order_release); }
};
inline size_t extension_offset(size_t base_size)
{
    return (base_size + 63U) & ~size_t(63U);
}
inline bool valid_region(const region &r)
{
    return r.signature.load(std::memory_order_acquire) == magic && r.abi_version == version &&
        r.region_bytes == sizeof(region) && r.record_bytes == sizeof(record) &&
        r.slot_count == max_rings && r.samples_per_slot == capacity;
}
slot *register_ring(uint64_t ring_id, uint32_t if_index);
} // namespace xlio_rx_layout
#endif
