/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>

namespace tx_snapshot {
constexpr size_t limit = 1000;

struct copy_site {
    unsigned qp, wqe;
    int sge, sge_count;
    size_t frame_offset;
};

struct dm_copy_info {
    copy_site site;
    uintptr_t host;
    uint32_t handle, lkey;
    size_t dm_offset, allocation, logical_length, copy_length;
    size_t read_length;
    int copy_rc, read_rc;
};

// Event and storage names are string literals. The queue owns everything else.
struct message {
    message *next;
    const char *event;
    const char *storage;
    unsigned qp;
    unsigned wqe;
    size_t requested;
    size_t size;
    bool api_send;
    unsigned nfields = 0;
    unsigned cqn = 0, cq_ci = 0;
    bool cq_record = false;
    bool dm_copy = false;
    dm_copy_info copy;
    const char *stage = nullptr;
    size_t total, offset;
    int segment = -1;
    uint64_t address;
    uint32_t lkey;
    int read_rc;
    size_t read_length;
    alignas(4) uint8_t bytes[limit];
};

struct field {
    const char *name;
    uint64_t value;
};
void metadata(const char *event, unsigned qp, unsigned wqe, std::initializer_list<field> fields,
              const char *description = "");
bool read_dm();
message *allocate();
void enqueue(message *msg);
// Copy a complete hardware entry, including ring wrap, in numbered chunks.
void raw_entry(const char *event, unsigned qp, unsigned wqe, const uint8_t *ring, size_t ring_size,
               size_t start, size_t length, unsigned cqn = 0, unsigned ci = 0);
} // namespace tx_snapshot
