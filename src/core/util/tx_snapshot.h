/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace tx_snapshot {
constexpr size_t limit = 1000;

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
    uint8_t bytes[limit];
};

message *allocate();
void enqueue(message *msg);
} // namespace tx_snapshot
