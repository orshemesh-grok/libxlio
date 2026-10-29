/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_HEADER_LAYOUT_H
#define XLIO_RX_HEADER_LAYOUT_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if_ether.h>

struct rx_l2_header {
    size_t length;
    uint16_t protocol; // Network order, like ethhdr::h_proto.
    uint16_t vlan_id; // Original customer VLAN, excluding the synthetic tags.
};

inline uint16_t rx_header_u16(const uint8_t *p)
{
    uint16_t value;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

inline bool rx_parse_l2_header(const uint8_t *frame, size_t size, bool headers_64,
                               rx_l2_header &header)
{
    if (!frame || size < ETH_HLEN) {
        return false;
    }
    header = {ETH_HLEN, rx_header_u16(frame + 12), 0};
    if (headers_64) {
        // Receive steering inserts exactly these two VLAN tags after the MACs.
        // Validate and ignore only our tags; preserve any original VLAN semantics.
        if (size < ETH_HLEN + 8U || header.protocol != htons(ETH_P_8021AD) ||
            rx_header_u16(frame + 14) != 0 || rx_header_u16(frame + 16) != htons(ETH_P_8021Q) ||
            rx_header_u16(frame + 18) != 0) {
            return false;
        }
        header.length += 8U;
        header.protocol = rx_header_u16(frame + 20);
    }
    if (header.protocol == htons(ETH_P_8021Q)) {
        if (size < header.length + 4U) {
            return false;
        }
        header.vlan_id = ntohs(rx_header_u16(frame + header.length)) & 0x0FFFU;
        header.protocol = rx_header_u16(frame + header.length + 2U);
        header.length += 4U;
    }
    return true;
}

inline bool rx_skip_strq_prefix(uint8_t *&buffer, size_t &length, size_t &capacity)
{
    // The patched DPCP makes CQE.byte_cnt[15:0] include the two padding bytes.
    if (!buffer || length < 2U || capacity < length) {
        return false;
    }
    buffer += 2U;
    length -= 2U;
    capacity -= 2U;
    return true;
}
#endif
