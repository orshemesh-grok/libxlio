/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_LAYOUT_SAMPLE_H
#define XLIO_RX_LAYOUT_SAMPLE_H
#include "dev/rx_header_layout.h"
#include "util/rx_layout_capture.h"
namespace xlio_rx_layout {

inline uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t(p[0]) << 8) | p[1];
}
inline bool parse_sample(const uint8_t *frame, size_t bytes, const uint8_t *slot_start,
                         bool headers_64, bool striding, uint16_t lro_segments, record &out)
{
    rx_l2_header l2;
    if (!frame || !slot_start || uintptr_t(frame) < uintptr_t(slot_start) || bytes > UINT32_MAX ||
        !rx_parse_l2_header(frame, bytes, headers_64, l2) || bytes <= l2.length) {
        return false;
    }
    size_t prefix = uintptr_t(frame) - uintptr_t(slot_start);
    if (prefix > UINT16_MAX) {
        return false;
    }
    const uint8_t *ip = frame + l2.length;
    size_t available = bytes - l2.length;
    size_t ip_bytes = 0, ip_header = 0;
    uint8_t protocol = 0;
    uint8_t ip_version = ip[0] >> 4;
    if (l2.protocol == htons(ETH_P_IP) && ip_version == 4) {
        if (available < 20) {
            return false;
        }
        ip_header = (ip[0] & 0xfU) * 4U;
        ip_bytes = read_be16(ip + 2);
        if (ip_header < 20 || ip_bytes < ip_header || ip_bytes > available ||
            (read_be16(ip + 6) & 0x3fffU)) {
            return false;
        }
        protocol = ip[9];
    } else if (l2.protocol == htons(ETH_P_IPV6) && ip_version == 6) {
        if (available < 40 || !read_be16(ip + 4)) {
            return false; // IPv6 jumbograms are outside this diagnostic format.
        }
        ip_bytes = 40U + read_be16(ip + 4);
        ip_header = 40;
        protocol = ip[6];
        if (ip_bytes > available) {
            return false;
        }
        for (unsigned depth = 0; protocol != 6 && depth < 8; ++depth) {
            if (protocol != 0 && protocol != 43 && protocol != 60 && protocol != 51) {
                return false; // Includes fragmented, encrypted and non-TCP traffic.
            }
            if (ip_bytes - ip_header < 2) {
                return false;
            }
            const uint8_t *extension = ip + ip_header;
            size_t length = protocol == 51 ? (size_t(extension[1]) + 2U) * 4U
                                           : (size_t(extension[1]) + 1U) * 8U;
            if (length > ip_bytes - ip_header) {
                return false;
            }
            protocol = extension[0];
            ip_header += length;
        }
    } else {
        return false;
    }
    if (protocol != 6 || ip_bytes - ip_header < 20 || ip_header > UINT16_MAX) {
        return false;
    }
    const uint8_t *tcp = ip + ip_header;
    size_t tcp_header = (tcp[12] >> 4) * 4U;
    if (tcp_header < 20 || tcp_header > ip_bytes - ip_header) {
        return false;
    }
    out = {};
    out.frame_bytes = static_cast<uint32_t>(bytes);
    out.payload_bytes = static_cast<uint32_t>(ip_bytes - ip_header - tcp_header);
    out.payload_offset = static_cast<uint32_t>(prefix + l2.length + ip_header + tcp_header);
    out.l2_bytes = static_cast<uint16_t>(l2.length);
    out.l3_bytes = static_cast<uint16_t>(ip_header);
    out.tcp_bytes = static_cast<uint16_t>(tcp_header);
    out.prefix_bytes = static_cast<uint16_t>(prefix);
    out.lro_segments = lro_segments > 1 ? lro_segments : 1;
    out.payload_mod64 = uintptr_t(tcp + tcp_header) & 63U;
    out.striding = striding;
    out.tcp_flags = tcp[13];
    out.ip_version = ip_version;
    return true;
}
inline void capture_sample(slot *s, const uint8_t *frame, size_t bytes, const uint8_t *slot_start,
                           bool headers_64, bool striding, uint16_t lro_segments)
{
    if (!s) {
        return;
    }
    auto token = begin(*s);
    if (!token) {
        return;
    }
    record sample;
    bool valid = parse_sample(frame, bytes, slot_start, headers_64, striding, lro_segments, sample);
    publish_attempt(*s, token, valid ? &sample : nullptr);
}
} // namespace xlio_rx_layout
#endif
