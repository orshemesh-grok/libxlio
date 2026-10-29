/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "dev/rx_layout_sample.h"
#include <array>
#include <cstring>
#include <gtest/gtest.h>
using namespace xlio_rx_layout;
namespace {
void be16(uint8_t *p, unsigned value)
{
    p[0] = value >> 8;
    p[1] = value & 255;
}
void ipv4_tcp(uint8_t *p, unsigned payload, unsigned tcp = 20, unsigned ip = 20)
{
    p[0] = 0x40 | (ip / 4);
    be16(p + 2, ip + tcp + payload);
    p[9] = 6;
    p[ip + 12] = (tcp / 4) << 4;
    p[ip + 13] = 0x10;
}
} // namespace
TEST(rx_layout_sample, ordinary_ipv4_ignores_ethernet_padding)
{
    alignas(64) uint8_t frame[128] = {};
    be16(frame + 12, ETH_P_IP);
    ipv4_tcp(frame + 14, 0);
    record r {};
    ASSERT_TRUE(parse_sample(frame, 60, frame, false, false, 0, r));
    EXPECT_EQ(60U, r.frame_bytes);
    EXPECT_EQ(54U, r.payload_offset);
    EXPECT_EQ(54U, r.payload_mod64);
    EXPECT_EQ(0U, r.payload_bytes);
    EXPECT_EQ(1U, r.lro_segments);
}
TEST(rx_layout_sample, prefix_and_tags_align_payload_with_lro)
{
    alignas(64) std::array<uint8_t, 20000> storage {};
    auto *frame = storage.data() + 2;
    const uint8_t tags[] = {0x88, 0xa8, 0, 0, 0x81, 0, 0, 0, 8, 0};
    std::memcpy(frame + 12, tags, sizeof(tags));
    ipv4_tcp(frame + 22, 17920);
    record r {};
    ASSERT_TRUE(parse_sample(frame, 17982, storage.data(), true, true, 2, r));
    EXPECT_EQ(2U, r.prefix_bytes);
    EXPECT_EQ(22U, r.l2_bytes);
    EXPECT_EQ(64U, r.payload_offset);
    EXPECT_EQ(0U, r.payload_mod64);
    EXPECT_EQ(17920U, r.payload_bytes);
    EXPECT_EQ(2U, r.lro_segments);
}
TEST(rx_layout_sample, options_and_short_payload_are_measured)
{
    alignas(64) uint8_t frame[256] = {};
    be16(frame + 12, ETH_P_IP);
    ipv4_tcp(frame + 14, 13, 32, 24);
    record r {};
    ASSERT_TRUE(parse_sample(frame, 83, frame, false, false, 1, r));
    EXPECT_EQ(24U, r.l3_bytes);
    EXPECT_EQ(32U, r.tcp_bytes);
    EXPECT_EQ(70U, r.payload_offset);
    EXPECT_EQ(6U, r.payload_mod64);
    EXPECT_EQ(13U, r.payload_bytes);
}
TEST(rx_layout_sample, customer_vlan_is_included)
{
    uint8_t frame[128] = {};
    be16(frame + 12, ETH_P_8021Q);
    be16(frame + 16, ETH_P_IP);
    ipv4_tcp(frame + 18, 4);
    record r {};
    ASSERT_TRUE(parse_sample(frame, 62, frame, false, false, 1, r));
    EXPECT_EQ(18U, r.l2_bytes);
    EXPECT_EQ(58U, r.payload_offset);
}
TEST(rx_layout_sample, ipv6_extension_headers_are_included)
{
    uint8_t frame[128] = {};
    be16(frame + 12, ETH_P_IPV6);
    auto *ip = frame + 14;
    ip[0] = 0x60;
    be16(ip + 4, 8 + 20 + 1);
    ip[6] = 60;
    ip[40] = 6;
    ip[48 + 12] = 0x50;
    record r {};
    ASSERT_TRUE(parse_sample(frame, 83, frame, false, false, 1, r));
    EXPECT_EQ(6U, r.ip_version);
    EXPECT_EQ(48U, r.l3_bytes);
    EXPECT_EQ(1U, r.payload_bytes);
}
TEST(rx_layout_sample, invalid_lengths_fragments_and_other_protocols_are_rejected)
{
    uint8_t frame[128] = {};
    be16(frame + 12, ETH_P_IP);
    ipv4_tcp(frame + 14, 5);
    record r {};
    for (unsigned length = 0; length < 59; ++length) {
        EXPECT_FALSE(parse_sample(frame, length, frame, false, false, 1, r));
    }
    frame[14 + 20 + 12] = 0xf0;
    EXPECT_FALSE(parse_sample(frame, 59, frame, false, false, 1, r));
    frame[14 + 20 + 12] = 0x40;
    EXPECT_FALSE(parse_sample(frame, 59, frame, false, false, 1, r));
    frame[14 + 20 + 12] = 0x50;
    frame[14 + 6] = 0x20;
    EXPECT_FALSE(parse_sample(frame, 59, frame, false, false, 1, r));
    frame[14 + 6] = 0;
    frame[14 + 9] = 17;
    EXPECT_FALSE(parse_sample(frame, 59, frame, false, false, 1, r));
    EXPECT_FALSE(parse_sample(nullptr, 59, nullptr, false, false, 1, r));
}

TEST(rx_layout_sample, actual_address_is_independent_of_slot_offset)
{
    alignas(64) uint8_t storage[128] = {};
    auto *frame = storage + 10;
    be16(frame + 12, ETH_P_IP);
    ipv4_tcp(frame + 14, 64);
    record r {};
    ASSERT_TRUE(parse_sample(frame, 118, frame, false, false, 1, r));
    EXPECT_EQ(54U, r.payload_offset);
    EXPECT_EQ(0U, r.payload_mod64);
    slot s;
    ASSERT_TRUE(register_slot(s, 1, 1));
    capture_sample(&s, nullptr, 0, nullptr, false, false, 0);
    EXPECT_EQ(phase::idle, state(s.control.load()));
    EXPECT_EQ(0U, s.inspected.load());
}
TEST(rx_layout_sample, synthetic_tags_and_customer_vlan)
{
    alignas(64) uint8_t storage[256] = {};
    auto *frame = storage + 2;
    const uint8_t tags[] = {0x88, 0xa8, 0, 0, 0x81, 0, 0, 0, 0x81, 0, 0, 42, 8, 0};
    std::memcpy(frame + 12, tags, sizeof(tags));
    ipv4_tcp(frame + 26, 64);
    record r {};
    ASSERT_TRUE(parse_sample(frame, 130, storage, true, true, 1, r));
    EXPECT_EQ(26U, r.l2_bytes);
    EXPECT_EQ(68U, r.payload_offset);
    EXPECT_EQ(4U, r.payload_mod64);
}
TEST(rx_layout_sample, ipv6_extension_bounds_and_plain_header)
{
    uint8_t frame[256] = {};
    be16(frame + 12, ETH_P_IPV6);
    auto *ip = frame + 14;
    ip[0] = 0x60;
    be16(ip + 4, 20);
    ip[6] = 6;
    ip[40 + 12] = 0x50;
    record r {};
    ASSERT_TRUE(parse_sample(frame, 74, frame, false, false, 1, r));
    EXPECT_EQ(40U, r.l3_bytes);
    be16(ip + 4, 0);
    EXPECT_FALSE(parse_sample(frame, 74, frame, false, false, 1, r));
    be16(ip + 4, 8 + 20);
    ip[6] = 60;
    ip[40] = 6;
    ip[41] = 255;
    EXPECT_FALSE(parse_sample(frame, 82, frame, false, false, 1, r));
    for (unsigned count : {8U, 9U}) {
        std::memset(ip + 40, 0, 128);
        be16(ip + 4, count * 8 + 20);
        for (unsigned n = 0; n < count; ++n) {
            ip[40 + n * 8] = n + 1 == count ? 6 : 60;
        }
        ip[40 + count * 8 + 12] = 0x50;
        EXPECT_EQ(count == 8, parse_sample(frame, 74 + count * 8, frame, false, false, 1, r));
    }
}
TEST(rx_layout_sample, ipv4_header_lengths_cannot_underflow)
{
    uint8_t frame[128] = {};
    be16(frame + 12, ETH_P_IP);
    ipv4_tcp(frame + 14, 0);
    record r {};
    frame[14] = 0x44;
    EXPECT_FALSE(parse_sample(frame, 54, frame, false, false, 1, r));
    frame[14] = 0x46;
    be16(frame + 16, 20);
    EXPECT_FALSE(parse_sample(frame, 54, frame, false, false, 1, r));
}
