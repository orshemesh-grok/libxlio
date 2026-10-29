/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include <gtest/gtest.h>
#include "dev/rx_header_layout.h"
#include <array>

TEST(rx_header_layout, original_untagged_and_vlan)
{
    uint8_t packet[64] = {};
    packet[12] = 0x08;
    rx_l2_header result;
    ASSERT_TRUE(rx_parse_l2_header(packet, sizeof(packet), false, result));
    EXPECT_EQ(14U, result.length);
    EXPECT_EQ(htons(ETH_P_IP), result.protocol);
    EXPECT_EQ(0, result.vlan_id);
    packet[12] = 0x81;
    packet[14] = 0xa0; // PCP must not be interpreted as VID.
    packet[15] = 42;
    packet[16] = 0x86;
    packet[17] = 0xdd;
    ASSERT_TRUE(rx_parse_l2_header(packet, sizeof(packet), false, result));
    EXPECT_EQ(18U, result.length);
    EXPECT_EQ(htons(ETH_P_IPV6), result.protocol);
    EXPECT_EQ(42, result.vlan_id);
}

TEST(rx_header_layout, synthetic_tags_preserve_payload_alignment)
{
    alignas(64) uint8_t storage[128] = {};
    uint8_t *frame = storage;
    size_t length = 128, capacity = 128;
    // HW prefix followed by MACs, synthetic tags, IPv4 and TCP headers.
    storage[14] = 0x88;
    storage[15] = 0xa8;
    storage[18] = 0x81;
    storage[22] = 0x08;
    storage[64] = 0x5a;
    ASSERT_TRUE(rx_skip_strq_prefix(frame, length, capacity));
    EXPECT_EQ(storage + 2, frame);
    EXPECT_EQ(126U, length);
    EXPECT_EQ(126U, capacity);
    rx_l2_header result;
    ASSERT_TRUE(rx_parse_l2_header(frame, length, true, result));
    EXPECT_EQ(22U, result.length);
    EXPECT_EQ(htons(ETH_P_IP), result.protocol);
    EXPECT_EQ(0U, result.vlan_id);
    EXPECT_EQ(storage + 64, frame + result.length + 20 + 20);
    EXPECT_EQ(0x5a, frame[result.length + 40]);
}

TEST(rx_header_layout, preserve_customer_vlan_after_synthetic_tags)
{
    uint8_t frame[64] = {};
    const uint8_t tags[] = {0x88, 0xa8, 0, 0, 0x81, 0, 0, 0, 0x81, 0, 0, 123, 0x86, 0xdd};
    std::memcpy(frame + 12, tags, sizeof(tags));
    rx_l2_header result;
    ASSERT_TRUE(rx_parse_l2_header(frame, sizeof(frame), true, result));
    EXPECT_EQ(26U, result.length);
    EXPECT_EQ(123U, result.vlan_id);
    EXPECT_EQ(htons(ETH_P_IPV6), result.protocol);
}

TEST(rx_header_layout, reject_truncated_or_missing_synthetic_tags)
{
    uint8_t frame[64] = {};
    const uint8_t tags[] = {0x88, 0xa8, 0, 0, 0x81, 0, 0, 0, 8, 0};
    std::memcpy(frame + 12, tags, sizeof(tags));
    rx_l2_header result;
    for (size_t size = 0; size < 22; ++size) {
        EXPECT_FALSE(rx_parse_l2_header(frame, size, true, result)) << size;
    }
    ASSERT_TRUE(rx_parse_l2_header(frame, 22, true, result));
    for (size_t offset : {12U, 13U, 14U, 15U, 16U, 17U, 18U, 19U}) {
        frame[offset] ^= 1;
        EXPECT_FALSE(rx_parse_l2_header(frame, sizeof(frame), true, result)) << offset;
        frame[offset] ^= 1;
    }
    frame[20] = 0x81;
    EXPECT_FALSE(rx_parse_l2_header(frame, 25, true, result));
    EXPECT_FALSE(rx_parse_l2_header(nullptr, 64, true, result));
}

TEST(rx_header_layout, reject_invalid_prefix_lengths_without_modifying_descriptor)
{
    uint8_t storage[64] = {};
    for (auto values : {std::array<size_t, 2> {0, 64}, {1, 64}, {65, 64}}) {
        uint8_t *buffer = storage;
        size_t length = values[0], capacity = values[1];
        EXPECT_FALSE(rx_skip_strq_prefix(buffer, length, capacity));
        EXPECT_EQ(storage, buffer);
        EXPECT_EQ(values[0], length);
        EXPECT_EQ(values[1], capacity);
    }
}
