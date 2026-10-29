/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "stats/rx_layout_summary.h"
#include <gtest/gtest.h>
using namespace xlio_rx_layout;
TEST(rx_layout_summary, frequency_and_alignment_exclude_control_from_data_denominator)
{
    batch b;
    b.count = 4;
    b.records[0].payload_bytes = 8960;
    b.records[0].payload_offset = 64;
    b.records[0].lro_segments = 1;
    b.records[1] = b.records[0];
    b.records[2].payload_bytes = 13;
    b.records[2].payload_offset = 70;
    b.records[2].payload_mod64 = 6;
    b.records[2].lro_segments = 1;
    b.records[3].payload_offset = 54;
    b.records[3].payload_mod64 = 54;
    b.records[3].lro_segments = 1;
    auto s = summarize(b);
    ASSERT_EQ(3U, s.rows.size());
    EXPECT_EQ(2U, s.rows[0].count);
    EXPECT_EQ(8960U, s.rows[0].layout.payload_bytes);
    EXPECT_EQ(3U, s.data);
    EXPECT_EQ(1U, s.control);
    EXPECT_EQ(2U, s.offset64);
    EXPECT_EQ(2U, s.address64);
    EXPECT_EQ(2U, s.length64);
}
TEST(rx_layout_summary, empty_capture_and_partial_progress_are_explicit)
{
    EXPECT_EQ("No traffic", progress_text(phase::armed, 200, 256));
    EXPECT_EQ("No traffic", progress_text(phase::filling, 0, 256));
    EXPECT_EQ("Collecting samples (3/256)", progress_text(phase::filling, 3, 256));
    EXPECT_TRUE(summarize(batch {}).rows.empty());
}
TEST(rx_layout_summary, different_lro_counts_remain_separate)
{
    batch b;
    b.count = 2;
    b.records[0].payload_bytes = b.records[1].payload_bytes = 8960;
    b.records[0].lro_segments = 1;
    b.records[1].lro_segments = 2;
    EXPECT_EQ(2U, summarize(b).rows.size());
}
