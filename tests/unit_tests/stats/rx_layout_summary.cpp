/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#include "stats/rx_layout_summary.h"
#include "stats/rx_analysis_csv.h"
#include "dev/rx_layout_sample.h"
#include <gtest/gtest.h>
using namespace xlio_rx_layout;
namespace {
void put16(uint8_t *p, unsigned n)
{
    p[0] = n >> 8;
    p[1] = n;
}
void put32(uint8_t *p, uint32_t n)
{
    put16(p, n >> 16);
    put16(p + 2, n);
}
record packet(uint32_t seq = 100, unsigned payload = 64, unsigned lro = 0)
{
    std::vector<uint8_t> f(54 + payload);
    put16(f.data() + 12, 0x800);
    f[14] = 0x45;
    put16(f.data() + 16, 40 + payload);
    f[23] = 6;
    f[26] = 10;
    f[30] = 11;
    put16(f.data() + 34, 1234);
    put16(f.data() + 36, 5678);
    put32(f.data() + 38, seq);
    f[46] = 0x50;
    f[47] = 0x10;
    uint8_t cq[64] {};
    cq[28] = 7;
    cq[32] = lro;
    auto r = collect_headers(f.data(), f.size(), f.data(), false, true, cq);
    r.sw_time_ns = 123456;
    return r;
}
batch metadata()
{
    batch b;
    b.ring_id = 1;
    b.generation = 1;
    b.if_index = 7;
    b.context = {65280, 32, 1, 3, 1, 1, 0, 1, 1};
    return b;
}
} //namespace
TEST(rx_analysis, preserves_zero_one_and_abort_groups)
{
    auto b = metadata();
    analyzer a;
    std::vector<observation> samples;
    for (unsigned lro : {0U, 1U, 2U}) {
        for (unsigned abrt : {0U, 1U, 2U, 3U}) {
            auto r = packet(100, 64, lro);
            r.cqe[4] = abrt << 4;
            auto o = a.inspect(r, b, samples.size() + 1);
            EXPECT_EQ(lro, o.sizes.lro_segments);
            EXPECT_EQ(lro ? "-" : "unknown", o.disq);
            EXPECT_EQ(lro ? false : true, abort_name(r) == "-");
            samples.push_back(o);
        }
    }
    auto s = summarize(samples);
    ASSERT_EQ(9U, s.rows.size());
    EXPECT_EQ(4U, s.rows.front().count);
}
TEST(rx_analysis, expected_sequence_resets_each_batch_and_on_ring_change)
{
    auto b = metadata();
    analyzer a;
    auto first = a.inspect(packet(0xfffffff0U, 64), b, 1);
    EXPECT_FALSE(first.expected_valid);
    auto second = a.inspect(packet(48, 64), b, 1);
    EXPECT_TRUE(second.expected_valid);
    EXPECT_EQ(48U, second.expected);
    EXPECT_EQ("unknown", second.disq);
    EXPECT_EQ(first.flow_id, second.flow_id);
    auto next = a.inspect(packet(999, 64), b, 2);
    EXPECT_FALSE(next.expected_valid);
    EXPECT_EQ(first.flow_id, next.flow_id);
    ++b.ring_id;
    EXPECT_FALSE(a.inspect(packet(1000), b, 2).expected_valid);
    ++b.generation;
    EXPECT_FALSE(a.inspect(packet(1064), b, 2).expected_valid);
}
TEST(rx_analysis, records_syn_fin_and_all_disqualifiers)
{
    auto b = metadata();
    analyzer a;
    auto r = packet(100, 0);
    r.tcp[13] = 2 | 0x20;
    r.tcp[12] |= 3;
    auto o = a.inspect(r, b, 1);
    EXPECT_TRUE(o.tcp_valid);
    EXPECT_FALSE(o.expected_valid);
    for (auto reason :
         {"SYN", "URG", "NS", "reserved TCP flags", "no TCP payload", "below min MSS"}) {
        EXPECT_NE(std::string::npos, o.disq.find(reason));
    }
    auto data = a.inspect(packet(101), b, 1);
    EXPECT_TRUE(data.expected_valid);
    EXPECT_EQ(101U, data.expected);
    r = packet(165, 0);
    r.tcp[13] = 1;
    EXPECT_TRUE(a.inspect(r, b, 1).expected_valid);
    EXPECT_FALSE(a.inspect(packet(166), b, 1).expected_valid);
}
TEST(rx_analysis, sequence_discrepancy_is_observed_and_missing_context_invalidates_history)
{
    auto b = metadata();
    analyzer a;
    a.inspect(packet(), b, 1);
    auto o = a.inspect(packet(200), b, 1);
    EXPECT_NE(std::string::npos, o.disq.find("observed sequence mismatch"));
    record excluded {};
    excluded.incomplete = 1;
    auto e = a.inspect(excluded, b, 1);
    EXPECT_FALSE(e.excluded.empty());
    EXPECT_FALSE(a.inspect(packet(999), b, 1).expected_valid);
    auto r = packet(1063);
    r.incomplete = 1;
    a.inspect(r, b, 1);
    EXPECT_FALSE(a.inspect(packet(1127), b, 1).expected_valid);
}
TEST(rx_analysis, aggregate_sequence_uses_completion_payload_and_preserves_original_ip)
{
    auto b = metadata();
    analyzer a;
    auto r = packet(100, 128, 2);
    put16(r.ip + 2, 104);
    auto first = a.inspect(r, b, 1);
    EXPECT_EQ(128U, first.sizes.payload_bytes);
    EXPECT_EQ(104U, u16(r.ip + 2));
    auto next = a.inspect(packet(228), b, 1);
    EXPECT_EQ(228U, next.expected);
    EXPECT_EQ("unknown", next.disq);
}
TEST(rx_analysis, tcp_timestamp_padding_and_unsupported_options)
{
    auto b = metadata();
    analyzer a;
    auto r = packet();
    r.tcp_len = 32;
    r.tcp[12] = 0x80;
    r.frame_bytes += 12;
    put16(r.ip + 2, 116);
    r.tcp[20] = 1;
    r.tcp[21] = 1;
    r.tcp[22] = 8;
    r.tcp[23] = 10;
    put32(r.tcp + 24, 100);
    EXPECT_EQ("unknown", a.inspect(r, b, 1).disq);
    put32(r.tcp + 4, 164);
    put32(r.tcp + 24, 90);
    EXPECT_NE(std::string::npos, a.inspect(r, b, 1).disq.find("timestamp decrease"));
    r.tcp[22] = 30;
    EXPECT_NE(std::string::npos, a.inspect(r, b, 2).disq.find("TCP options 30"));
    r.tcp[23] = 40;
    EXPECT_NE(std::string::npos, a.inspect(r, b, 3).disq.find("malformed TCP options"));
}
TEST(rx_analysis, excluded_histogram_and_csv_keep_records_in_order)
{
    auto b = metadata();
    analyzer a;
    record excluded {};
    excluded.incomplete = 1;
    std::vector<record> records {packet(), excluded, packet(164)};
    std::vector<observation> obs;
    std::ostringstream csv;
    csv_header(csv);
    for (auto &r : records) {
        obs.push_back(a.inspect(r, b, 8));
        csv_record(csv, r, obs.back(), b, 8);
    }
    auto s = summarize(obs);
    EXPECT_EQ(2U, s.data);
    EXPECT_EQ(1U, s.excluded.size());
    EXPECT_FALSE(obs[2].expected_valid);
    auto text = csv.str();
    EXPECT_NE(std::string::npos, text.find("\"batch\",\"ring-id\""));
    EXPECT_EQ(4U, std::count(text.begin(), text.end(), '\n'));
    EXPECT_NE(std::string::npos, text.find("\"expected-seqno\",\"sw-time-ns\""));
    EXPECT_NE(std::string::npos, text.find("truncated Ethernet"));
}
TEST(rx_analysis, bounded_flow_table_assigns_new_id_after_eviction_and_separates_vlans)
{
    auto b = metadata();
    analyzer a(2);
    auto r = packet();
    auto first = a.inspect(r, b, 1);
    put16(r.tcp, 1235);
    auto second = a.inspect(r, b, 1);
    put16(r.tcp, 1236);
    auto third = a.inspect(r, b, 1);
    EXPECT_NE(first.flow_id, second.flow_id);
    EXPECT_NE(second.flow_id, third.flow_id);
    auto again = a.inspect(packet(), b, 1);
    EXPECT_NE(first.flow_id, again.flow_id);
    EXPECT_FALSE(again.expected_valid);
    r = packet();
    r.cqe[29] |= 1;
    put16(r.cqe + 30, 42);
    auto vlan = a.inspect(r, b, 1);
    EXPECT_NE(again.flow_id, vlan.flow_id);
}
TEST(rx_analysis, empty_capture_and_partial_progress_are_explicit)
{
    EXPECT_EQ("No traffic", progress_text(phase::armed, 200, 256));
    EXPECT_EQ("No traffic", progress_text(phase::filling, 0, 256));
    EXPECT_EQ("Collecting samples (3/256)", progress_text(phase::filling, 3, 256));
    EXPECT_TRUE(summarize({}).rows.empty());
}
TEST(rx_analysis, missing_cqe_does_not_invent_lro_or_sequence_context)
{
    auto b = metadata();
    analyzer a;
    auto r = packet();
    r.cqe_valid = 0;
    auto o = a.inspect(r, b, 1);
    EXPECT_FALSE(o.excluded.empty());
    EXPECT_EQ("unknown", o.disq);
    EXPECT_FALSE(a.inspect(packet(164), b, 1).expected_valid);
    uint8_t frame[54] {};
    put16(frame + 12, 0x800);
    frame[14] = 0x45;
    put16(frame + 16, 40);
    frame[23] = 6;
    frame[46] = 0x50;
    EXPECT_TRUE(collect_headers(frame, sizeof(frame), frame, false, false, nullptr).incomplete);
}
TEST(rx_analysis, incomplete_records_have_separate_histogram_rows)
{
    auto b = metadata();
    analyzer a;
    auto r = packet();
    auto first = a.inspect(r, b, 1);
    r.incomplete = 1;
    auto second = a.inspect(r, b, 2);
    EXPECT_EQ(2U, summarize({first, second}).rows.size());
}
TEST(rx_analysis, unavailable_context_is_reported_as_incomplete)
{
    batch b;
    analyzer a;
    auto o = a.inspect(packet(), b, 1);
    EXPECT_TRUE(o.incomplete);
}
TEST(rx_analysis, parseable_excluded_fragment_retains_flow_identity_without_continuity)
{
    auto b = metadata();
    analyzer a;
    auto first = a.inspect(packet(), b, 1);
    auto r = packet(164);
    put16(r.ip + 6, 0x2000);
    auto fragment = a.inspect(r, b, 1);
    EXPECT_EQ(first.flow_id, fragment.flow_id);
    EXPECT_FALSE(fragment.expected_valid);
    EXPECT_FALSE(a.inspect(packet(228), b, 1).expected_valid);
}
