/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_LAYOUT_SUMMARY_H
#define XLIO_RX_LAYOUT_SUMMARY_H
#include "core/util/rx_layout_capture.h"
#include <algorithm>
#include <map>
#include <string>
#include <tuple>
#include <vector>
namespace xlio_rx_layout {
struct row {
    record layout;
    unsigned count;
};
struct summary {
    std::vector<row> rows;
    unsigned data = 0, control = 0, offset64 = 0, address64 = 0, length64 = 0;
};

inline auto layout_key(const record &r)
{
    return std::make_tuple(r.frame_bytes, r.payload_bytes, r.payload_offset, r.l2_bytes, r.l3_bytes,
                           r.tcp_bytes, r.prefix_bytes, r.lro_segments, r.payload_mod64, r.striding,
                           r.tcp_flags, r.ip_version);
}
inline summary summarize(const batch &b)
{
    summary result;
    std::map<decltype(layout_key(record {})), row> histogram;
    for (unsigned i = 0; i < b.count && i < capacity; ++i) {
        const auto &r = b.records[i];
        auto entry = histogram.emplace(layout_key(r), row {r, 0});
        ++entry.first->second.count;
        if (r.payload_bytes) {
            ++result.data;
            result.offset64 += r.payload_offset == 64;
            result.address64 += r.payload_mod64 == 0;
            result.length64 += r.payload_bytes % 64 == 0;
        } else {
            ++result.control;
        }
    }
    for (const auto &item : histogram) {
        result.rows.push_back(item.second);
    }
    std::sort(result.rows.begin(), result.rows.end(), [](const row &left, const row &right) {
        return left.count != right.count ? left.count > right.count
                                         : layout_key(left.layout) < layout_key(right.layout);
    });
    return result;
}
inline std::string progress_text(phase p, unsigned count, unsigned requested)
{
    if (p == phase::armed || count == 0) {
        return "No traffic";
    }
    return "Collecting samples (" + std::to_string(count) + "/" + std::to_string(requested) + ")";
}
} // namespace xlio_rx_layout
#endif
