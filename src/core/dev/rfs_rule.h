/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef RFS_RULE_H
#define RFS_RULE_H

#include <memory>
#include <vector>
#include "ib/base/verbs_extra.h"
#include <mellanox/dpcp.h>

class rfs_rule {
public:
    bool create(dpcp::match_params &match_value, dpcp::match_params &match_mask, dpcp::tir &in_tir,
                uint16_t priority, uint32_t flow_tag, dpcp::adapter &in_adapter);

private:
    bool create_headers_table(dpcp::tir &tir, uint32_t flow_tag, dpcp::adapter &adapter);
    // Destruction order: root rule, private table (its FTE/group), then action objects.
    std::vector<std::shared_ptr<dpcp::flow_action>> _headers_actions;
    std::shared_ptr<dpcp::flow_table> _headers_table;
    std::unique_ptr<dpcp::flow_rule> _dpcp_flow;
};

#endif
