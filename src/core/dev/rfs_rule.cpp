/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "dev/rfs_rule.h"

#include <cinttypes>
#include <algorithm>
#include "dev/rfs.h"

#define MODULE_NAME "rfs_rule"

#define rfs_logpanic   __log_info_panic
#define rfs_logerr     __log_info_err
#define rfs_logwarn    __log_info_warn
#define rfs_loginfo    __log_info_info
#define rfs_logdbg     __log_info_dbg
#define rfs_logfunc    __log_info_func
#define rfs_logfuncall __log_info_funcall

bool rfs_rule::create(dpcp::match_params &match_value, dpcp::match_params &match_mask,
                      dpcp::tir &in_tir, uint16_t priority, uint32_t flow_tag,
                      dpcp::adapter &in_adapter)
{
    rfs_logdbg("Creating flow dpcp_adpater::create_flow_rule(), priority %" PRIu16
               ", flow_tag: %" PRIu32,
               priority, flow_tag);
    rfs_logdbg("match_mask:\n"
               "ethertype: 0x%04" PRIx16 ", vlan_id: 0x%04" PRIx16 ", protocol: 0x%02" PRIx8
               ", ip_version: 0x%02" PRIx8 "\n"
               "dst_port: 0x%04" PRIx16 ", src_ports: 0x%04" PRIx16 "\n"
               "src_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_mac: 0x%016" PRIx64,
               match_mask.ethertype, match_mask.vlan_id, match_mask.protocol, match_mask.ip_version,
               match_mask.dst_port, match_mask.src_port, match_mask.src.ipv4,
               *reinterpret_cast<uint64_t *>(match_mask.src.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_mask.src.ipv6), match_mask.dst.ipv4,
               *reinterpret_cast<uint64_t *>(match_mask.dst.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_mask.dst.ipv6),
               *reinterpret_cast<uint64_t *>(match_mask.dst_mac));
    rfs_logdbg("match_value:\n"
               "ethertype: 0x%04" PRIx16 ", vlan_id: %" PRIu16 ", protocol: %" PRIu8
               ", ip_version: %" PRIu8 "\n"
               "dst_port: %" PRIu16 ", src_ports: %" PRIu16 "\n"
               "src_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_ip: ipv4: 0x%08" PRIx32 ", ipv6: 0x%016" PRIx64 "%016" PRIx64 "\n"
               "dst_mac: 0x%016" PRIx64,
               match_value.ethertype, match_value.vlan_id, match_value.protocol,
               match_value.ip_version, match_value.dst_port, match_value.src_port,
               match_value.src.ipv4, *reinterpret_cast<uint64_t *>(match_value.src.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_value.src.ipv6), match_value.dst.ipv4,
               *reinterpret_cast<uint64_t *>(match_value.dst.ipv6 + 8),
               *reinterpret_cast<uint64_t *>(match_value.dst.ipv6),
               *reinterpret_cast<uint64_t *>(match_value.dst_mac));

    dpcp::flow_rule *new_rule = nullptr;
    dpcp::status status_out = in_adapter.create_flow_rule(priority, match_mask, new_rule);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_adpater::create_flow_rule(), Priority %" PRIu16 ", Status: %d",
                   priority, static_cast<int>(status_out));
        return false;
    }

    rfs_logdbg("Succeeded dpcp_adpater::create_flow_rule(), Priority %" PRIu16
               ", rfs_rule %p, dpcp_flow: %p",
               priority, this, new_rule);

    _dpcp_flow.reset(new_rule);

    status_out = _dpcp_flow->set_match_value(match_value);
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::set_match_value(), Status: %d, dpcp_flow: %p",
                   static_cast<int>(status_out), new_rule);
        return false;
    }

    if (safe_mce_sys().headers_64) {
        if (!create_headers_table(in_tir, flow_tag, in_adapter)) {
            return false;
        }
        status_out = _dpcp_flow->set_dest_table(_headers_table.get());
    } else {
        status_out = _dpcp_flow->add_dest_tir(&in_tir);
    }
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::add_dest_tir(), Status: %d, dpcp_flow: %p",
                   static_cast<int>(status_out), new_rule);
        return false;
    }

    uint32_t tirn = 0U;
    in_tir.get_id(tirn);
    rfs_logdbg("Added dpcp_flow_rule::add_dest_tir() TIR %" PRIu32 ", dpcp_flow: %p", tirn,
               new_rule);

    if (flow_tag) {
        rfs_logdbg("Setting flow tag dpcp_adpater::set_flow_id(), Tag: %" PRIu32 ", dpcp_flow: %p",
                   flow_tag, new_rule);

        status_out = _dpcp_flow->set_flow_id(flow_tag);
        if (status_out != dpcp::DPCP_OK) {
            rfs_logerr("Failed dpcp_flow_rule::set_flow_id(), Status: %d, dpcp_flow: %p",
                       static_cast<int>(status_out), new_rule);
            return false;
        }
    }

    status_out = _dpcp_flow->apply_settings();
    if (status_out != dpcp::DPCP_OK) {
        rfs_logerr("Failed dpcp_flow_rule::apply_settings(), Status: %d, dpcp_flow: %p",
                   static_cast<int>(status_out), new_rule);
        return false;
    }

    return true;
}

bool rfs_rule::create_headers_table(dpcp::tir &tir, uint32_t flow_tag, dpcp::adapter &adapter)
{
    dpcp::adapter_hca_capabilities caps {};
    if (adapter.get_hca_capabilities(caps) != dpcp::DPCP_OK ||
        !caps.flow_table_caps.receive.is_flow_table_supported ||
        !caps.flow_table_caps.receive.is_flow_action_reformat_from_type_insert_supported ||
        !caps.flow_table_caps.receive.is_flow_action_reparse_supported ||
        caps.flow_table_caps.receive.max_flow_table_level < 2U) {
        rfs_logerr("headers-64 requires NIC RX insert-header, reparse and flow-table support");
        return false;
    }

    // Keep the established root matcher, including IPv6/VLAN/priority semantics.
    // Only this flow's destination changes: root match -> insert/reparse -> original TIR.
    dpcp::flow_table_attr table_attr;
    table_attr.type = dpcp::FT_RX;
    table_attr.level =
        std::min<uint32_t>(caps.flow_table_caps.receive.max_flow_table_level - 1U, UINT8_MAX);
    table_attr.log_size = 0; // One FTE, matching everything already selected by the root rule.
    if (adapter.create_flow_table(table_attr, _headers_table) != dpcp::DPCP_OK || !_headers_table ||
        _headers_table->create() != dpcp::DPCP_OK) {
        rfs_logerr("headers-64 failed to create receive insertion table");
        return false;
    }

    dpcp::flow_group_attr group_attr;
    std::weak_ptr<dpcp::flow_group> group_ref;
    if (_headers_table->add_flow_group(group_attr, group_ref) != dpcp::DPCP_OK ||
        group_ref.expired() || group_ref.lock()->create() != dpcp::DPCP_OK) {
        rfs_logerr("headers-64 failed to create receive insertion group");
        return false;
    }

    // Insert QinQ headers immediately after destination/source MAC addresses.
    // The original EtherType (and any original VLAN) stays after these eight bytes.
    uint8_t vlan_tags[] = {0x88, 0xa8, 0, 0, 0x81, 0, 0, 0};
    dpcp::flow_action_reformat_attr insert_attr {};
    insert_attr.insert.type = dpcp::INSERT_HDR;
    insert_attr.insert.start_hdr = dpcp::MAC_START;
    insert_attr.insert.offset = 12;
    insert_attr.insert.data_len = sizeof(vlan_tags);
    insert_attr.insert.data = vlan_tags;
    auto &generator = adapter.get_flow_action_generator();
    _headers_actions = {generator.create_reformat(insert_attr), generator.create_reparse(),
                        generator.create_fwd({&tir})};
    if (flow_tag) {
        _headers_actions.push_back(generator.create_tag(flow_tag));
    }
    for (const auto &action : _headers_actions) {
        if (!action) {
            rfs_logerr("headers-64 failed to allocate receive insertion action");
            return false;
        }
    }
    dpcp::flow_rule_attr_ex rule_attr;
    rule_attr.actions = _headers_actions;
    std::weak_ptr<dpcp::flow_rule_ex> rule;
    if (group_ref.lock()->add_flow_rule(rule_attr, rule) != dpcp::DPCP_OK || rule.expired() ||
        rule.lock()->create() != dpcp::DPCP_OK) {
        rfs_logerr("headers-64 failed to install VLAN insertion/reparse/TIR action");
        return false;
    }
    rfs_logdbg("headers-64: inserted 88a8:0000 / 8100:0000 before forwarding to TIR");
    return true;
}
