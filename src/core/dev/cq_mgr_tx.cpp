/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "dev/cq_mgr_tx.h"
#include <util/valgrind.h>
#include <sock/sock-redirect.h>
#include <sock/sock-app.h>
#include <iomanip>
#include "ring_simple.h"
#include "hw_queue_tx.h"

#define MODULE_NAME "cq_mgr_tx"

#define cq_logpanic   __log_info_panic
#define cq_logerr     __log_info_err
#define cq_logwarn    __log_info_warn
#define cq_loginfo    __log_info_info
#define cq_logdbg     __log_info_dbg
#define cq_logfunc    __log_info_func
#define cq_logfuncall __log_info_funcall

#define WQEBB_SIZE 64

cq_mgr_tx::cq_mgr_tx(ring_simple *p_ring, ib_ctx_handler *p_ib_ctx_handler, int cq_size,
                     dpcp::comp_channel *p_comp_event_channel)
    : m_p_ring(p_ring)
    , m_p_ib_ctx_handler(p_ib_ctx_handler)
    , m_comp_event_channel(p_comp_event_channel)
{
    configure(cq_size);

    memset(&m_mlx5_cq, 0, sizeof(m_mlx5_cq));
}

cq_mgr_tx::~cq_mgr_tx()
{
    cq_logdbg("Destroying CQ as Tx");

    delete m_p_cq;
    m_p_cq = nullptr;

    cq_logdbg("Destroying CQ as Tx done");
}

uint32_t cq_mgr_tx::get_cqn()
{
    uint32_t cqn = 0;
    if (m_p_cq) {
        m_p_cq->get_id(cqn);
    }
    return cqn;
}

void cq_mgr_tx::configure(int cq_size)
{
    dpcp::adapter *adapter = m_p_ib_ctx_handler->get_dpcp_adapter();
    if (!adapter) {
        throw_xlio_exception("dpcp adapter not available for CQ creation");
    }

    uint32_t eqn = 0;
    uint32_t comp_vector = 0;
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    if (safe_mce_sys().app.distribute_cq_interrupts && g_p_app->get_worker_id() >= 0) {
        comp_vector = g_p_app->get_worker_id();
    }
#endif
    if (adapter->query_eqn(eqn, comp_vector) != dpcp::DPCP_OK) {
        throw_xlio_exception("Failed to query EQN for TX CQ");
    }

        dpcp::cq_attr cq_attr = {};
    cq_attr.cq_sz = cq_size;
    cq_attr.eq_num = eqn;
    cq_attr.cq_attr_use.set(dpcp::CQ_SIZE);
    cq_attr.cq_attr_use.set(dpcp::CQ_EQ_NUM);

    dpcp::status rc = adapter->create_cq(cq_attr, m_p_cq);
    if (rc != dpcp::DPCP_OK || !m_p_cq) {
        throw_xlio_exception("dpcp create_cq failed for TX CQ");
    }

    if (m_comp_event_channel) {
        rc = m_comp_event_channel->bind(*m_p_cq);
        if (rc != dpcp::DPCP_OK) {
            cq_logwarn("Failed to bind TX comp_channel to CQ (rc=%d)", (int)rc);
        }
    }

    cq_logdbg("Created CQ as Tx with fd[%d] and of size %d elements (dpcp::cq=%p)",
              get_channel_fd(), cq_size, m_p_cq);
}

void cq_mgr_tx::add_qp_tx(hw_queue_tx *hqtx_ptr)
{
    cq_logdbg("hqtx_ptr=%p", hqtx_ptr);
    m_hqtx_ptr = hqtx_ptr;

    if (0 != xlio_ib_mlx5_get_cq(m_p_cq, &m_mlx5_cq)) {
        cq_logpanic("xlio_ib_mlx5_get_cq failed (errno=%d %m)", errno);
    }

    cq_logfunc("hqtx_ptr=%p m_mlx5_cq.dbrec=%p m_mlx5_cq.cq_buf=%p", m_hqtx_ptr, m_mlx5_cq.dbrec,
               m_mlx5_cq.cq_buf);
}

void cq_mgr_tx::del_qp_tx(hw_queue_tx *hqtx_ptr)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (m_hqtx_ptr != hqtx_ptr) {
        cq_logdbg("wrong hqtx_ptr=%p != m_hqtx_ptr=%p", hqtx_ptr, m_hqtx_ptr);
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    cq_logdbg("m_hqtx_ptr=%p", m_hqtx_ptr);
    m_hqtx_ptr = nullptr;
}

bool cq_mgr_tx::request_notification()
{
    cq_logfuncall("");

    if (m_b_notification_armed == false) {

        cq_logfunc("arming cq_mgr_tx notification channel");

        // Arm the CQ notification channel
        IF_VERBS_FAILURE(xlio_ib_mlx5_req_notify_cq(&m_mlx5_cq, 0))
        {
            cq_logerr("Failure arming the TX notification channel (errno=%d %m)", errno);
        }
        else
        {
            m_b_notification_armed = true;
        }
        ENDIF_VERBS_FAILURE;
    }

    cq_logfuncall("returning with %d", m_b_notification_armed ? 1 : 0);
    return m_b_notification_armed;
}

cq_mgr_tx *cq_mgr_tx::get_cq_mgr_from_cq_event(dpcp::comp_channel *p_cq_channel,
                                                 dpcp::cq *p_cq)
{
    if (!p_cq_channel || !p_cq) {
        return nullptr;
    }

    dpcp::eq_context eq_ctx = {};
    dpcp::status rc = p_cq_channel->request(*p_cq, eq_ctx);
    if (rc != dpcp::DPCP_OK) {
        vlog_printf(VLOG_INFO,
                    MODULE_NAME
                    ":%d: waiting on cq_mgr_tx event returned with error (rc=%d errno=%d %m)\n",
                    __LINE__, (int)rc, errno);
        return nullptr;
    }

    return nullptr;
}

std::string cq_mgr_tx::wqe_to_hexstring(uint16_t index, uint32_t credits) const
{
    const auto sq_start = static_cast<const uint8_t *>(m_hqtx_ptr->m_mlx5_qp.sq.buf);

    std::ostringstream oss;
    // see `calculate_credits` - credits is give or take the amount of WQEBBs per WQE
    for (uint32_t wqebb_i = 0; wqebb_i < credits; ++wqebb_i) {
        const uint32_t wqebb_wrapped_index = (index + wqebb_i) & (m_hqtx_ptr->m_tx_num_wr - 1);
        const auto current_wqebb_begin = sq_start + wqebb_wrapped_index * WQEBB_SIZE;

        for (uint8_t wqebb_inner_i = 0; wqebb_inner_i < WQEBB_SIZE; ++wqebb_inner_i) {
            const auto current_byte_ptr = current_wqebb_begin + wqebb_inner_i;
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<uint32_t>(*current_byte_ptr);
        }
    }

    return oss.str();
}

int cq_mgr_tx::poll_and_process_element_tx()
{
    cq_logfuncall("");

    static auto is_error_opcode = [&](uint8_t opcode) {
        return opcode == MLX5_CQE_REQ_ERR || opcode == MLX5_CQE_RESP_ERR;
    };

    int ret = -1;
    xlio_mlx5_cqe *cqe = get_cqe_tx();

    if (likely(cqe)) {
        unsigned index = ntohs(cqe->wqe_counter) & (m_hqtx_ptr->m_tx_num_wr - 1);

        // All error opcodes have the most significant bit set.
        if (unlikely(cqe->op_own & 0x80) && is_error_opcode(cqe->op_own >> 4)) {
            // m_p_cq_stat->n_tx_cqe_error++; Future counter
            log_cqe_error(cqe, index, m_hqtx_ptr->m_sq_wqe_idx_to_prop[index].credits);

            m_hqtx_ptr->m_sq_wqe_idx_to_prop[index].buf->m_flags |= mem_buf_desc_t::HAD_CQE_ERROR;
        }

        handle_sq_wqe_prop(index);
        ret = 1;
    }

    return ret;
}

void cq_mgr_tx::log_cqe_error(struct xlio_mlx5_cqe *cqe, uint16_t wqe_index, uint32_t credits) const
{
    struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe;

    /* TODO We can also ask hw_queue_tx to log WQE fields from SQ. But at first, we need to remove
     * prefetch and memset of the next WQE there. Credit system will guarantee that we don't
     * reuse the WQE at this point.
     */

    if (MLX5_CQE_SYNDROME_WR_FLUSH_ERR != ecqe->syndrome) {
        cq_logwarn("cqe: syndrome=0x%x vendor=0x%x hw=0x%x (type=0x%x) wqe_opcode_qpn=0x%x "
                   "wqe_counter=0x%x wqe=%s",
                   ecqe->syndrome, ecqe->vendor_err_synd, *((uint8_t *)&ecqe->rsvd1 + 16),
                   *((uint8_t *)&ecqe->rsvd1 + 17), ntohl(ecqe->s_wqe_opcode_qpn),
                   ntohs(ecqe->wqe_counter), wqe_to_hexstring(wqe_index, credits).c_str());
    }
}

void cq_mgr_tx::handle_sq_wqe_prop(unsigned index)
{
    sq_wqe_prop *p = &m_hqtx_ptr->m_sq_wqe_idx_to_prop[index];
    sq_wqe_prop *prev;
    unsigned credits = 0;

    /*
     * TX completions can be signalled for a set of WQEs as an optimization.
     * Therefore, for every TX completion we may need to handle multiple
     * WQEs. Since every WQE can have various size and the WQE index is
     * wrapped around, we build a linked list to simplify things. Each
     * element of the linked list represents properties of a previously
     * posted WQE.
     *
     * We keep index of the last completed WQE and stop processing the list
     * when we reach the index. This condition is checked in
     * is_sq_wqe_prop_valid().
     */

    do {
        if (p->buf) {
            m_p_ring->mem_buf_desc_return_single_locked(p->buf);
        }
        if (p->ti) {
            xlio_ti *ti = p->ti;
            if (ti->m_callback) {
                ti->m_callback(ti->m_callback_arg);
            }

            ti->put();
            if (unlikely(ti->m_released && ti->m_ref == 0)) {
                ti->ti_released();
            }
        }
        credits += p->credits;

        prev = p;
        p = p->next;
    } while (prev != m_hqtx_ptr->m_last_sq_wqe_prop_to_complete);

    m_p_ring->return_tx_pool_to_global_pool();
    m_hqtx_ptr->credits_return(credits);
    m_hqtx_ptr->m_last_sq_wqe_prop_to_complete =
        &m_hqtx_ptr->m_sq_wqe_idx_to_prop[(index + m_hqtx_ptr->m_sq_wqe_idx_to_prop[index].wqebbs) %
                                          m_hqtx_ptr->m_tx_num_wr];
}
