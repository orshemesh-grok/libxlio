/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "util/valgrind.h"
#if defined(DEFINED_DIRECT_VERBS)

#include "util/valgrind.h"
#include "util/utils.h"
#include "ib/mlx5/ib_mlx5.h"

int xlio_ib_mlx5_get_qp_tx(dpcp::pp_sq *sq, xlio_ib_mlx5_qp_t *mlx5_qp)
{
    if (!sq || !mlx5_qp) {
        return -1;
    }

    uint32_t sqn = 0;
    if (sq->get_id(sqn) != dpcp::DPCP_OK) {
        return -1;
    }

    void *wq_buf = nullptr;
    if (sq->get_wq_buf(wq_buf) != dpcp::DPCP_OK) {
        return -1;
    }

    uint32_t *dbrec = nullptr;
    if (sq->get_dbrec(dbrec) != dpcp::DPCP_OK) {
        return -1;
    }

    uint64_t *bf_reg = nullptr;
    if (sq->get_bf_reg(bf_reg) != dpcp::DPCP_OK) {
        return -1;
    }

    uint32_t wqe_num = 0;
    if (sq->get_wqe_num(wqe_num) != dpcp::DPCP_OK) {
        return -1;
    }

    uint32_t wqe_sz = 0;
    if (sq->get_wqe_sz(wqe_sz) != dpcp::DPCP_OK) {
        return -1;
    }

    mlx5_qp->qpn = sqn;
    mlx5_qp->sqn = sqn;
    mlx5_qp->sq.buf = wq_buf;
    mlx5_qp->sq.dbrec = dbrec;
    mlx5_qp->sq.wqe_cnt = wqe_num;
    mlx5_qp->sq.stride = wqe_sz;
    mlx5_qp->bf.reg = (void *)bf_reg;

    return 0;
}

int xlio_ib_mlx5_get_cq(dpcp::cq *cq, xlio_ib_mlx5_cq_t *mlx5_cq)
{
    if (!mlx5_cq || !cq || mlx5_cq->initialized) {
        return 0;
    }

    uint32_t cqn = 0;
    if (cq->get_id(cqn) != dpcp::DPCP_OK) {
        return -1;
    }

    void *cq_buf = nullptr;
    if (cq->get_cq_buf(cq_buf) != dpcp::DPCP_OK) {
        return -1;
    }

    uint32_t *dbrec = nullptr;
    if (cq->get_dbrec(dbrec) != dpcp::DPCP_OK) {
        return -1;
    }

    volatile void *uar_page = nullptr;
    if (cq->get_uar_page(uar_page) != dpcp::DPCP_OK) {
        return -1;
    }

    uint32_t cqe_num = 0;
    if (cq->get_cqe_num(cqe_num) != dpcp::DPCP_OK) {
        return -1;
    }

    size_t cqe_size = cq->get_cqe_sz();

    mlx5_cq->initialized = true;
    mlx5_cq->cq_num = cqn;
    mlx5_cq->cq_ci = 0;
    mlx5_cq->cq_sn = 0;
    mlx5_cq->cqe_count = cqe_num;
    mlx5_cq->cqe_size = cqe_size;
    mlx5_cq->cqe_size_log = ilog_2(cqe_size);
    mlx5_cq->dbrec = dbrec;
    mlx5_cq->uar = (void *)uar_page;

    /* Move buffer forward for 128b CQE, so we would get pointer to the 2nd
     * 64b when polling.
     */
    mlx5_cq->cq_buf = (uint8_t *)cq_buf + cqe_size - sizeof(struct xlio_mlx5_cqe);

    return 0;
}

#endif /* DEFINED_DIRECT_VERBS */
