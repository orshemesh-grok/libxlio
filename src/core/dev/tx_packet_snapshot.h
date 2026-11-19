/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#pragma once
#include "util/tx_snapshot.h"
#include <infiniband/mlx5dv.h>
#include <netinet/in.h>
#include <sys/uio.h>

namespace tx_snapshot {
template <class Lookup>
inline void packet(const uint8_t *base, size_t ring_size, size_t offset_in_ring, unsigned qp,
                   const char *event, Lookup get_dm)
{
    (void)get_dm;
    const auto *wqe = base + offset_in_ring;
    const auto *ctrl = reinterpret_cast<const mlx5_wqe_ctrl_seg *>(wqe);
    const auto *eth = reinterpret_cast<const mlx5_wqe_eth_seg *>(ctrl + 1);
    const unsigned counter = ntohl(ctrl->opmod_idx_opcode) >> 8 & 0xffff;
    const size_t ds_bytes = (ntohl(ctrl->qpn_ds) & 0x3f) * 16U;
    const size_t header_size = ntohs(eth->inline_hdr_sz);
    uint8_t bytes[tx_snapshot::limit];
    size_t size = 0;
    size_t offset = sizeof(*ctrl) + offsetof(mlx5_wqe_eth_seg, inline_hdr_start);
    auto ring_offset = [&](size_t pos) { return (offset_in_ring + pos) % ring_size; };
    auto copy_inline = [&](size_t pos, size_t count) {
        count = std::min(count, sizeof(bytes) - size);
        size_t start = ring_offset(pos);
        size_t first = std::min(count, ring_size - start);
        memcpy(bytes + size, base + start, first);
        memcpy(bytes + size + first, base, count - first);
        size += count;
    };
    copy_inline(offset, header_size);
    offset = (offset + header_size + 15U) & ~size_t(15U);
    const char *storage = "wqe-inline";
    while (offset < ds_bytes && size < sizeof(bytes)) {
        auto *seg = reinterpret_cast<const mlx5_wqe_data_seg *>(base + ring_offset(offset));
        unsigned count = ntohl(seg->byte_count);
        if (count & 0x80000000U) {
            copy_inline(offset + sizeof(seg->byte_count), count & 0x7fffffffU);
            break;
        }
        offset += sizeof(*seg);
        size_t take = std::min<size_t>(count, sizeof(bytes) - size);
        if (!take) {
            continue;
        }
        // Some registered addresses are inaccessible to the CPU. A failed read
        // must not turn a diagnostic into an application fault.
        int saved = errno;
        ssize_t n;
#ifdef DEFINED_IBV_DM
        auto *dm = get_dm(ntohl(seg->lkey));
        if (dm) {
            alignas(4) uint8_t tmp[tx_snapshot::limit];
            n = ibv_memcpy_from_dm(tmp, dm, be64toh(seg->addr), (take + 3U) & ~size_t(3U)) == 0
                ? static_cast<ssize_t>(take)
                : -1;
            if (n > 0) {
                memcpy(bytes + size, tmp, take);
            }
            storage = "device";
        } else
#endif
        {
            iovec dst = {bytes + size, take};
            iovec src = {reinterpret_cast<void *>(be64toh(seg->addr)), take};
            n = process_vm_readv(getpid(), &dst, 1, &src, 1, 0);
            storage = "dma";
        }
        errno = saved;
        if (n > 0) {
            size += static_cast<size_t>(n);
        }
        if (n != static_cast<ssize_t>(take)) {
            storage = "unreadable";
            break;
        }
    }
    tx_snapshot::record(event, qp, counter, bytes, size, storage);
}
} //namespace tx_snapshot
