/*
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#pragma once
#include "util/tx_snapshot.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <unistd.h>
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
    auto *msg = allocate();
    if (!msg) {
        return;
    }
    auto &bytes = msg->bytes;
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
    size_t frame_offset = header_size;
    int segment = 0;
    bool prefix_readable = true;
    while (offset < ds_bytes) {
        auto *seg = reinterpret_cast<const mlx5_wqe_data_seg *>(base + ring_offset(offset));
        unsigned count = ntohl(seg->byte_count);
        if (count & 0x80000000U) {
            copy_inline(offset + sizeof(seg->byte_count), count & 0x7fffffffU);
            break;
        }
        offset += sizeof(*seg);
        auto *part = allocate();
        if (!part) {
            break;
        }
        part->event = "TX_SGE";
        part->stage = event;
        part->api_send = false;
        part->qp = qp;
        part->wqe = counter;
        part->segment = segment++;
        part->total = count;
        part->offset = frame_offset;
        part->address = be64toh(seg->addr);
        part->lkey = ntohl(seg->lkey);
        size_t take = std::min<size_t>(count, limit);
        part->size = 0;
        part->read_length = take;
        part->read_rc = 0;
        int saved = errno;
#ifdef DEFINED_IBV_DM
        auto *dm = get_dm(part->lkey);
        if (dm && !read_dm()) {
            part->storage = "device-read-skipped";
            part->read_length = 0;
            part->read_rc = ECANCELED;
        } else if (dm) {
            part->storage = "device";
            part->read_length = (take + 3U) & ~size_t(3U);
            memset(part->bytes, 0xa5, part->read_length);
            part->read_rc = ibv_memcpy_from_dm(part->bytes, dm, part->address, part->read_length);
            if (!part->read_rc) {
                part->size = take;
            }
        } else
#endif
        {
            part->storage = "dma";
            iovec dst = {part->bytes, take};
            iovec src = {reinterpret_cast<void *>(part->address), take};
            ssize_t n = process_vm_readv(getpid(), &dst, 1, &src, 1, 0);
            part->size = n < 0 ? 0 : static_cast<size_t>(n);
            part->read_rc = n < 0 ? errno : 0;
        }
        errno = saved;
        if (prefix_readable && size < limit) {
            size_t copied = std::min(limit - size, part->size);
            memcpy(bytes + size, part->bytes, copied);
            size += copied;
            prefix_readable = size == limit || part->size == take;
            storage = prefix_readable ? part->storage : "unreadable";
        }
        enqueue(part);
        frame_offset += count;
    }
    msg->event = event;
    msg->storage = storage;
    msg->qp = qp;
    msg->wqe = counter;
    msg->size = size;
    msg->api_send = false;
    enqueue(msg);
}
} //namespace tx_snapshot
