/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "dm_mgr.h"
#include <sys/uio.h>
#include "vlogger/vlogger.h"
#include "proto/mem_buf_desc.h"
#include "dev/ib_ctx_handler.h"

#if defined(DEFINED_DIRECT_VERBS)
#if defined(DEFINED_IBV_DM)

#include <atomic>
#include <link.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_ioctl_verbs.h>
#include <rdma/mlx5_user_ioctl_cmds.h>

#define DM_MEMORY_MASK_8          7
#define DM_MEMORY_MASK_64         63
#define DM_ALIGN_SIZE(size, mask) ((size + mask) & (~mask))

#undef MODULE_NAME
#define MODULE_NAME "dm_mgr"
#undef MODULE_HDR
#define MODULE_HDR MODULE_NAME "%d:%s() "

#define dm_logerr  __log_info_err
#define dm_logwarn __log_info_warn
#define dm_logdbg  __log_info_dbg
#define dm_logfunc __log_info_func

dm_mgr::dm_mgr()
    : m_p_dm_mr(nullptr)
    , m_p_ibv_dm(nullptr)
    , m_p_ring_stat(nullptr)
    , m_allocation(0)
    , m_used(0)
    , m_head(0) {};

// mlx5 exposes the mapping cookie and an in-page offset through DM_QUERY.
// The returned page index is a userspace mmap selector, not a BAR page number.
static void trace_mapping(ibv_dm *dm, unsigned qp, uint64_t generation)
{
    struct query {
        uint16_t length, object, method, count;
        uint64_t reserved1;
        uint32_t driver, reserved2;
        ib_uverbs_attr attrs[4];
    } request = {};
    static_assert(offsetof(query, attrs) == sizeof(ib_uverbs_ioctl_hdr), "uverbs header");
    uint64_t offset = 0, granted = 0;
    uint16_t page = 0;
    request.length = sizeof(request);
    request.object = UVERBS_OBJECT_DM;
    request.method = MLX5_IB_METHOD_DM_QUERY;
    request.count = 4;
    request.driver = RDMA_DRIVER_MLX5;
    auto attr = [&](int i, uint16_t id, uint16_t size, uint64_t value) {
        request.attrs[i].attr_id = id;
        request.attrs[i].len = size;
        request.attrs[i].flags = UVERBS_ATTR_F_MANDATORY;
        request.attrs[i].data = value;
    };
    attr(0, MLX5_IB_ATTR_QUERY_DM_REQ_HANDLE, 0, dm->handle);
    attr(1, MLX5_IB_ATTR_QUERY_DM_RESP_START_OFFSET, sizeof(offset), uintptr_t(&offset));
    attr(2, MLX5_IB_ATTR_QUERY_DM_RESP_PAGE_INDEX, sizeof(page), uintptr_t(&page));
    attr(3, MLX5_IB_ATTR_QUERY_DM_RESP_LENGTH, sizeof(granted), uintptr_t(&granted));
    int rc = ioctl(dm->context->cmd_fd, RDMA_VERBS_IOCTL, &request) < 0 ? errno : 0;
    mlx5dv_obj obj = {};
    mlx5dv_dm view = {};
    obj.dm.in = dm;
    obj.dm.out = &view;
    int dv_rc = mlx5dv_init_obj(&obj, MLX5DV_OBJ_DM);
    size_t pagesize = sysconf(_SC_PAGESIZE);
    tx_snapshot::metadata(
        "DM_MAP", qp, 0,
        {{"generation", generation},
         {"handle", dm->handle},
         {"query_rc", static_cast<unsigned>(rc)},
         {"dv_rc", static_cast<unsigned>(dv_rc)},
         {"page_index", page},
         {"start_offset", offset},
         {"page_size", pagesize},
         {"in_page_offset", offset % pagesize},
         {"granted_len", granted},
         {"mapping_va", uintptr_t(view.buf)},
         {"mapped_len", rc ? 0 : ((granted + pagesize - 1) / pagesize) * pagesize}});
}

struct provider_identity {
    uintptr_t address;
    const char *path;
    char build_id[129];
};

static int find_provider(dl_phdr_info *image, size_t, void *arg)
{
    auto &id = *static_cast<provider_identity *>(arg);
    bool found = false;
    for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
        const auto &p = image->dlpi_phdr[i];
        auto start = image->dlpi_addr + p.p_vaddr;
        if (p.p_type == PT_LOAD && id.address >= start && id.address - start < p.p_memsz) {
            found = true;
        }
    }
    if (!found) {
        return 0;
    }
    id.path = *image->dlpi_name ? image->dlpi_name : "/proc/self/exe";
    for (unsigned i = 0; i < image->dlpi_phnum; ++i) {
        const auto &p = image->dlpi_phdr[i];
        if (p.p_type != PT_NOTE) {
            continue;
        }
        const auto *cur = reinterpret_cast<const uint8_t *>(image->dlpi_addr + p.p_vaddr);
        const auto *end = cur + p.p_memsz;
        while (size_t(end - cur) >= sizeof(ElfW(Nhdr))) {
            ElfW(Nhdr) n;
            memcpy(&n, cur, sizeof(n));
            cur += sizeof(n);
            size_t names = (size_t(n.n_namesz) + 3) & ~size_t(3),
                   desc = (size_t(n.n_descsz) + 3) & ~size_t(3);
            if (names + desc > size_t(end - cur)) {
                break;
            }
            if (n.n_type == NT_GNU_BUILD_ID && n.n_namesz == 4 && !memcmp(cur, "GNU", 4) &&
                n.n_descsz <= 64) {
                for (unsigned j = 0; j < n.n_descsz; ++j) {
                    snprintf(id.build_id + 2 * j, 3, "%02x", cur[names + j]);
                }
                return 1;
            }
            cur += names + desc;
        }
    }
    return 1;
}

static void trace_identity(ib_ctx_handler *ctx, unsigned qp, const void *fn)
{
    provider_identity id = {reinterpret_cast<uintptr_t>(fn), "unknown", "unknown"};
    dl_iterate_phdr(find_provider, &id);
    char path[PATH_MAX], resolved[PATH_MAX], desc[800];
    snprintf(path, sizeof(path), "%s/device", ctx->get_ibv_device()->ibdev_path);
    const char *bdf = realpath(path, resolved) ? strrchr(resolved, '/') : nullptr;
    snprintf(desc, sizeof(desc),
             "rdma_device=%.64s pci_bdf=%.32s fw=%.64s provider=%.320s build_id=%.128s",
             ctx->get_ibname(), bdf ? bdf + 1 : "unknown", ctx->get_ibv_device_attr()->fw_ver,
             id.path, id.build_id);
    tx_snapshot::metadata(
        "DEVICE_ID", qp, 0,
        {{"dm_readback", tx_snapshot::read_dm()},
         {"configured_dm_bytes", static_cast<uint64_t>(safe_mce_sys().ring_dev_mem_tx)}},
        desc);
}

/*
 * Allocate dev_mem resources
 */
bool dm_mgr::allocate_resources(ib_ctx_handler *ib_ctx, ring_stats_t *ring_stats, unsigned qp)
{
    size_t allocation_size = DM_ALIGN_SIZE(safe_mce_sys().ring_dev_mem_tx, DM_MEMORY_MASK_64);
    xlio_ibv_alloc_dm_attr dm_attr;
    xlio_ibv_reg_mr_in mr_in;
    m_trace_qp = qp;
    m_p_ring_stat = ring_stats;
    if (!allocation_size) {
        trace_identity(ib_ctx, qp, reinterpret_cast<const void *>(&mlx5dv_init_obj));
        // On Device Memory usage was disabled by the user
        return false;
    }

    if (!ib_ctx->get_on_device_memory_size()) {
        // On Device Memory usage is not supported
        return false;
    }

    // Allocate on device memory buffer
    memset(&dm_attr, 0, sizeof(dm_attr));
    dm_attr.length = allocation_size;
    m_p_ibv_dm = xlio_ibv_alloc_dm(ib_ctx->get_ibv_context(), &dm_attr);
    if (!m_p_ibv_dm) {
        // Memory allocation can fail if we have already allocated the maximum possible.
        VLOG_PRINTF_ONCE_THEN_DEBUG(
            VLOG_WARNING, "**************************************************************\n");
        VLOG_PRINTF_ONCE_THEN_DEBUG(
            VLOG_WARNING, "Not enough memory on device to allocate %lu bytes             \n",
            allocation_size);
        VLOG_PRINTF_ONCE_THEN_DEBUG(
            VLOG_WARNING, "Continue working without on Device Memory usage               \n");
        VLOG_PRINTF_ONCE_THEN_DEBUG(
            VLOG_WARNING, "**************************************************************\n");
        errno = 0;
        return false;
    }

    // Initialize MR attributes
    memset(&mr_in, 0, sizeof(mr_in));
    xlio_ibv_init_dm_mr(mr_in, ib_ctx->get_ibv_pd(), allocation_size, m_p_ibv_dm);

    // Register On Device Memory MR
    m_p_dm_mr = xlio_ibv_reg_dm_mr(&mr_in);
    if (!m_p_dm_mr) {
        xlio_ibv_free_dm(m_p_ibv_dm);
        m_p_ibv_dm = nullptr;
        dm_logerr("ibv_free_dm error - dm_mr registration failed, %d %m", errno);
        return false;
    }

    int saved = errno;
    static std::atomic<uint64_t> next_generation {1};
    m_generation = next_generation.fetch_add(1, std::memory_order_relaxed);
    trace_identity(ib_ctx, qp, reinterpret_cast<const void *>(m_p_ibv_dm->memcpy_from_dm));
    tx_snapshot::metadata("DM_CREATE", qp, 0,
                          {{"generation", m_generation},
                           {"handle", m_p_ibv_dm->handle},
                           {"requested_len", dm_attr.length},
                           {"mr_handle", m_p_dm_mr->handle},
                           {"mr_base", 0},
                           {"mr_len", m_p_dm_mr->length},
                           {"lkey", m_p_dm_mr->lkey},
                           {"access", IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_ZERO_BASED}});
    trace_mapping(m_p_ibv_dm, qp, m_generation);
    errno = saved;
    m_allocation = allocation_size;
    m_p_ring_stat->n_tx_dev_mem_allocated = m_allocation;

    dm_logdbg("Device memory allocation completed successfully! device[%s] bytes[%zu] dm_mr "
              "handle[%d] dm_mr lkey[%d]",
              ib_ctx->get_ibv_device()->name, dm_attr.length, m_p_dm_mr->handle, m_p_dm_mr->lkey);

    return true;
}

/*
 * Release dev_mem resources
 */
void dm_mgr::release_resources()
{
    tx_snapshot::metadata("DM_DESTROY", m_trace_qp, 0,
                          {{"generation", m_generation},
                           {"handle", m_p_ibv_dm->handle},
                           {"mr_handle", m_p_dm_mr->handle},
                           {"lkey", m_p_dm_mr->lkey},
                           {"mr_base", 0},
                           {"mr_len", m_p_dm_mr->length},
                           {"access", IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_ZERO_BASED},
                           {"allocation", m_allocation},
                           {"head", m_head},
                           {"used", m_used}});
    if (m_p_dm_mr) {
        if (ibv_dereg_mr(m_p_dm_mr)) {
            dm_logerr("ibv_dereg_mr failed, %d %m", errno);
        } else {
            dm_logdbg("ibv_dereg_mr success");
        }
        m_p_dm_mr = nullptr;
    }

    if (m_p_ibv_dm) {
        if (xlio_ibv_free_dm(m_p_ibv_dm)) {
            dm_logerr("ibv_free_dm failed %d %m", errno);
        } else {
            dm_logdbg("ibv_free_dm success");
        }
        m_p_ibv_dm = nullptr;
    }

    m_p_ring_stat = nullptr;

    dm_logdbg("Device memory release completed!");
}

// The provider may reject a source address without touching it. Probe host
// memory without introducing a fault in the diagnostic path.
static void sample_host(tx_snapshot::message *msg, uint8_t *src)
{
    if (msg) {
        iovec local = {msg->bytes, msg->copy.read_length};
        iovec remote = {src, msg->copy.read_length};
        ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        msg->copy.read_rc = n < 0 ? errno : 0;
        msg->size = n < 0 ? 0 : static_cast<size_t>(n);
    }
}

static int trace_dm_copy(ibv_dm *dm, uint8_t *src, const tx_snapshot::dm_copy_info &info)
{
    auto sample = [&](const char *event, const char *storage) {
        auto *msg = tx_snapshot::allocate();
        if (msg) {
            msg->event = event;
            msg->storage = storage;
            msg->qp = info.site.qp;
            msg->wqe = info.site.wqe;
            msg->api_send = false;
            msg->dm_copy = true;
            msg->copy = info;
            msg->size = 0;
        }
        return msg;
    };
    auto *before = sample("DM_HOST_BEFORE", "host");
    auto *after = sample("DM_HOST_AFTER", "host");
    auto *device = tx_snapshot::read_dm() ? sample("DM_READBACK", "device") : nullptr;
    xlio_ibv_memcpy_dm_attr attr = {};
    xlio_ibv_init_memcpy_dm(attr, src, info.dm_offset, info.copy_length);
    int saved = errno;
    sample_host(before, src);
    errno = saved;
    int rc = xlio_ibv_memcpy_dm(dm, &attr);
    saved = errno;
    sample_host(after, src);
    if (device) {
        // Distinguish bytes left untouched by the provider from a zero-filled
        // tail or the device bad-access signature.
        memset(device->bytes, 0xa5, info.read_length);
        device->copy.read_rc =
            ibv_memcpy_from_dm(device->bytes, dm, info.dm_offset, info.read_length);
        if (!device->copy.read_rc) {
            device->size = info.read_length;
        }
    }
    for (auto *msg : {before, after, device}) {
        if (msg) {
            msg->copy.copy_rc = rc;
            tx_snapshot::enqueue(msg);
        }
    }
    errno = saved;
    return rc;
}

/*
 * Copy data into the On Device Memory buffer.
 *
 * On Device Memory buffer is implemented in a cycle way using two variables :
 * m_head - index of the next offset to be written.
 * m_used - amount of used bytes within the On Device Memory buffer (which also used to calculate
 * the tail of the buffer).
 *
 * In order to maintain a proper order of allocation and release, we must distinguish between three
 * possible cases:
 *
 * First case:
 *   Free space exists in the beginning and in the end of the array.
 *
 *   |-------------------------------------------|
 *   |    |XXXXXXXXXX|                           |
 *   |-------------------------------------------|
 *       tail     head
 *
 * Second case:
 *   There is not enough free space at the end of the array.
 *   |-------------------------------------------|
 *   |                             |XXXXXXXXXX|  |
 *   |-------------------------------------------|
 *                                tail     head
 *
 *   In the case above, we will move the head to the beginning of the array.
 *   |-------------------------------------------|
 *   |                             |XXXXXXXXXXXXX|
 *   |-------------------------------------------|
 *   head                         tail
 *
 * Third case:
 *   Free space exists in the middle of the array
 *   |-------------------------------------------|
 *   |XXXXXXXXXXXXXX|                     |XXXXXX|
 *   |-------------------------------------------|
 *                 head                 tail
 *
 * Due to hardware limitations:
 * 1. Data should be written to 4bytes aligned addresses.
 * 2. Data length should be aligned to 4bytes.
 *
 * Due to performance reasons:
 *  1. Data should be written to a continuous memory area.
 *  2. Data will be written to 8bytes aligned addresses.
 */
bool dm_mgr::copy_data(struct mlx5_wqe_data_seg *seg, uint8_t *src, uint32_t length,
                       mem_buf_desc_t *buff, const tx_snapshot::copy_site &site)
{

    uint32_t length_aligned_8 = DM_ALIGN_SIZE(length, DM_MEMORY_MASK_8);
    size_t continuous_left = 0;
    const auto old_head = m_head, old_used = m_used, old_charge = buff->tx.dev_mem_length;
    size_t selected = m_head, wrap_padding = 0;
    const char *reason = "reason=insufficient_contiguous_space";
    auto account = [&](const char *event, const char *detail) {
        tx_snapshot::metadata(event, site.qp, site.wqe,
                              {{"generation", m_generation},
                               {"descriptor", reinterpret_cast<uintptr_t>(buff)},
                               {"sge", static_cast<unsigned>(site.sge)},
                               {"logical_len", length},
                               {"copy_len", length_aligned_8},
                               {"offset", selected},
                               {"wrap_padding", wrap_padding},
                               {"head_before", old_head},
                               {"head_after", m_head},
                               {"used_before", old_used},
                               {"used_after", m_used},
                               {"charge_before", old_charge},
                               {"charge_after", buff->tx.dev_mem_length}},
                              detail);
    };
    size_t &dev_mem_length = buff->tx.dev_mem_length = 0;

    // Check if On Device Memory buffer is full
    if (m_used >= m_allocation) {
        reason = "reason=full";
        goto dev_mem_oob;
    }

    // Check for a continuous space to write
    if (m_head >= m_used) { // First case
        if ((continuous_left = m_allocation - m_head) < length_aligned_8) { // Second case
            if (m_head - m_used >= length_aligned_8) {
                // There is enough space at the beginning of the buffer.
                selected = m_head = 0;
                wrap_padding = continuous_left;
                dev_mem_length = continuous_left;
            } else {
                // There no enough space at the beginning of the buffer.
                goto dev_mem_oob;
            }
        }
    } else if ((continuous_left = m_allocation - m_used) < length_aligned_8) { // Third case
        goto dev_mem_oob;
    }

    {
        const tx_snapshot::dm_copy_info info = {
            site,
            reinterpret_cast<uintptr_t>(src),
            m_p_ibv_dm->handle,
            m_p_dm_mr->lkey,
            m_head,
            m_allocation,
            length,
            length_aligned_8,
            std::min<size_t>(length_aligned_8, tx_snapshot::limit),
            0,
            0};
        if (trace_dm_copy(m_p_ibv_dm, src, info)) {
            account("DM_FALLBACK", "reason=provider_copy_failed");
            dm_logfunc("Failed to memcopy data into the memic buffer %m");
            return false;
        }
    }

    // Update values
    seg->lkey = htonl(m_p_dm_mr->lkey);
    seg->addr = htonll(m_head);
    m_head = (m_head + length_aligned_8) % m_allocation;
    dev_mem_length += length_aligned_8;
    buff->tx.dm_owner_wqe = site.wqe;
    m_used += dev_mem_length;
    account("DM_RESERVE", "");

    // Update On Device Memory statistics
    m_p_ring_stat->n_tx_dev_mem_pkt_count++;
    m_p_ring_stat->n_tx_dev_mem_byte_count += length;

    NOT_IN_USE(continuous_left);
    dm_logfunc("Send completed successfully! Buffer[%p] length[%d] length_aligned_8[%d] "
               "continuous_left[%zu] head[%zu] used[%zu]",
               buff, length, length_aligned_8, continuous_left, m_head, m_used);

    return true;

dev_mem_oob:
    account("DM_FALLBACK", reason);
    dm_logfunc("Send OOB! Buffer[%p] length[%d] length_aligned_8[%d] continuous_left[%zu] "
               "head[%zu] used[%zu]",
               buff, length, length_aligned_8, continuous_left, m_head, m_used);

    m_p_ring_stat->n_tx_dev_mem_oob++;

    return false;
}

/*
 * Release On Device Memory buffer.
 * This method should be called after completion was received.
 */
void dm_mgr::release_data(mem_buf_desc_t *buff, unsigned retiring_wqe)
{
    const size_t charge = buff->tx.dev_mem_length;
    const size_t before = m_used;
    m_used -= charge;
    tx_snapshot::metadata(
        "DM_RELEASE", m_trace_qp, buff->tx.dm_owner_wqe,
        {{"generation", m_generation},
         {"descriptor", reinterpret_cast<uintptr_t>(buff)},
         {"charge", charge},
         {"ref_before", buff->lwip_pbuf.ref},
         {"head", m_head},
         {"used_before", before},
         {"used_after", m_used},
         {"cq_retirement", retiring_wqe != UINT32_MAX}},
        retiring_wqe == UINT32_MAX ? "path=descriptor_return" : "path=cq_retirement");
    buff->tx.dev_mem_length = 0;

    dm_logfunc("Device memory release! buffer[%p] buffer_dev_mem_length[%zu] head[%zu] used[%zu]",
               buff, buff->tx.dev_mem_length, m_head, m_used);
}

#endif /* DEFINED_IBV_DM */
#endif /* DEFINED_DIRECT_VERBS */
