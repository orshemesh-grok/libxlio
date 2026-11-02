/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "core/util/xlio_stats.h"
#include "rx_layout_summary.h"
#include "rx_analysis_csv.h"
#include <fstream>
#include "rx_layout_view.h"
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <signal.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace {
volatile sig_atomic_t capture_stopped = 0;
void stop_capture(int)
{
    capture_stopped = 1;
}
struct mapping {
    int fd = -1;
    void *address = MAP_FAILED;
    size_t size = 0;
    ~mapping()
    {
        if (address != MAP_FAILED) {
            munmap(address, size);
        }
        if (fd >= 0) {
            close(fd);
        }
    }
};
struct signals {
    struct sigaction old_int {
    }, old_term {};
    signals()
    {
        capture_stopped = 0;
        struct sigaction action {};
        action.sa_handler = stop_capture;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, &old_int);
        sigaction(SIGTERM, &action, &old_term);
    }
    ~signals()
    {
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
    }
};

void print_batch(unsigned index, const xlio_rx_layout::batch &b, xlio_rx_layout::analyzer &analysis,
                 uint64_t batch_id, std::ostream *csv)
{
    using namespace xlio_rx_layout;
    std::vector<observation> observations;
    for (unsigned i = 0; i < b.count; ++i) {
        observations.push_back(analysis.inspect(b.records[i], b, batch_id));
        if (csv) {
            csv_record(*csv, b.records[i], observations.back(), b, batch_id);
        }
    }
    auto s = summarize(observations);
    printf("Ring %u id=0x%" PRIx64 " ifindex=%u generation=%" PRIu64 ": %u/%u samples%s\n", index,
           b.ring_id, b.if_index, b.generation, b.count, b.requested, b.closed ? " (closed)" : "");
    if (!b.count) {
        printf("  No traffic\n");
        return;
    }
    const auto &c = b.context;
    auto n = [](unsigned value, bool valid) { return valid ? std::to_string(value) : "-"; };
    printf("  LRO context: enable-mask=%s min-mss=%s psh=%s timestamp=%s max-size=%s size-mode=%s "
           "timeout-us=%s\n",
           n(c.enable_mask, c.tir_known).c_str(), n(c.min_mss, c.caps_known).c_str(),
           n(c.psh, c.caps_known).c_str(), n(c.timestamp, c.caps_known).c_str(),
           n(c.max_lro_bytes, c.tir_known).c_str(), n(c.max_size_mode, c.caps_known).c_str(),
           n(c.timeout_us, c.tir_known).c_str());
    for (auto *rows : {&s.rows, &s.excluded}) {
        if (rows->empty()) {
            continue;
        }
        if (rows == &s.excluded) {
            printf(" Excluded packets (included in sample count and CSV):\n");
        }
        printf(" Count   Share RQ   IP LRO Prefix Hdr L2/IP/TCP   Frame Payload Offset A%%64 L%%64 "
               "Flags Incomplete lro_abrt    lro disq%s\n",
               rows == &s.excluded ? " | excluded" : "");
        for (const auto &row : *rows) {
            const auto &o = row.item;
            const auto &r = o.sizes;
            const char *abort_names[] = {"0:max-size", "1:timeout", "2:exception", "3:undefined"};
            std::string abrt = r.lro_segments ? abort_names[o.abrt] : "-";
            char flags[8];
            snprintf(flags, sizeof(flags), "0x%02x", r.tcp_flags);
            printf(" %5u %6.2f%% %-4s %2s %3s %6u %3s %2s/%2s/%2s %8u %7s %6s %4s %4s %5s %10s "
                   "%-11s %s%s%s\n",
                   row.count, 100.0 * row.count / b.count, r.striding ? "STRQ" : "RQ",
                   n(r.ip_version, o.ip_valid).c_str(), n(r.lro_segments, o.cqe_valid).c_str(),
                   r.prefix_bytes, n(r.l2_bytes + r.l3_bytes + r.tcp_bytes, o.tcp_valid).c_str(),
                   n(r.l2_bytes, o.ethernet_valid).c_str(), n(r.l3_bytes, o.ip_valid).c_str(),
                   n(r.tcp_bytes, o.tcp_fields_valid).c_str(), r.frame_bytes,
                   n(r.payload_bytes, o.tcp_valid).c_str(),
                   n(r.payload_offset, o.tcp_valid).c_str(),
                   n(r.payload_mod64, o.tcp_valid).c_str(),
                   n(r.payload_bytes % 64, o.tcp_valid).c_str(), o.tcp_fields_valid ? flags : "-",
                   o.incomplete ? "true" : "false", abrt.c_str(), o.disq.c_str(),
                   o.excluded.empty() ? "" : " | ", o.excluded.c_str());
        }
    }
    printf(" Data=%u, control-only=%u", s.data, s.control);
    if (s.data) {
        printf("; data alignment: offset=64 %.2f%%, address%%64=0 %.2f%%, length%%64=0 %.2f%%",
               100.0 * s.offset64 / s.data, 100.0 * s.address64 / s.data,
               100.0 * s.length64 / s.data);
    }
    printf("\n");
}
} // namespace

int print_rx_analysis(int pid, const std::string &directory, unsigned samples, int interval,
                      int cycles, const std::string &csv_path)
{
    using namespace xlio_rx_layout;
    if (interval < 1 || samples < 1 || samples > capacity || cycles < 0) {
        fprintf(stderr, "xliostat: RX analysis needs interval >= 1 and samples in [1, %u]\n",
                capacity);
        return 1;
    }
    const std::string path = directory + "/xliostat." + std::to_string(pid);
    mapping m;
    m.fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (m.fd < 0) {
        fprintf(stderr, "xliostat: RX capture needs read/write access to %s: %s\n", path.c_str(),
                strerror(errno));
        return 1;
    }
    if (flock(m.fd, LOCK_EX | LOCK_NB) != 0) {
        fprintf(stderr, "xliostat: RX capture is busy or cannot be locked: %s\n", strerror(errno));
        return 1;
    }
    struct stat info {};
    if (fstat(m.fd, &info) || info.st_size < static_cast<off_t>(sizeof(sh_mem_t))) {
        fprintf(stderr, "xliostat: incomplete statistics header\n");
        return 1;
    }
    m.size = sizeof(sh_mem_t);
    m.address = mmap(nullptr, m.size, PROT_READ, MAP_SHARED, m.fd, 0);
    if (m.address == MAP_FAILED) {
        fprintf(stderr, "xliostat: cannot map statistics header: %s\n", strerror(errno));
        return 1;
    }
    auto *header = static_cast<const sh_mem_t *>(m.address);
    if (memcmp(header->stats_protocol_ver, STATS_PROTOCOL_VER,
               std::min(sizeof(header->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER))) != 0) {
        fprintf(stderr, "xliostat: incompatible statistics protocol\n");
        return 1;
    }
    size_t sockets = header->max_skt_inst_num;
    const size_t limit =
        (std::numeric_limits<size_t>::max() - sizeof(sh_mem_t) - sizeof(region) - 63U) /
        sizeof(socket_instance_block_t);
    if (sockets > limit) {
        fprintf(stderr, "xliostat: invalid statistics size\n");
        return 1;
    }
    size_t offset = extension_offset(SHMEM_STATS_SIZE(sockets));
    size_t full_size = offset + sizeof(region);
    if (static_cast<uint64_t>(info.st_size) < full_size) {
        fprintf(stderr, "xliostat: RX analysis capture is not supported by this library\n");
        return 1;
    }
    munmap(m.address, m.size);
    m.size = full_size;
    m.address = mmap(nullptr, m.size, PROT_READ | PROT_WRITE, MAP_SHARED, m.fd, 0);
    if (m.address == MAP_FAILED) {
        fprintf(stderr, "xliostat: cannot map RX capture: %s\n", strerror(errno));
        return 1;
    }
    auto *capture = reinterpret_cast<region *>(static_cast<char *>(m.address) + offset);
    if (!valid_region(*capture)) {
        fprintf(stderr, "xliostat: unsupported RX capture version or record layout\n");
        return 1;
    }
    mapping csv_target;
    std::ofstream csv;
    if (!csv_path.empty()) {
        // Open without truncation first. Comparing the open inode also handles
        // hard links/symlinks. Reopen this descriptor via procfs, never the
        // user-supplied path, so a rename cannot race the alias check.
        csv_target.fd = open(csv_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
        struct stat destination {};
        if (csv_target.fd < 0 || fstat(csv_target.fd, &destination) ||
            (destination.st_dev == info.st_dev && destination.st_ino == info.st_ino)) {
            fprintf(stderr,
                    "xliostat: CSV must be writable and distinct from the live statistics file\n");
            return 1;
        }
        csv.open("/proc/self/fd/" + std::to_string(csv_target.fd));
        if (!csv) {
            fprintf(stderr, "xliostat: cannot open CSV %s\n", csv_path.c_str());
            return 1;
        }
        csv_header(csv);
    }
    analyzer analysis;
    signals signal_guard;
    for (auto &s : capture->slots) {
        recover_reader(s);
        arm(s, s.control.load(std::memory_order_acquire), samples);
    }
    printf("xliostat: RX analysis samples for pid %d; up to %u records/ring every "
           "%ds\n",
           pid, samples, interval);
    printf(
        "Sizes describe RX completions; LRO aggregates do not reveal every "
        "wire segment. Disqualifiers are inferred from observed packets, not HW session state.\n");
    fflush(stdout);
    for (int cycle = 0; !capture_stopped && (!cycles || cycle < cycles); ++cycle) {
        struct timespec delay {
            interval, 0
        };
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR && !capture_stopped) {
        }
        if (capture_stopped) {
            break;
        }
        printf("\nBatch %d\n", cycle + 1);
        bool shown = false;
        for (unsigned i = 0; i < max_rings; ++i) {
            auto &s = capture->slots[i];
            batch b;
            if (reader_copy(s, b)) {
                print_batch(i, b, analysis, cycle + 1, csv.is_open() ? &csv : nullptr);
                shown = true;
            } else {
                auto token = s.control.load(std::memory_order_acquire);
                if (state(token) == phase::idle && arm(s, token, samples)) {
                    token = s.control.load(std::memory_order_acquire);
                }
                if (state(token) == phase::armed || state(token) == phase::filling) {
                    // Slot identity stays pinned until this request has been consumed.
                    auto n = s.progress.load(std::memory_order_acquire);
                    printf("Ring %u ifindex=%u: %s\n", i, s.if_index,
                           progress_text(state(token), n, target(token)).c_str());
                    shown = true;
                }
            }
            if (!cycles || cycle + 1 < cycles) {
                arm(s, s.control.load(std::memory_order_acquire), samples);
            }
        }
        if (!shown) {
            printf("No traffic (no active capture rings)\n");
        }
        auto failures = capture->registration_failures.load(std::memory_order_relaxed);
        if (failures) {
            printf("Capture coverage limited: %u ring registrations had no free "
                   "capture slot\n",
                   failures);
        }
        if (csv.is_open()) {
            csv.flush();
            if (!csv) {
                fprintf(stderr, "xliostat: CSV write failed\n");
                return 1;
            }
        }
        fflush(stdout);
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            printf("xliostat: target process exited\n");
            break;
        }
    }
    return 0;
}

const char *rx_analysis_help()
{
    return R"help(
RX analysis (--rx-analysis, optionally -C/--csv_file PATH):
  --rx-samples N sets a maximum of N packet completions per ring per batch,
  including excluded packets. Storage is fixed at 256 records per ring.
  An LRO aggregate is one completion, not a sample of every wire segment.
  Captures run only when requested. No traffic / Collecting samples describes
  an empty / partial batch; closing a ring publishes its partial batch.
  All sizes are bytes. Histograms group identical layouts and reasons:
    Count/Share: frequency / percentage of all records in that ring batch.
    RQ: STRQ (striding) or RQ (regular). IP: IP version.
    LRO: raw CQE segment count; 0=no session, 1=one-packet session, >1=aggregate.
    Prefix: bytes before Ethernet; Hdr: L2+IP+TCP lengths, excluding Prefix.
    L2/IP/TCP: individual header lengths, including tags/options/extensions.
    Frame: completed Ethernet frame size; Payload: aggregate TCP payload size.
    Offset: payload offset from the posted slot start, including Prefix.
    A%64/L%64: payload address / payload length modulo 64. Flags: raw TCP flags.
    lro_abrt: HW completion reason: 0:max-size, 1:timeout, 2:exception,
      3:undefined; '-' for LRO=0. A session's triggering packet is generally
      not part of the aggregate. This column is not a SW-inferred flush cause.
    lro disq: '-' for LRO>0, otherwise all identified observed disqualifiers,
      or 'unknown'. These are inferences from sampled packets and effective
      LRO settings, NOT HW session state or proof of the NIC's actual decision.
      'not validated' CQE bits do not prove a bad checksum. Resource exhaustion
      and unsampled packets cannot be diagnosed. Padding NOP/EOL is allowed.
    Excluded: packets without a safely interpretable complete TCP layout;
      separate histogram, included in the requested count and CSV.
    Data/control-only: TCP packets with/without payload. Alignment percentages
      use data packets only. Missing or unavailable values are '-'.
  CSV: one row per captured completion, including excluded records, in each
  ring's capture order. No global packet ordering across rings is implied.
    batch: display update number; ring-id/ring-generation/ifindex: RX identity.
    flow-id: small directional-flow ID retained across batches; tuple: interface,
      source/destination IP:port and VLAN context. Bounded to 4096 active IDs;
      an evicted tuple receives a new ID. These fields are calculated by xlio_stats.
    expected-seqno: previous observed sequence + aggregate payload + SYN + FIN,
      modulo 2^32, calculated by xlio_stats. '-' on the first flow packet in
      each batch, ring change, SYN, or after lost/malformed context. No inference
      spans sampling gaps. Observed FIN/RST ends continuity.
    sw-time-ns: CLOCK_MONOTONIC_RAW when SW processes the completion, before
      header repair; includes polling delay and is NOT wire-arrival time.
    Incomplete/incomplete: some requested header/metadata information was not recorded.
      IPv4 option / IPv6 extension bodies are omitted; only extension types
      are kept. Omitted application payload does not set this boolean.
    rq/headers-64: queue kind / active header-layout setting.
    frame-bytes/prefix-bytes/frame-address-mod64: actual RX buffer layout.
    l2-bytes/ip-bytes/tcp-bytes: decoded header sizes (ip-bytes means header).
    payload-bytes/payload-offset/payload-address-mod64/payload-length-mod64:
      decoded layout as in the histogram, using completion length for LRO>1.
    ethernet-header/ip-header/tcp-header/tcp-options/ipv6-extension-types:
      bounded raw bytes in hex, before XLIO repairs LRO headers. IP base header
      only; TCP includes up to 40 option bytes. No packet payload is recorded.
    ip-version/ip-dscp-ecn: version and combined DSCP+ECN byte.
    ipv4-total-length/ipv4-id/ipv4-frag/ipv4-checksum: raw IPv4 header fields;
      frag includes flags and fragment offset. ipv6-flow-label/ipv6-payload-length:
      raw IPv6 fields. ip-ttl-hop-limit / ip-protocol-next-header: corresponding
      raw base-IP fields. Source/destination addresses are also in tuple.
    src-port/dst-port/seqno/ackno: raw TCP fields; tcp-doff-reserved-ns is the
      raw byte containing data offset, reserved bits and NS. tcp-flags/window/
      checksum/urgent: raw TCP flags, advertised window, checksum and urgent pointer.
    cqe: raw 64-byte CQE in hex. cqe-* columns expose raw fields as unsigned
      numbers: pkt-info (packet info), lro-tcppsh-abort-dupack (packed LRO flags,
      abort and dupack), min-ttl (minimum TTL), tcp-window/ack-seq (LRO final values),
      rx-hash/rx-hash-type, csum (HW checksum), hds-ip-ext (validation bits),
      l4-hdr-type-etc (types/fragment/extension/VLAN flags), vlan-info (TCI),
      byte-count (raw, including STRQ encoding), timestamp (64-bit raw union:
      TCP timestamp values when LRO timestamp-valid is set, otherwise CQ clock),
      flow-table-metadata, sop-rxdrop-qpn-flowtag (packed metadata), wqe-counter,
      op-own (opcode/ownership). Interpretation depends on opcode and validity
      bits; zero in a raw union does not imply that every subfield is applicable.
    lro-enable-mask: effective TIR IPv4=1/IPv6=2; lro-min-mss: device minimum
      TCP payload; lro-psh-cap/lro-timestamp-cap: device support booleans;
      lro-max-size: configured size limit; lro-max-size-mode: 0=TCP header+data,
      1=whole frame; lro-timeout-us: TIR timeout. Unknown context is '-'.
)help";
}
