# Experimental receive header alignment

BF4 worktree: `/root/libxlio-shift-steer`, branch `shift-steer`, based on
`vr_vNext` at `8878f3690520175c89422813f0ed56cd983d5789`.

Enable the boolean `hardware_features.headers-64` (default `false`), or
`XLIO_HEADERS_64=1` with legacy configuration. Example:

```json
{
  "hardware_features": {
    "headers-64": true,
    "striding_rq": { "enable": true },
    "tcp": { "lro": "enable" }
  },
  "network": { "protocols": { "tcp": { "timestamps": "disable" } } }
}
```

Run with the paired libraries from this worktree:

```sh
XLIO_USE_NEW_CONFIG=1 XLIO_CONFIG_FILE=/path/to/headers-64.json \
LD_LIBRARY_PATH=/root/libxlio-shift-steer/dpcp-install/lib \
LD_PRELOAD=/root/libxlio-shift-steer/install/lib/libxlio.so your-application
```

## Hardware and software behavior

For every XLIO receive steering rule, the original matching criteria and priority
are retained. Its destination becomes a private NIC RX flow table containing one
match-all FTE. That FTE inserts `88a8:0000 / 8100:0000` immediately after the two
MAC addresses, reparses the packet, preserves the socket flow tag, and forwards to
the original TIR/RQ. These VLAN tags are inserted on receive; the sender and packets
on the wire are unchanged. The insertion uses the existing DPCP INSERT_HDR action.

DPCP sets `WQ.two_byte_shift_en=1` for striding RQs. Hardware writes two zero bytes
before the Ethernet frame. On this BF4, the striding CQE byte count includes those
two bytes. XLIO subtracts them from the descriptor length/capacity and advances
its packet pointer, while keeping parent WQE accounting and refcounts in full
hardware strides. No payload data is copied or moved.

For an originally untagged packet without IP/TCP options:

```text
stride base + 0   two zero bytes
stride base + 2   Ethernet MACs (12 bytes)
stride base + 14  synthetic S-tag and C-tag (8 bytes)
stride base + 22  original EtherType (2 bytes)
stride base + 24  IPv4 header (20 bytes)
stride base + 44  TCP header (20 bytes)
stride base + 64  TCP payload
```

The shared receive parser validates and skips exactly the two synthetic tags.
It retains the existing handling of a real customer VLAN beneath them. The same
helper is used by LRO header repair, CQ drain classification, flow-tag dispatch,
and ordinary receive dispatch. LRO IP-length repair uses the normalized descriptor
length, excluding the two-byte prefix and the CQE stride-count bits.

### Prototype boundary requested for this branch

The private DPCP patch **always enables the two-byte prefix for striding RQs**.
Accordingly, XLIO always removes that prefix, including when `headers-64=false`.
The boolean currently gates VLAN insertion and interpretation. Gating the hardware
shift itself on this boolean is deferred to productization. Do not mix this XLIO
with an unpatched DPCP, or this DPCP with an XLIO that does not normalize the prefix.
Regular RQs are unchanged with the boolean false; true with regular RQ is rejected.

The 64-byte calculation assumes no original VLAN, IPv4 options or TCP options.
IPv6 and additional real VLAN headers change the payload offset. Aligned later
LRO appends also require the preceding TCP payload lengths to be multiples of 64;
this knob does not modify MSS, MTU or the sender's segmentation. TCP timestamp
negotiation should be disabled for the ordinary 20-byte TCP layout.

This prototype creates an additional flow table, group, FTE and reformat context
per root receive rule. It is intended for the alignment experiment; rule-scale
and performance effects have not been characterized.

## DPCP dependency and reproducible build

Private dependency: `submodules/libdpcp`, based on
`4cc43b3047367383d3eb8d9c63e8637dfcea5d70`, branch `shift-steer`.
This XLIO revision does not track or populate that directory through autogen.
Its changes are preserved as patches under `contrib/patches/`:

- `dpcp-two-byte-shift.patch`: the exact unconditional `rq.cpp` shift change from
  `/root/libxlio-two-byte-shift`.
- `dpcp-forward-table.patch`: allow the established legacy receive matcher to
  forward to a private table. This retains IPv6 matching rather than converting
  to the newer IPv4-only `match_params_ex` interface.

```sh
cd /root/libxlio-shift-steer
./autogen.sh
# Only when preparing a fresh dependency checkout:
# mkdir -p submodules
# git clone --no-hardlinks /root/libxlio-vr-vNext/submodules/libdpcp submodules/libdpcp
# git -C submodules/libdpcp checkout 4cc43b3047367383d3eb8d9c63e8637dfcea5d70
# git -C submodules/libdpcp apply ../../contrib/patches/dpcp-two-byte-shift.patch
# git -C submodules/libdpcp apply ../../contrib/patches/dpcp-forward-table.patch
cd submodules/libdpcp
./autogen.sh
./configure --prefix=/root/libxlio-shift-steer/dpcp-install --enable-shared --enable-static
make -j8
make install
cd ../..
./configure --prefix=/root/libxlio-shift-steer/install \
    --enable-shared --disable-static \
    --with-dpcp=/root/libxlio-shift-steer/dpcp-install
make -j8
make install
make -C tests/unit_tests -j8
tests/unit_tests/unit_tests
```

### Static XLIO and xlio_perf

The in-source build is now configured for static XLIO, installed under
`/root/libxlio-shift-steer/install-static`. The earlier shared-library installation
under `install/` is preserved. This revision rejects simultaneous shared/static
XLIO builds; clean the build products when changing between them.

The standard `/root/xlio_tools` source at
`0ab62155aace9374534d2bdfa6db0f3be3b2910e` has a separate build directory,
`/root/xlio_tools/build-shift-steer`. Reproduce with:

```sh
cd /root/libxlio-shift-steer
make clean
./configure --prefix=/root/libxlio-shift-steer/install-static \
    --enable-static --disable-shared \
    --with-dpcp=/root/libxlio-shift-steer/dpcp-install
make -j8
make install
meson setup /root/xlio_tools/build-shift-steer /root/xlio_tools \
    -Dtests=false \
    -Dxlio_include_dir=/root/libxlio-shift-steer/install-static/include/mellanox \
    -Dxlio_lib_dir=/root/libxlio-shift-steer/install-static/lib \
    -Ddpcp_lib_dir=/root/libxlio-shift-steer/dpcp-install/lib \
    -Drdma_lib_dir=/usr/lib/aarch64-linux-gnu
ninja -C /root/xlio_tools/build-shift-steer -j8
```

For an existing Meson build directory, use `meson setup --reconfigure`.
The executable is `/root/xlio_tools/build-shift-steer/xlio_perf`. It statically
links XLIO and dynamically links the private DPCP, resolved through its build
RUNPATH. No `LD_PRELOAD` is needed. The build manifest, linkage verification and
CLI-help check are in `validation/static-perf-manifest.json`, `perf-elf.txt`,
`perf-link-command.txt` and `perf-help.log`. No performance workload was run for
this build.

Regenerate config artifacts after schema edits:
`python3 src/core/config/generate_mappings.py` and `python3 generate_docs.py`.

## Invariant review

| Observer | Contract after this change |
|---|---|
| RQ posting and memory ownership | Original WQE address and registered extent remain unchanged. |
| Stride progression and reclamation | Full consumed stride count and parent references remain unchanged. |
| Fillers and error CQEs | Never remove prefix or interpret LRO headers. |
| Ethernet/IP/transport parsing | Packet pointer excludes prefix; parser skips exactly two synthetic tags when enabled. |
| Fast flow-tag and ordinary receive dispatch | Use the same L2 offset; original customer VLAN validation remains. |
| Hardware LRO completion repair | Uses normalized length and actual L2 length, not raw CQE byte count. |
| User receive / zero-copy pointers | Point at original received data; payload is not moved. |
| Flow match and priorities | Legacy matcher remains responsible for all original fields, including IPv6. |
| Flow creation failure | Root redirect is installed only after insertion table/FTE creation succeeds. |
| Flow teardown | Root rule dies before destination table, its FTE/group, and finally reformat actions. |
| TIR lifetime | Original TIR ownership remains with the RX queue, as for the original steering rule. |
| Disabled boolean | No synthetic VLAN insertion; private DPCP still shifts STRQ and parser compensates. |
| Regular RQ | Original layout when false; incompatible true setting rejected. |

See `validation/README.md` for measured validation and its limits.
