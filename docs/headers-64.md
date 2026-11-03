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
export XLIO_USE_NEW_CONFIG=1
export XLIO_CONFIG_FILE=/path/to/headers-64.json
# Run an application linked with the paired libraries described below.
```

## Hardware and software behavior

For every XLIO receive steering rule, the original matching criteria and priority
are retained. Its destination becomes a private NIC RX flow table with two FTEs:

| Incoming frame | Match | Bytes inserted after the MAC addresses |
|---|---|---|
| Untagged | `cvlan_tag=0, svlan_tag=0` | `88a8:0000 / 8100:0000` (8 bytes) |
| One 802.1Q tag | `cvlan_tag=1, svlan_tag=0` | `88a8:0000` (4 bytes) |

The rules match tag presence independently of VID, including priority tags with
VID 0. The original customer tag is not rewritten: VID, PCP and DEI are preserved.
Each FTE reparses the packet, preserves the socket flow tag and forwards to the
original TIR/RQ. Both supported input layouts reach the TIR with exactly two tags.
Insertion happens on receive; the sender and packets on the wire are unchanged.
DPCP must expose independent `cvlan_tag`/`svlan_tag` masks and values in its
extended matcher. Rebuild XLIO against the matching DPCP headers and library.

DPCP sets `WQ.two_byte_shift_en=1` for striding RQs. Hardware writes two zero bytes
before the Ethernet frame. On this BF4, the striding CQE byte count includes those
two bytes. XLIO subtracts them from the descriptor length/capacity and advances
its packet pointer, while keeping parent WQE accounting and refcounts in full
hardware strides. No payload data is copied or moved.

For an untagged or single-802.1Q packet without IP/TCP options:

```text
stride base + 0   two zero bytes
stride base + 2   Ethernet MACs (12 bytes)
stride base + 14  synthetic S-tag + original or synthetic C-tag (8 bytes)
stride base + 22  original EtherType (2 bytes)
stride base + 24  IPv4 header (20 bytes)
stride base + 44  TCP header (20 bytes)
stride base + 64  TCP payload
```

The shared receive parser validates and skips the synthetic S-tag, then parses
the inner C-tag normally. A synthetic C-tag has VID 0; an original C-tag retains
its VLAN semantics. Additional tags are rejected in this mode. The same
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

The 64-byte calculation supports untagged and single-802.1Q inputs, with no IPv4
or TCP options. IPv6 and IP/TCP options change the payload offset. Incoming QinQ
and service-tagged frames are outside the supported input layouts. Aligned later
LRO appends also require the preceding TCP payload lengths to be multiples of 64;
this knob does not modify MSS, MTU or the sender's segmentation. TCP timestamp
negotiation should be disabled for the ordinary 20-byte TCP layout.

This prototype creates an additional flow table, group, two FTEs and two reformat
contexts per root receive rule. It is intended for the alignment experiment; rule-scale
and performance effects have not been characterized.

## DPCP dependency and reproducible build

The paired dependency is `/root/libdpcp-shift-steer`, branch `two-byte-shift`.
It contains the two-byte receive shift, legacy flow-rule table destinations, and
independent VLAN-presence matching in `match_params_lyr_2`. The old two patches
under `contrib/patches/` do not include the VLAN-presence API; applying only those
patches is insufficient for this version of XLIO.

The VLAN-presence fields change DPCP's public structure layout. Rebuild consumers
against the updated headers and library together. Do not run an older XLIO or
xlio_perf binary against this updated private DPCP library.

Build on the BF4 local disk, not the shared workspace:

```sh
cd /root/libdpcp-shift-steer
# Run ./autogen.sh first only for an unconfigured checkout.
./configure --prefix=/root/libdpcp-shift-steer/install --enable-shared --enable-static
make -j8
make -C tests/gtest -j8
tests/gtest/gtest --gtest_filter='dpcp_flow_matcher.*'
make install

cd /root/libxlio-shift-steer
# Run ./autogen.sh first only for an unconfigured checkout.
./configure --prefix=/root/libxlio-shift-steer/install-static \
    --enable-static --disable-shared \
    --with-dpcp=/root/libdpcp-shift-steer/install
make -j8
make -C tests/unit_tests -j8
tests/unit_tests/unit_tests
make install
```

This XLIO build supports either static or shared libraries, not both in the same
build. If switching build types, clean the build products first. The active
benchmark build is `/root/xlio_tools/build-rx-layout`, linked to this static XLIO:

```sh
meson setup --reconfigure /root/xlio_tools/build-rx-layout /root/xlio_tools \
    -Dtests=false \
    -Dxlio_include_dir=/root/libxlio-shift-steer/install-static/include/mellanox \
    -Dxlio_lib_dir=/root/libxlio-shift-steer/install-static/lib \
    -Ddpcp_lib_dir=/root/libdpcp-shift-steer/install/lib \
    -Drdma_lib_dir=/usr/lib/aarch64-linux-gnu
ninja -C /root/xlio_tools/build-rx-layout -j8
```

Omit `--reconfigure` when creating the Meson build directory for the first time.
The executable is `/root/xlio_tools/build-rx-layout/xlio_perf`. It statically links
XLIO and dynamically links `/root/libdpcp-shift-steer/install/lib/libdpcp.so`
through its RUNPATH. It does not require LD_PRELOAD.

Regenerate config artifacts after schema edits:
`python3 src/core/config/generate_mappings.py` and `python3 generate_docs.py`.

## Invariant review

| Observer | Contract after this change |
|---|---|
| RQ posting and memory ownership | Original WQE address and registered extent remain unchanged. |
| Stride progression and reclamation | Full consumed stride count and parent references remain unchanged. |
| Fillers and error CQEs | Never remove prefix or interpret LRO headers. |
| Ethernet/IP/transport parsing | Packet pointer excludes prefix; parser skips the synthetic S-tag and retains the inner C-tag VLAN ID. |
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
