#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Privileged kernel smoke for Network Fabric v3.
# Covers: TC attach, fail-closed policy, IPv4/IPv6 CIDRs, L4 policy,
# fixed-window PPS limiting, flow/stats maps, IPv4/IPv6 XDP blocking, Set 6S/
# 13 exact Pod-scoped identity/port policy, and Set 14's unified fluxvm_prules
# rich CIDR+L4 tuple rules (including SCTP) enforced both by the main
# fluxvm_egress program and by the separate fluxvm_pod_ingress.bpf.o object
# loaded with shared pinned maps.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (sudo -E $0)" >&2
  exit 2
fi

ulimit -l unlimited 2>/dev/null || true
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJ_DIR="${1:-$ROOT/dist/bpf}"
TC_OBJ="$OBJ_DIR/fluxvm_tc.bpf.o"
XDP_OBJ="$OBJ_DIR/fluxvm_xdp.bpf.o"
POD_ING_OBJ="$OBJ_DIR/fluxvm_pod_ingress.bpf.o"

for cmd in bpftool tc ip python3 ping mount; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[[ -f "$TC_OBJ" ]] || { echo "missing $TC_OBJ" >&2; exit 2; }
[[ -f "$XDP_OBJ" ]] || { echo "missing $XDP_OBJ" >&2; exit 2; }
[[ -f "$POD_ING_OBJ" ]] || { echo "missing $POD_ING_OBJ" >&2; exit 2; }

SUFFIX="$$"
A="fvmta${SUFFIX}"; A="${A:0:15}"
B="fvmtb${SUFFIX}"; B="${B:0:15}"
NSA="fvm-a-${SUFFIX}"
NSB="fvm-b-${SUFFIX}"
BPFFS="/run/fluxvm-smoke-${SUFFIX}"
PIN="$BPFFS/pins"
TC_PREF=49152
IDENTITY=42
A4="10.77.0.1"
B4="10.77.0.2"
A6="2001:db8:77::1"
B6="2001:db8:77::2"

cleanup() {
  ip netns exec "$NSA" ip link set dev "$A" xdp off 2>/dev/null || true
  ip netns exec "$NSA" tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf 2>/dev/null || true
  ip netns exec "$NSA" tc qdisc del dev "$A" clsact 2>/dev/null || true
  ip netns del "$NSA" 2>/dev/null || true
  ip netns del "$NSB" 2>/dev/null || true
  rm -rf "$BPFFS" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add "$NSA"
ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip netns exec "$NSA" ip addr add "$A4/24" dev "$A"
ip netns exec "$NSB" ip addr add "$B4/24" dev "$B"
ip netns exec "$NSA" ip -6 addr add "$A6/64" dev "$A"
ip netns exec "$NSB" ip -6 addr add "$B6/64" dev "$B"
ip netns exec "$NSA" ip link set lo up
ip netns exec "$NSB" ip link set lo up
ip netns exec "$NSA" ip link set "$A" up
ip netns exec "$NSB" ip link set "$B" up

# IPv6 DAD needs a moment before the first ping succeeds.
sleep 2

ip netns exec "$NSB" ping -q -c 1 -W 2 "$A4" >/dev/null
ip netns exec "$NSB" ping -6 -q -c 1 -W 2 "$A6" >/dev/null

# Keep bpffs and all pinned objects in one netns session. Some CI hosts
# remount /sys on every `ip netns exec`, so separate invocations lose mounts.
ip netns exec "$NSA" env \
  TC_OBJ="$TC_OBJ" XDP_OBJ="$XDP_OBJ" POD_ING_OBJ="$POD_ING_OBJ" A="$A" NSB="$NSB" \
  A4="$A4" B4="$B4" A6="$A6" B6="$B6" PIN="$PIN" BPFFS="$BPFFS" \
  TC_PREF="$TC_PREF" IDENTITY="$IDENTITY" \
  bash -euo pipefail <<'INNER'
hex_u32() {
  python3 - "$1" <<'PY'
import struct, sys
print(" ".join(f"{b:02x}" for b in struct.pack("=I", int(sys.argv[1]))))
PY
}

iface_value() {
  # 6*u32 + 2*u64 + 2*u32, matching struct iface_config in bpf/fluxvm_tc.bpf.c:
  # identity, default_allow, enforce_cidr, enforce_l4, sample_rate, allow_icmp,
  # rate_bytes_per_sec, rate_packets_per_sec, pod_id, reserved0 (Set 6S).
  # Args: identity default_allow enforce_cidr enforce_l4 sample rate_bytes rate_pps
  #       [allow_icmp=0] [pod_id=0]
  python3 - "$@" <<'PY'
import struct, sys
vals = [int(x) for x in sys.argv[1:]]
identity, default_allow, enforce_cidr, enforce_l4, sample, rate_bytes, rate_pps = vals[:7]
allow_icmp = vals[7] if len(vals) > 7 else 0
pod_id = vals[8] if len(vals) > 8 else 0
raw = struct.pack(
    "=IIIIIIQQII",
    identity,
    default_allow,
    enforce_cidr,
    enforce_l4,
    sample,
    allow_icmp,
    rate_bytes,
    rate_pps,
    pod_id,
    0,
)
print(" ".join(f"{b:02x}" for b in raw))
PY
}

pod4_key() {
  python3 - "$1" "$2" <<'PY'
import ipaddress, struct, sys
pod_id, ip = int(sys.argv[1]), sys.argv[2]
raw = struct.pack("=I", pod_id) + ipaddress.IPv4Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

pod4_port_key() {
  # Matches struct fluxvm_pid4_port_key in bpf/fluxvm_pod_policy.bpf.h:
  # pod_id, address, protocol, one pad byte, port (host order). Set 13.
  # Args: pod_id ip protocol port
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import ipaddress, struct, sys
pod_id, ip, protocol, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
raw = struct.pack("=I", pod_id) + ipaddress.IPv4Address(ip).packed + struct.pack("=BBH", protocol, 0, port)
print(" ".join(f"{b:02x}" for b in raw))
PY
}

pod_policy_value() {
  # Matches struct fluxvm_pod_policy in bpf/fluxvm_pod_policy.bpf.h: flags
  # (u32), reserved0 (u32, Set 14 rich-rule count), reserved1 (u32, Set 14
  # wire schema version), reserved2 (u32, still spare). Args: flags
  # [rule_count=0] [schema_version=0]
  python3 - "$@" <<'PY'
import struct, sys
flags = int(sys.argv[1])
rule_count = int(sys.argv[2]) if len(sys.argv) > 2 else 0
schema_version = int(sys.argv[3]) if len(sys.argv) > 3 else 0
print(" ".join(f"{b:02x}" for b in struct.pack("=IIII", flags, rule_count, schema_version, 0)))
PY
}

pod_rule_value() {
  # Matches struct fluxvm_pod_rule in bpf/fluxvm_pod_policy.bpf.h: pod_id
  # (u32), direction/family/protocol/prefix_len (u8 each), port_start/
  # port_end (u16 each), address[16]. 28 bytes total, no padding (every
  # field already falls on its natural alignment). Args: pod_id direction
  # family protocol prefix_len port_start port_end address
  python3 - "$@" <<'PY'
import ipaddress, struct, sys
pod_id, direction, family, protocol, prefix_len, port_start, port_end, addr = sys.argv[1:9]
pod_id, direction, family = int(pod_id), int(direction), int(family)
protocol, prefix_len = int(protocol), int(prefix_len)
port_start, port_end = int(port_start), int(port_end)
if family == 4:
    raw_addr = ipaddress.IPv4Address(addr).packed + b"\x00" * 12
else:
    raw_addr = ipaddress.IPv6Address(addr).packed
raw = struct.pack("=IBBBBHH", pod_id, direction, family, protocol, prefix_len, port_start, port_end) + raw_addr
assert len(raw) == 28, len(raw)
print(" ".join(f"{b:02x}" for b in raw))
PY
}

flush_ct() {
  # Learned CT entries bypass deny/rate after an allow; clear between flips.
  local pin="$PIN/tc/maps/fluxvm_ct"
  [[ -e "$pin" ]] || return 0
  python3 - "$pin" <<'PY'
import json, subprocess, sys
pin = sys.argv[1]
try:
    data = json.loads(
        subprocess.check_output(["bpftool", "-j", "map", "dump", "pinned", pin], text=True)
    )
except Exception:
    sys.exit(0)
if not isinstance(data, list):
    sys.exit(0)
for ent in data:
    key = ent.get("key")
    if not key:
        continue
    if isinstance(key, dict):
        # rare alternate encoding
        continue
    hex_bytes = []
    for b in key:
        if isinstance(b, str):
            hex_bytes.append(b.removeprefix("0x").zfill(2))
        else:
            hex_bytes.append(f"{int(b):02x}")
    subprocess.run(
        ["bpftool", "map", "delete", "pinned", pin, "key", "hex", *hex_bytes],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
PY
}

lpm4_key() {
  python3 - "$1" "$2" "$3" <<'PY'
import ipaddress, struct, sys
prefix, identity, ip = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
raw = struct.pack("=II", prefix, identity) + ipaddress.IPv4Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

lpm6_key() {
  python3 - "$1" "$2" "$3" <<'PY'
import ipaddress, struct, sys
prefix, identity, ip = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
raw = struct.pack("=II", prefix, identity) + ipaddress.IPv6Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

l4_key() {
  python3 - "$1" "$2" "$3" <<'PY'
import struct, sys
identity, port, proto = map(int, sys.argv[1:])
raw = struct.pack("=IHBB", identity, port, proto, 0)
print(" ".join(f"{b:02x}" for b in raw))
PY
}

xdp4_key() {
  python3 - "$1" "$2" <<'PY'
import ipaddress, struct, sys
prefix, ip = int(sys.argv[1]), sys.argv[2]
raw = struct.pack("=I", prefix) + ipaddress.IPv4Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

xdp6_key() {
  python3 - "$1" "$2" <<'PY'
import ipaddress, struct, sys
prefix, ip = int(sys.argv[1]), sys.argv[2]
raw = struct.pack("=I", prefix) + ipaddress.IPv6Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

expect_ping4() { ip netns exec "$NSB" ping -q -c 1 -W 2 "$A4" >/dev/null; }
expect_no_ping4() {
  flush_ct
  if ip netns exec "$NSB" ping -q -c 1 -W 1 "$A4" >/dev/null; then
    echo "expected IPv4 ping to be blocked" >&2; exit 1
  fi
}
expect_ping6() { ip netns exec "$NSB" ping -6 -q -c 1 -W 2 "$A6" >/dev/null; }
expect_no_ping6() {
  flush_ct
  if ip netns exec "$NSB" ping -6 -q -c 1 -W 1 "$A6" >/dev/null; then
    echo "expected IPv6 ping to be blocked" >&2; exit 1
  fi
}

mkdir -p "$BPFFS"
mount -t bpf bpf "$BPFFS"
mkdir -p "$PIN/tc/progs" "$PIN/tc/maps" "$PIN/xdp/progs" "$PIN/xdp/maps"

# fluxvm_tc.bpf.o carries exactly one SEC("tc") program again under Set 14
# -- the separate Pod-ingress object (fluxvm_pod_ingress.bpf.o) is loaded
# on demand later in this script, sharing this object's pinned maps, the
# same way crates/fluxvm-network/src/ebpf.rs's sync_pod_ingress_attachment
# does for a real VM.
bpftool prog load "$TC_OBJ" "$PIN/tc/progs/fluxvm_egress" \
  type classifier pinmaps "$PIN/tc/maps"
IFINDEX="$(cat "/sys/class/net/$A/ifindex")"
IFKEY="$(hex_u32 "$IFINDEX")"
ONE="$(hex_u32 1)"

# v3 configures maps before attach. Missing interface config is fail-closed.
ALLOW_VALUE="$(iface_value "$IDENTITY" 1 0 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $ALLOW_VALUE

tc qdisc add dev "$A" clsact
tc filter add dev "$A" ingress pref "$TC_PREF" handle 1 bpf da \
  pinned "$PIN/tc/progs/fluxvm_egress"
tc filter show dev "$A" ingress pref "$TC_PREF" | grep -q 'bpf'
expect_ping4
expect_ping6

# Default deny applies to both families (ARP/NDP bootstrap remains allowed).
DENY_VALUE="$(iface_value "$IDENTITY" 0 0 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $DENY_VALUE
expect_no_ping4
expect_no_ping6

# IPv4 /32 allow: IPv4 succeeds; IPv6 remains denied because CIDR policy is global.
CIDR_VALUE="$(iface_value "$IDENTITY" 0 1 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $CIDR_VALUE
V4KEY="$(lpm4_key 64 "$IDENTITY" "$A4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_v4" key hex $V4KEY value hex $ONE
expect_ping4
expect_no_ping6
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_v4" key hex $V4KEY

# IPv6 /128 allow: IPv6 succeeds; IPv4 remains denied.
V6KEY="$(lpm6_key 160 "$IDENTITY" "$A6")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_v6" key hex $V6KEY value hex $ONE
expect_ping6
expect_no_ping4
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_v6" key hex $V6KEY

# L4 allowlist: both ports are really listening; only tcp/18080 may enter.
python3 - <<'PY' &
import socket, threading, time

def serve(port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.77.0.1", port)); s.listen(8); s.settimeout(0.25)
    until=time.time()+8
    while time.time()<until:
        try:
            c,_=s.accept(); c.close()
        except socket.timeout:
            pass
    s.close()
for p in (18080,18081): threading.Thread(target=serve,args=(p,),daemon=True).start()
time.sleep(8)
PY
SERVER_PID=$!
sleep 0.4
L4_VALUE="$(iface_value "$IDENTITY" 0 0 1 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $L4_VALUE
L4KEY="$(l4_key "$IDENTITY" 18080 6)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_l4" key hex $L4KEY value hex $ONE
ip netns exec "$NSB" python3 - <<'PY'
import socket
s=socket.create_connection(("10.77.0.1",18080),1); s.close()
PY
if ip netns exec "$NSB" python3 - <<'PY'
import socket
s=socket.create_connection(("10.77.0.1",18081),1); s.close()
PY
then
  echo "expected tcp/18081 to be blocked by L4 policy" >&2
  exit 1
fi
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_l4" key hex $L4KEY

# PPS limiter: first packet in the window passes, an immediate second packet drops,
# and traffic resumes after a new one-second window.
RATE_VALUE="$(iface_value "$IDENTITY" 1 0 0 0 0 1)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $RATE_VALUE
expect_ping4
expect_no_ping4
sleep 1.1
expect_ping4

bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_stats" | grep -q 'key'
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_flows" | grep -q 'key'

tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf

# XDP IPv4 + IPv6 source-CIDR guard.
bpftool prog load "$XDP_OBJ" "$PIN/xdp/progs/fluxvm_xdp_guard" \
  type xdp pinmaps "$PIN/xdp/maps"
BLOCK4="$(xdp4_key 32 "$B4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/xdp/maps/fvm_xdp_block4" key hex $BLOCK4 value hex $ONE
ip link set dev "$A" xdp pinned "$PIN/xdp/progs/fluxvm_xdp_guard"
expect_no_ping4
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/xdp/maps/fvm_xdp_block4" key hex $BLOCK4
expect_ping4

BLOCK6="$(xdp6_key 128 "$B6")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/xdp/maps/fvm_xdp_block6" key hex $BLOCK6 value hex $ONE
expect_no_ping6
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/xdp/maps/fvm_xdp_block6" key hex $BLOCK6
expect_ping6
ip link set dev "$A" xdp off

# Set 6S: Pod-scoped identity policy, additive on top of an otherwise-allowed
# VM-level verdict. pod_id=0 (every prior section above) must have exercised
# zero pod-policy behavior; this section is the first to set pod_id nonzero.
tc filter add dev "$A" ingress pref "$TC_PREF" handle 1 bpf da \
  pinned "$PIN/tc/progs/fluxvm_egress"
POD_ID=777
POD_ALLOW_BASELINE="$(iface_value "$IDENTITY" 1 0 0 0 0 0 0 "$POD_ID")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $POD_ALLOW_BASELINE
expect_ping4
FLUXVM_PSPOL_ENABLED=1
FLUXVM_PSPOL_DEFAULT_DENY=2
POD_POLICY_KEY="$(hex_u32 "$POD_ID")"
POD_POLICY_VALUE="$(pod_policy_value $((FLUXVM_PSPOL_ENABLED | FLUXVM_PSPOL_DEFAULT_DENY)))"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY value hex $POD_POLICY_VALUE
expect_no_ping4
PODKEY4="$(pod4_key "$POD_ID" "$A4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pid4" key hex $PODKEY4 value hex $ONE
expect_ping4
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_ppstat" | grep -q 'key'
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_pid4" key hex $PODKEY4

# Set 13: with the address-wide fluxvm_pid4 entry gone, a peer with no
# port-scoped fluxvm_pid4_port entry still falls through to default_deny.
expect_no_ping4
# ICMP has no real port, but parse_ports4 defaults sport/dport to 0 for any
# non-TCP/UDP protocol, so IPPROTO_ICMP(1)/port(0) is exactly the tuple this
# ping's own packets present to fluxvm_pod_policy_verdict4 -- a wrong port
# here (9999) must still miss and fall through to deny.
WRONGPORT4="$(pod4_port_key "$POD_ID" "$A4" 1 9999)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pid4_port" key hex $WRONGPORT4 value hex $ONE
expect_no_ping4
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_pid4_port" key hex $WRONGPORT4
PORTKEY4="$(pod4_port_key "$POD_ID" "$A4" 1 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pid4_port" key hex $PORTKEY4 value hex $ONE
expect_ping4
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_pid4_port" key hex $PORTKEY4
expect_no_ping4

# ---- Set 14: unified fluxvm_prules rich directional CIDR+L4 tuple rules ----
FLUXVM_PSPOL_RICH_RULES=8
FLUXVM_PSPOL_EGRESS_ISOLATED=16
FLUXVM_PSPOL_INGRESS_ISOLATED=32
SCHEMA_V2=2
RULE_SLOT="$(hex_u32 0)"

# Egress, CIDR-only rule (protocol=any): an isolated Pod with zero rules
# denies everything (Kubernetes semantics for an egress-isolating policy
# with no matching allow rule); a /24 rule covering $A4 then allows the
# ICMP ping through the real fluxvm_prules scan, not an approximation.
RICH_EGRESS_FLAGS=$((FLUXVM_PSPOL_ENABLED | FLUXVM_PSPOL_RICH_RULES | FLUXVM_PSPOL_EGRESS_ISOLATED))
RICH_EMPTY="$(pod_policy_value "$RICH_EGRESS_FLAGS" 0 "$SCHEMA_V2")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY value hex $RICH_EMPTY
expect_no_ping4
CIDR_RULE="$(pod_rule_value "$POD_ID" 1 4 0 24 0 0 "$A4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_prules" key hex $RULE_SLOT value hex $CIDR_RULE
RICH_ONE="$(pod_policy_value "$RICH_EGRESS_FLAGS" 1 "$SCHEMA_V2")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY value hex $RICH_ONE
expect_ping4
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_ppstat" | grep -q 'key'

# Protocol+port scoping at the same rule slot: narrowing the rule to
# tcp/18080 leaves both ICMP and tcp/18081 denied while tcp/18080 is
# allowed -- proves the tuple's protocol and port fields are enforced, not
# just the CIDR.
python3 - <<'PY' &
import socket, threading, time

def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.77.0.1", port)); s.listen(8); s.settimeout(0.25)
    until = time.time() + 8
    while time.time() < until:
        try:
            c, _ = s.accept(); c.close()
        except socket.timeout:
            pass
    s.close()
for p in (18080, 18081):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
time.sleep(8)
PY
SERVER_PID=$!
sleep 0.4
TCP_RULE="$(pod_rule_value "$POD_ID" 1 4 6 32 18080 18080 "$A4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_prules" key hex $RULE_SLOT value hex $TCP_RULE
expect_no_ping4
ip netns exec "$NSB" python3 - <<'PY'
import socket
s = socket.create_connection(("10.77.0.1", 18080), 1); s.close()
PY
if ip netns exec "$NSB" python3 - <<'PY'
import socket
s = socket.create_connection(("10.77.0.1", 18081), 1); s.close()
PY
then
  echo "expected tcp/18081 to be blocked by the Set 14 rich rule" >&2
  exit 1
fi
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# SCTP: a raw minimal SCTP common header (source/dest port only, no real
# association) proves fluxvm_tc.bpf.c's IPPROTO_SCTP parse_ports4 branch
# extracts ports correctly and that the rich rule's protocol field actually
# discriminates SCTP from TCP, not just "any L4". A raw AF_INET/SOCK_RAW
# listener bound to that protocol number receives a copy of any
# locally-delivered packet with it regardless of whether the host has a
# real SCTP association -- it only sees the packet at all if the TC
# program let it through first.
SCTP_PROTO=132
SCTP_PORT=19090
SCTP_RESULT="/tmp/fluxvm-smoke-sctp-result-$$"
send_sctp() {
  ip netns exec "$NSB" python3 - "$1" "$SCTP_PROTO" "$SCTP_PORT" <<'PY'
import socket, struct, sys
dst, proto, port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
# Full 12-byte SCTP common header (source, dest, verification tag,
# checksum) -- Set 16 extends bpf/fluxvm_tc.bpf.c's fluxvm_sctphdr_min to
# this same size (needed for its vtag==0 anti-replay check), so
# parse_ports4's bounds check now requires all 12 bytes present, not just
# the 4-byte port pair this test used to send. vtag=0 mimics a genuine
# SCTP INIT chunk; checksum is left zero since nothing inspects it.
payload = struct.pack("!HHII", 44444, port, 0, 0) + b"\xde\xad\xbe\xef"
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
s.sendto(payload, (dst, 0))
PY
}
sctp_probe() {
  local expect="$1"
  : > "$SCTP_RESULT"
  python3 - "$SCTP_PROTO" > "$SCTP_RESULT" <<'PY' &
import socket, sys
proto = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
s.settimeout(2)
try:
    data, _ = s.recvfrom(4096)
    # A raw IPPROTO socket's recvfrom always includes the IP header (see
    # raw(7)) -- skip past it (IHL is the low nibble of the first byte,
    # in 4-byte words) before checking our marker, which sits right after
    # the full 12-byte SCTP common header we sent as the payload.
    ihl = (data[0] & 0x0f) * 4
    marker = data[ihl + 12:ihl + 16]
    print("received" if marker == b"\xde\xad\xbe\xef" else "other")
except socket.timeout:
    print("timeout")
PY
  local pid=$!
  sleep 0.3
  send_sctp "$A4"
  wait "$pid" 2>/dev/null || true
  local got
  got="$(cat "$SCTP_RESULT")"
  if [[ "$expect" == "allow" && "$got" != "received" ]]; then
    echo "expected SCTP packet to be allowed by the Set 14 SCTP rule (got: $got)" >&2
    exit 1
  fi
  if [[ "$expect" == "deny" && "$got" == "received" ]]; then
    echo "expected SCTP packet to be blocked before an SCTP rule exists" >&2
    exit 1
  fi
}
sctp_probe deny
SCTP_RULE="$(pod_rule_value "$POD_ID" 1 4 "$SCTP_PROTO" 32 "$SCTP_PORT" "$SCTP_PORT" "$A4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_prules" key hex $RULE_SLOT value hex $SCTP_RULE
sctp_probe allow

# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_prules" key hex $RULE_SLOT
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY
tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf

# ---- Set 14: separate fluxvm_pod_ingress.bpf.o object, shared pinned maps ----
# Loaded on demand (as crates/fluxvm-network/src/ebpf.rs's
# sync_pod_ingress_attachment does for a real VM), binding its map
# references by name to this object's already-pinned maps rather than
# introducing a second, independent set of Pod policy maps. Traffic leaving
# $A back toward $NSB -- for an ICMP round trip, the echo *reply* $A's
# kernel generates in response to $NSB's request -- is what this program
# inspects; blocking that reply fails the same expect_ping4/expect_no_ping4
# helpers already used above.
bpftool prog load "$POD_ING_OBJ" "$PIN/tc/progs/fluxvm_pod_ingress" type classifier \
  map name fluxvm_id pinned "$PIN/tc/maps/fluxvm_id" \
  map name fluxvm_pspol pinned "$PIN/tc/maps/fluxvm_pspol" \
  map name fluxvm_pid4 pinned "$PIN/tc/maps/fluxvm_pid4" \
  map name fluxvm_pid6 pinned "$PIN/tc/maps/fluxvm_pid6" \
  map name fluxvm_pid4_port pinned "$PIN/tc/maps/fluxvm_pid4_port" \
  map name fluxvm_pid6_port pinned "$PIN/tc/maps/fluxvm_pid6_port" \
  map name fluxvm_prules pinned "$PIN/tc/maps/fluxvm_prules" \
  map name fluxvm_ppstat pinned "$PIN/tc/maps/fluxvm_ppstat" \
  map name fluxvm_ct pinned "$PIN/tc/maps/fluxvm_ct"
# Confirm real map sharing, not just a same-named coincidence: every map id
# the ingress program reports must already appear in fluxvm_egress's list.
python3 - "$PIN/tc/progs/fluxvm_egress" "$PIN/tc/progs/fluxvm_pod_ingress" <<'PY'
import json, subprocess, sys
egress, ingress = sys.argv[1], sys.argv[2]
def map_ids(pin):
    out = subprocess.check_output(["bpftool", "-j", "prog", "show", "pinned", pin], text=True)
    obj = json.loads(out)
    obj = obj[0] if isinstance(obj, list) else obj
    return set(obj.get("map_ids", []))
shared = map_ids(ingress)
if not shared or not shared.issubset(map_ids(egress)):
    sys.exit("fluxvm_pod_ingress map_ids are not a subset of fluxvm_egress's")
PY
tc filter add dev "$A" egress pref 49153 handle 2 bpf da \
  pinned "$PIN/tc/progs/fluxvm_pod_ingress"
tc filter show dev "$A" egress pref 49153 | grep -q 'bpf'

# Same rich-rule mechanics as the egress test above, but direction=INGRESS
# (2) and matched against the echo reply's source address ($A4, the "remote
# peer" as seen from the guest's perspective).
RICH_INGRESS_FLAGS=$((FLUXVM_PSPOL_ENABLED | FLUXVM_PSPOL_RICH_RULES | FLUXVM_PSPOL_INGRESS_ISOLATED))
RICH_EMPTY_IN="$(pod_policy_value "$RICH_INGRESS_FLAGS" 0 "$SCHEMA_V2")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY value hex $RICH_EMPTY_IN
expect_no_ping4
INGRESS_RULE="$(pod_rule_value "$POD_ID" 2 4 0 32 0 0 "$A4")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_prules" key hex $RULE_SLOT value hex $INGRESS_RULE
RICH_ONE_IN="$(pod_policy_value "$RICH_INGRESS_FLAGS" 1 "$SCHEMA_V2")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY value hex $RICH_ONE_IN
expect_ping4
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_ppstat" | grep -q 'key'

# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_prules" key hex $RULE_SLOT
# shellcheck disable=SC2086
bpftool map delete pinned "$PIN/tc/maps/fluxvm_pspol" key hex $POD_POLICY_KEY
tc filter del dev "$A" egress pref 49153 handle 2 bpf
INNER

echo "FluxVM Network Fabric v3 TC/IPv4/IPv6/L4/rate/XDP/Set-14-Pod-policy kernel smoke test passed"
echo "not covered here: live stateful conntrack bypass between the egress and Pod-ingress programs (tracked follow-up, see docs/secure-containers-set14.md)"
