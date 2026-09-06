#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Privileged kernel smoke for Network Fabric v3.
# Covers: TC attach, fail-closed policy, IPv4/IPv6 CIDRs, L4 policy,
# fixed-window PPS limiting, flow/stats maps, and IPv4/IPv6 XDP blocking.
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

for cmd in bpftool tc ip python3 ping mount; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[[ -f "$TC_OBJ" ]] || { echo "missing $TC_OBJ" >&2; exit 2; }
[[ -f "$XDP_OBJ" ]] || { echo "missing $XDP_OBJ" >&2; exit 2; }

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
  TC_OBJ="$TC_OBJ" XDP_OBJ="$XDP_OBJ" A="$A" NSB="$NSB" \
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
  # 6*u32 + 2*u64, matching struct iface_config exactly.
  python3 - "$@" <<'PY'
import struct, sys
vals = [int(x) for x in sys.argv[1:]]
identity, default_allow, enforce_cidr, enforce_l4, sample, rate_bytes, rate_pps = vals
raw = struct.pack("=IIIIIIQQ", identity, default_allow, enforce_cidr, enforce_l4,
                  sample, 0, rate_bytes, rate_pps)
print(" ".join(f"{b:02x}" for b in raw))
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
  if ip netns exec "$NSB" ping -q -c 1 -W 1 "$A4" >/dev/null; then
    echo "expected IPv4 ping to be blocked" >&2; exit 1
  fi
}
expect_ping6() { ip netns exec "$NSB" ping -6 -q -c 1 -W 2 "$A6" >/dev/null; }
expect_no_ping6() {
  if ip netns exec "$NSB" ping -6 -q -c 1 -W 1 "$A6" >/dev/null; then
    echo "expected IPv6 ping to be blocked" >&2; exit 1
  fi
}

mkdir -p "$BPFFS"
mount -t bpf bpf "$BPFFS"
mkdir -p "$PIN/tc/progs" "$PIN/tc/maps" "$PIN/xdp/progs" "$PIN/xdp/maps"

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
INNER

echo "FluxVM Network Fabric v3 TC/IPv4/IPv6/L4/rate/XDP kernel smoke test passed"
