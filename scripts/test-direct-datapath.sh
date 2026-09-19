#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Linux-root netns test for the direct (bridge-less) datapath. No KVM, no
# daemon: it loads the real BPF objects with bpftool and emulates a Cilium pod.
#
#   node ns:  lxc0 (10.98.0.1) ⇄ veth ⇄ eth0 :pod ns  (Cilium delivers here)
#   pod ns:   eth0 ── direct_in ──▶ tap0 ◀── python "guest" (10.98.0.2)
#             tap0 ── fluxvm_egress (policy) ──▶ redirect_peer(eth0) ──▶ lxc0
#
# Asserts, in order of how much the design depends on them:
#   1. traffic flows both ways with NO bridge device in either namespace
#   2. VM-edge policy still gates the redirect (deny => guest replies dropped)
#   3. a TC redirect INTO the tap still runs the tap's egress hooks (so the
#      Pod-ingress policy program is not bypassed) -- the plan's decision 4
#   4. an unconfigured outer device fails open instead of blackholing state
#
#   sudo ./scripts/test-direct-datapath.sh
#   FLUXVM_BPF_DIR=dist/bpf sudo ./scripts/test-direct-datapath.sh   # prebuilt objects
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { echo "test-direct-datapath: $*"; }
skip() { say "SKIP: $*"; exit 0; }
FAILS=0
pass() { echo "  ✅ $*"; }
fail() { echo "  ❌ $*" >&2; FAILS=$((FAILS + 1)); }

[[ "$(uname -s)" == "Linux" ]] || skip "Linux required"
[[ "$(id -u)" -eq 0 ]] || skip "root required (run with sudo)"
for c in ip tc bpftool nsenter python3; do
  command -v "$c" >/dev/null || skip "$c not found"
done
# findmnt, not `mount | grep -q`: under pipefail grep -q's early exit SIGPIPEs mount.
[[ "$(findmnt -n -o FSTYPE /sys/fs/bpf 2>/dev/null)" == "bpf" ]] || skip "bpffs is not mounted at /sys/fs/bpf"

NSP="fvdd$$"
NODE="${NSP}-node"
POD="${NSP}-pod"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/direct-datapath.XXXXXX")"
PIN="/sys/fs/bpf/${NSP}"
NODE_IP=10.98.0.1
GUEST_IP=10.98.0.2
GUEST_MAC=02:00:00:00:00:02
GUEST_PID=""

cleanup() {
  [[ -n "$GUEST_PID" ]] && kill "$GUEST_PID" 2>/dev/null || true
  ip netns del "$NODE" 2>/dev/null || true
  ip netns del "$POD" 2>/dev/null || true
  rm -rf "$PIN" "$WORK"
}
trap cleanup EXIT INT TERM

# nsenter --net (not `ip netns exec`): the latter re-mounts /sys and can hide
# bpffs, and the real loader uses nsenter for the same reason.
inpod()  { nsenter --net="/run/netns/${POD}" -- "$@"; }
innode() { nsenter --net="/run/netns/${NODE}" -- "$@"; }

if [[ -n "${FLUXVM_BPF_DIR:-}" ]]; then
  BPF="$FLUXVM_BPF_DIR"
else
  command -v clang >/dev/null || skip "clang not found (set FLUXVM_BPF_DIR to prebuilt objects)"
  BPF="$WORK/bpf"
  bash "$ROOT/scripts/build-ebpf.sh" "$BPF" >/dev/null 2>&1 || { say "FAIL: build-ebpf.sh"; exit 1; }
fi
[[ -f "$BPF/fluxvm_tc.bpf.o" && -f "$BPF/fluxvm_direct.bpf.o" ]] || { say "FAIL: BPF objects missing in $BPF"; exit 1; }

echo "== direct datapath: node lxc0 ⇄ pod eth0 → tap0 → guest =="

# ── topology ────────────────────────────────────────────────────────
ip netns add "$NODE"; ip netns add "$POD"
ip -n "$NODE" link add lxc0 type veth peer name eth0 netns "$POD"
ip -n "$NODE" addr add "${NODE_IP}/24" dev lxc0
ip -n "$NODE" link set lo up; ip -n "$NODE" link set lxc0 up
ip -n "$POD" link set lo up;  ip -n "$POD" link set eth0 up
ip -n "$POD" tuntap add dev tap0 mode tap
ip -n "$POD" link set tap0 up
for n in "$NODE" "$POD"; do ip netns exec "$n" sysctl -qw net.ipv6.conf.all.disable_ipv6=1; done
TAP_IDX=$(ip -n "$POD" -o link show tap0 | cut -d: -f1)
ETH_IDX=$(ip -n "$POD" -o link show eth0 | cut -d: -f1)

# Started with nsenter directly, NOT through the inpod() function: backgrounding a
# function makes $! the wrapper subshell, so cleanup would never kill python.
# stdio is detached so a leaked guest can never hold the caller's pipe open.
nsenter --net="/run/netns/${POD}" -- python3 "$ROOT/scripts/direct-datapath-guest.py" \
  tap0 "$GUEST_IP" "$GUEST_MAC" "$WORK/guest.stats" >"$WORK/guest.log" 2>&1 </dev/null &
GUEST_PID=$!
for _ in $(seq 1 20); do [[ -f "$WORK/guest.stats" ]] && break; sleep 0.1; done
[[ -f "$WORK/guest.stats" ]] || { say "FAIL: guest did not start"; exit 1; }

# ── load + configure (mirrors what the daemon loader will do) ───────
le32() { printf '%02x %02x %02x %02x' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)); }
Z8='00 00 00 00 00 00 00 00'
# struct iface_config (48 B): identity default_allow enforce_cidr enforce_l4 sample_rate allow_icmp
#                             rate_bytes(8) rate_pps(8) pod_id reserved0
iface_cfg() { echo "$(le32 1) $(le32 "$1") $(le32 0) $(le32 0) $(le32 0) $(le32 "$2") $Z8 $Z8 $(le32 0) $(le32 0)"; }
mapupd() { bpftool map update pinned "$1" key hex $2 value hex $3; }

mkdir -p "$PIN/maps" "$PIN/maps_in"
bpftool prog load "$BPF/fluxvm_direct.bpf.o" "$PIN/in" type classifier pinmaps "$PIN/maps_in"
pass "fluxvm_direct.bpf.o (inbound redirect) passes the kernel verifier"

# The real fluxvm_egress is large; some kernels' verifiers reject it (Linux 7.0.0-31
# processes >1,000,000 insns for the UNMODIFIED object too). In that case fall back to
# a test stub with the same shape -- policy verdict, then the shared redirect tail from
# bpf/fluxvm_direct.bpf.h -- so the redirect mechanics are still proven.
MODE=real
if ! bpftool prog load "$BPF/fluxvm_tc.bpf.o" "$PIN/egress" type classifier pinmaps "$PIN/maps" >"$WORK/real-load.log" 2>&1; then
  MODE=stub
  rm -rf "$PIN/maps" "$PIN/egress"; mkdir -p "$PIN/maps"
  echo "  ⚠️  real fluxvm_egress rejected by this kernel's verifier ($(grep -oE 'processed [0-9]+ insns \(limit [0-9]+\)|too large' "$WORK/real-load.log" | tail -1))"
  echo "  ⚠️  using the STUB policy program: redirect mechanics are verified, real-policy ordering is NOT"
  A=$(case "$(uname -m)" in x86_64) echo x86 ;; aarch64) echo arm64 ;; *) echo unsupported ;; esac)
  [[ "$A" != unsupported ]] || skip "no stub build support for $(uname -m)"
  MULTI=""; command -v gcc >/dev/null && MULTI="-I/usr/include/$(gcc -print-multiarch)"
  # shellcheck disable=SC2086
  clang -target bpf -O2 -g -Wall -Werror "-D__TARGET_ARCH_${A}" $MULTI \
    -c "$ROOT/bpf/tests/fluxvm_direct_stub_egress.bpf.c" -o "$WORK/stub.bpf.o"
  bpftool prog load "$WORK/stub.bpf.o" "$PIN/egress" type classifier pinmaps "$PIN/maps"
  pass "stub egress program loads (same redirect tail as the real one)"
else
  pass "real fluxvm_egress (with redirect tail) passes the kernel verifier"
fi

# Empty a pinned map. The real loader (ebpf.rs) does this to fluxvm_ct on every policy
# change, because conntrack deliberately keeps already-learned flows flowing: without it a
# deny would not affect the ICMP flow the earlier steps established.
clear_map() { python3 "$ROOT/scripts/bpf-map-clear.py" "$1" 2>/dev/null; }

# policy allow|deny for the tap, whichever program is loaded
policy() {
  local on=0; [[ "$1" == allow ]] && on=1
  if [[ "$MODE" == real ]]; then
    mapupd "$PIN/maps/fluxvm_id" "$(le32 "$TAP_IDX")" "$(iface_cfg "$on" "$on")"
    clear_map "$PIN/maps/fluxvm_ct"
  else
    mapupd "$PIN/maps/stub_allow" "$(le32 "$TAP_IDX")" "$(le32 "$on")"
  fi
}
policy allow
mapupd "$PIN/maps/fluxvm_direct" "$(le32 "$TAP_IDX")" "$(le32 "$ETH_IDX") $(le32 1) $(le32 0) $(le32 0)"   # PEER -> eth0
mapupd "$PIN/maps_in/fluxvm_direct_in" "$(le32 "$ETH_IDX")" "$(le32 "$TAP_IDX") $(le32 1)"                 # PEER mode -> tap0
inpod tc qdisc add dev tap0 clsact
inpod tc filter add dev tap0 ingress bpf da pinned "$PIN/egress"
inpod tc qdisc add dev eth0 clsact
inpod tc filter add dev eth0 ingress bpf da pinned "$PIN/in"

stat() { grep "^$1=" "$WORK/guest.stats" | cut -d= -f2; }
ping_ok()   { innode ping -c "${2:-3}" -W 1 -i 0.2 -q "$1" >/dev/null 2>&1; }

# ── 1. flows both ways, no bridge anywhere ──────────────────────────
if ping_ok "$GUEST_IP"; then pass "node → guest ping works through eth0 → direct_in → tap0 → fluxvm_egress → lxc0"
else fail "node cannot reach the guest through the direct path"; fi
[[ "$(stat icmp_replies)" -ge 3 ]] && pass "guest answered $(stat icmp_replies) echo requests (arp_replies=$(stat arp_replies))" \
  || fail "guest saw too few echo requests: $(cat "$WORK/guest.stats" | tr '\n' ' ')"
# grep -c exits 1 on a zero count, which set -e would treat as a failed assignment.
count_bridges() { ip -n "$1" -d link | grep -c 'bridge ' || true; }
BR=$(( $(count_bridges "$NODE") + $(count_bridges "$POD") ))
[[ "$BR" -eq 0 ]] && pass "no bridge device exists in either namespace" || fail "$BR bridge device(s) present"

# ── 2. VM-edge policy still gates the redirect ──────────────────────
policy deny
if ping_ok "$GUEST_IP" 2; then fail "policy deny did not stop guest replies (redirect ran before policy?)"
else pass "default-deny at the VM edge drops guest replies before any redirect"; fi
policy allow
ping_ok "$GUEST_IP" && pass "restoring allow restores connectivity" || fail "connectivity did not recover after allow"

# ── 3. redirect into the tap still runs the tap's egress hooks ──────
before=$(stat rx_frames); icmp_before=$(stat icmp_replies)
inpod tc filter add dev tap0 egress protocol all prio 1 matchall action drop
if ping_ok "$GUEST_IP" 2; then fail "DECISION 4 WRONG: redirected frames bypassed the tap's egress hook"
else pass "tap egress hook runs on redirected frames (Pod-ingress policy is not bypassed)"; fi
sleep 0.3
after=$(stat rx_frames)
# The counter is cumulative across earlier steps, so compare a delta: not one new echo
# request may reach the guest while the egress drop is active.
[[ "$(stat icmp_replies)" -eq "$icmp_before" ]] \
  && pass "guest received no echo requests while the egress drop was active (rx_frames $before → $after)" \
  || fail "guest received $(( $(stat icmp_replies) - icmp_before )) echo request(s) through the egress drop"
inpod tc filter del dev tap0 egress prio 1
ping_ok "$GUEST_IP" && pass "removing the egress drop restores connectivity" || fail "connectivity did not recover"

# ── 4. unconfigured outer device fails open ─────────────────────────
# shellcheck disable=SC2046  # bpftool wants the hex bytes as separate arguments
bpftool map delete pinned "$PIN/maps_in/fluxvm_direct_in" key hex $(le32 "$ETH_IDX")
if ping_ok "$GUEST_IP" 2; then fail "with no direct_in entry traffic should fall to the (empty) stack, not reach the guest"
else pass "missing direct_in entry fails open to the stack (no redirect, no crash)"; fi
mapupd "$PIN/maps_in/fluxvm_direct_in" "$(le32 "$ETH_IDX")" "$(le32 "$TAP_IDX") $(le32 1)"
ping_ok "$GUEST_IP" && pass "re-adding the entry restores the path" || fail "path did not recover"

echo
if [[ "$FAILS" -eq 0 ]]; then echo "🎉 direct datapath test PASS (egress program: $MODE)"; else echo "direct datapath test: $FAILS FAILED" >&2; exit 1; fi
