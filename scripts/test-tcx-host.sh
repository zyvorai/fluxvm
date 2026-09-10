#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Privileged host smoke test for the TCX helper. Requires Linux >= 6.6,
# CAP_BPF/CAP_NET_ADMIN (normally root), libbpf, bpffs and bpftool.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: run as root'; exit 0; }
command -v ip >/dev/null || { echo 'SKIP: iproute2 missing'; exit 0; }
command -v bpftool >/dev/null || { echo 'SKIP: bpftool missing'; exit 0; }
command -v pkg-config >/dev/null || { echo 'SKIP: pkg-config missing'; exit 0; }
command -v python3 >/dev/null || { echo 'SKIP: python3 missing'; exit 0; }
pkg-config --exists libbpf || { echo 'SKIP: libbpf-dev missing'; exit 0; }

TMP="$(mktemp -d)"
IFACE="fvtcx$$"
PIN_ROOT="/sys/fs/bpf/fluxvm/tcx-test-$$"
cleanup() {
  "$TMP/fluxvm-tcx" detach "$PIN_ROOT/link" >/dev/null 2>&1 || true
  rm -rf "$PIN_ROOT" >/dev/null 2>&1 || true
  ip link del "$IFACE" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || { echo 'SKIP: bpffs is not mounted and could not be mounted'; exit 0; }
fi

${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcx.c" -o "$TMP/fluxvm-tcx" $(pkg-config --cflags --libs libbpf)
ip link add "$IFACE" type dummy
ip link set "$IFACE" up
if ! "$TMP/fluxvm-tcx" probe "$IFACE"; then
  echo 'SKIP: kernel/libbpf does not support TCX on the test interface'
  exit 0
fi

# Reuse the production VM-edge program. Load two independent program/map
# generations so BPF_LINK_UPDATE proves an actual program-id transition.
"$ROOT/scripts/build-ebpf.sh" "$TMP/bpf"
mkdir -p "$PIN_ROOT/maps-a" "$PIN_ROOT/maps-b" "$PIN_ROOT/progs"
bpftool prog load "$TMP/bpf/fluxvm_tc.bpf.o" "$PIN_ROOT/progs/egress-a" type classifier pinmaps "$PIN_ROOT/maps-a"
bpftool prog load "$TMP/bpf/fluxvm_tc.bpf.o" "$PIN_ROOT/progs/egress-b" type classifier pinmaps "$PIN_ROOT/maps-b"

prog_id() {
  bpftool -j prog show pinned "$1" | python3 -c 'import json,sys; v=json.load(sys.stdin); v=v[0] if isinstance(v,list) else v; print(v["id"])'
}
OLD_ID="$(prog_id "$PIN_ROOT/progs/egress-a")"
NEW_ID="$(prog_id "$PIN_ROOT/progs/egress-b")"
[[ "$OLD_ID" != "$NEW_ID" ]]

"$TMP/fluxvm-tcx" attach "$IFACE" "$PIN_ROOT/progs/egress-a" "$PIN_ROOT/link"
STATUS="$($TMP/fluxvm-tcx status "$PIN_ROOT/link")"
echo "$STATUS" | grep -q '"mode":"tcx"'
echo "$STATUS" | grep -q "\"prog_id\":$OLD_ID"

"$TMP/fluxvm-tcx" update "$PIN_ROOT/progs/egress-b" "$PIN_ROOT/link" "$PIN_ROOT/progs/egress-a"
STATUS="$($TMP/fluxvm-tcx status "$PIN_ROOT/link")"
echo "$STATUS" | grep -q "\"prog_id\":$NEW_ID"

"$TMP/fluxvm-tcx" detach "$PIN_ROOT/link"
[[ ! -e "$PIN_ROOT/link" ]]
echo 'TCX privileged smoke test: PASS'
