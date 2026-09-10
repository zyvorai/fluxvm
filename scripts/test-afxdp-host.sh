#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: root required'; exit 0; }
for c in ip ping bpftool clang cc pkg-config python3; do command -v "$c" >/dev/null || { echo "SKIP: $c unavailable"; exit 0; }; done
pkg-config --exists libbpf libxdp || { echo 'SKIP: libbpf/libxdp development packages unavailable'; exit 0; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || { echo 'SKIP: cannot mount bpffs'; exit 0; }
TMP="$(mktemp -d)"; PIN="/sys/fs/bpf/fluxvm-set9-test-$$"; A="f9a$$"; AP="p9a$$"; B="f9b$$"; BP="p9b$$"; NSA="n9a$$"; NSB="n9b$$"; WPID=""
cleanup(){ set +e; [[ -n "$WPID" ]] && kill "$WPID" 2>/dev/null; "$TMP/loader" unload "$PIN" "$A" "$B" >/dev/null 2>&1; ip netns del "$NSA" 2>/dev/null; ip netns del "$NSB" 2>/dev/null; ip link del "$A" 2>/dev/null; ip link del "$B" 2>/dev/null; rm -rf "$PIN" "$TMP"; }
trap cleanup EXIT
"$ROOT/scripts/build-afxdp-fastpath.sh" "$TMP/bpf" "$TMP/bin"
cp "$TMP/bin/fluxvm-afxdp-loader" "$TMP/loader"; cp "$TMP/bin/fluxvm-afxdp-worker" "$TMP/worker"
ip link add "$A" type veth peer name "$AP"; ip link add "$B" type veth peer name "$BP"
ip netns add "$NSA"; ip netns add "$NSB"; ip link set "$AP" netns "$NSA"; ip link set "$BP" netns "$NSB"
ip link set "$A" up; ip link set "$B" up
ip -n "$NSA" link set lo up; ip -n "$NSB" link set lo up; ip -n "$NSA" link set "$AP" up; ip -n "$NSB" link set "$BP" up
ip -n "$NSA" addr add 10.199.9.1/24 dev "$AP"; ip -n "$NSB" addr add 10.199.9.2/24 dev "$BP"
"$TMP/loader" load "$TMP/bpf/fluxvm_afxdp.bpf.o" "$PIN" "$A" "$B" 424242 auto 0 > "$TMP/load.json"
# A second loader must refuse to replace the already-owned XDP attachment.
if "$TMP/loader" load "$TMP/bpf/fluxvm_afxdp.bpf.o" "$PIN-second" "$A" "$B" 424243 auto 0 >/dev/null 2>&1; then echo 'FAIL: XDP ownership replacement was not refused' >&2; exit 1; fi
"$TMP/worker" "$PIN" "$A" 0 "$B" 0 copy 64 >"$TMP/worker.out" 2>"$TMP/worker.err" & WPID=$!
sleep 1
ip netns exec "$NSA" ping -c 3 -W 1 10.199.9.2 >/dev/null
ip netns exec "$NSB" ping -c 2 -W 1 10.199.9.1 >/dev/null
sleep 1
kill -TERM "$WPID"; wait "$WPID" || true; WPID=""
bpftool -j map dump pinned "$PIN/maps/afxdp_runtime" > "$TMP/runtime.json"
python3 - "$TMP/runtime.json" <<'PY2'
import json,sys
rows=json.load(open(sys.argv[1])); active=[]
for r in rows:
 v=r.get('value',[])
 if isinstance(v,list) and len(v)>=88:
  b=bytes(int(x,16) if isinstance(x,str) else x for x in v)
  rx=int.from_bytes(b[0:8],sys.byteorder); tx=int.from_bytes(b[16:24],sys.byteorder); pid=int.from_bytes(b[84:88],sys.byteorder)
  if pid: active.append((rx,tx))
assert len(active)>=2,active
assert sum(x for x,_ in active)>0,active
assert sum(y for _,y in active)>0,active
print('AF_XDP veth bridge runtime counters: PASS',active)
PY2
"$TMP/loader" status "$PIN" "$A" "$B" >/dev/null
echo 'AF_XDP privileged host test: PASS'
