#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: root required'; exit 0; }
for x in ip bpftool clang cargo python3 pkg-config; do command -v "$x" >/dev/null || { echo "SKIP: $x unavailable"; exit 0; }; done
pkg-config --exists libbpf || { echo 'SKIP: libbpf-dev unavailable'; exit 0; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || { echo 'SKIP: cannot mount bpffs'; exit 0; }
TMP="$(mktemp -d)"; PINS="/sys/fs/bpf/fluxvm-quiclb-test-$$"; NSC="fq-c-$$"; NSB="fq-b-$$"; IN="fqin$$"; CP="fqcp$$"; OUT="fqout$$"; BP="fqbp$$"; ID="11111111-2222-4333-8444-555555555555"
cleanup(){ set +e; FLUXVM_QUICLB_STATE_ROOT="$TMP/state" FLUXVM_QUICLB_PIN_ROOT="$PINS" "$ROOT/target/release/fluxvm-quiclb" remove "$ID" >/dev/null 2>&1; ip netns del "$NSC" 2>/dev/null; ip netns del "$NSB" 2>/dev/null; rm -rf "$TMP" "$PINS"; }; trap cleanup EXIT
ip netns add "$NSC"; ip netns add "$NSB"; ip link add "$IN" type veth peer name "$CP"; ip link set "$CP" netns "$NSC"; ip link add "$OUT" type veth peer name "$BP"; ip link set "$BP" netns "$NSB"
ip addr add 192.0.2.1/24 dev "$IN"; ip link set "$IN" up; ip link set "$OUT" up
ip -n "$NSC" addr add 192.0.2.2/24 dev "$CP"; ip -n "$NSC" link set "$CP" up
ip -n "$NSC" route add 198.51.100.100/32 via 192.0.2.1 dev "$CP"
ip -n "$NSB" addr add 198.51.100.2/24 dev "$BP"; ip -n "$NSB" addr add 198.51.100.100/32 dev lo; ip -n "$NSB" link set "$BP" up; ip -n "$NSB" link set lo up
MAC="$(ip netns exec "$NSB" cat /sys/class/net/$BP/address)"
"$ROOT/scripts/build-quiclb.sh" "$TMP/bpf" "$TMP/bin"
cargo build --release -p fluxvm-intelligence --bin fluxvm-quiclb
mkdir -p "$TMP/state" "$PINS"
cat >"$TMP/spec.json" <<EOF
{"instance_id":"$ID","interface":"$IN","mode":"generic","services":[{"name":"host-test","vip":"198.51.100.100","port":443,"short_dcid_len":8,"quic_only":true,"backends":[{"id":1,"interface":"$OUT","mac":"$MAC","weight":1,"state":"ready"}]}]}
EOF
FLUXVM_QUICLB_LOADER="$TMP/bin/fluxvm-quiclb-loader" "$ROOT/target/release/fluxvm-quiclb" plan "$TMP/spec.json" "$TMP/plan.json" >/dev/null
FLUXVM_QUICLB_LOADER="$TMP/bin/fluxvm-quiclb-loader" FLUXVM_QUICLB_OBJECT="$TMP/bpf/fluxvm_quiclb.bpf.o" FLUXVM_QUICLB_STATE_ROOT="$TMP/state" FLUXVM_QUICLB_PIN_ROOT="$PINS" "$ROOT/target/release/fluxvm-quiclb" apply "$TMP/plan.json" >/dev/null
ip netns exec "$NSB" python3 - >"$TMP/server.out" 2>&1 <<'PY' &
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.100',443));s.settimeout(5);n=0
while n<3:
    s.recvfrom(2048); n+=1
print(n,flush=True)
PY
SP=$!; sleep .2
ip netns exec "$NSC" python3 - <<'PY'
import socket
p=bytes([0xc0])+bytes.fromhex('00000001')+bytes([8])+b'CIDTEST1'+bytes([0])+b'x'
for port in (40001,40002,40003):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.2',port));s.sendto(p,('198.51.100.100',443));s.close()
PY
wait "$SP"; grep -q '^3$' "$TMP/server.out"
S="$(FLUXVM_QUICLB_LOADER="$TMP/bin/fluxvm-quiclb-loader" FLUXVM_QUICLB_STATE_ROOT="$TMP/state" "$ROOT/target/release/fluxvm-quiclb" status "$ID")"
python3 - "$S" <<'PY'
import json,sys
x=json.loads(sys.argv[1]); assert x['attached']; assert x['stats'][0]['redirects']>=3; assert x['stats'][0]['affinity_hits']>=2
print('QUIC affinity + DSR redirect host test: PASS')
PY
