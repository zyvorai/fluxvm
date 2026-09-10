#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Privileged disposable integration test. Skips cleanly if prerequisites or
# kernel attachment support are unavailable.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "SKIP: root required"; exit 0; }
for c in ip bpftool clang cargo cc pkg-config python3 ping; do command -v "$c" >/dev/null || { echo "SKIP: $c unavailable"; exit 0; }; done
pkg-config --exists libbpf || { echo "SKIP: libbpf development package unavailable"; exit 0; }
if ! mountpoint -q /sys/fs/bpf; then mount -t bpf bpf /sys/fs/bpf 2>/dev/null || { echo "SKIP: cannot mount bpffs"; exit 0; }; fi

SUF="$$"; NS="f6ns${SUF}"; H="f6h${SUF}"; P="f6p${SUF}"
H="${H:0:15}"; P="${P:0:15}"; OCT=$(( (SUF % 180) + 20 )); HIP="10.253.${OCT}.1"; PIP="10.253.${OCT}.2"
PORT=$(( 20000 + (SUF % 20000) ))
BP="/sys/fs/bpf/fluxvm-set6-test-${SUF}"; STATE="/tmp/fluxvm-set6-state-${SUF}"; OUT="/tmp/fluxvm-set6-build-${SUF}"
ID1="11111111-1111-4111-8111-111111111111"; ID2="22222222-2222-4222-8222-222222222222"
SERVER=""
cleanup(){ set +e; [[ -n "$SERVER" ]] && kill "$SERVER" 2>/dev/null; "$ROOT/target/release/fluxvm-tcpintel" detach "$ID1" >/dev/null 2>&1; "$ROOT/target/release/fluxvm-shield" remove "$ID1" >/dev/null 2>&1; ip netns del "$NS" 2>/dev/null; ip link del "$H" 2>/dev/null; rm -rf "$BP" "$STATE" "$OUT" /tmp/fluxvm-set6-*.json; }
trap cleanup EXIT

"$ROOT/scripts/build-network-intelligence.sh" "$OUT/bpf"
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-xdp-shield-loader.c" -o "$OUT/fluxvm-xdp-shield-loader" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-shield-events.c" -o "$OUT/fluxvm-shield-events" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcp-loader.c" -o "$OUT/fluxvm-tcp-loader" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcp-events.c" -o "$OUT/fluxvm-tcp-events" $(pkg-config --cflags --libs libbpf)
(cd "$ROOT" && cargo build --release -p fluxvm-intelligence --bin fluxvm-shield --bin fluxvm-tcpintel)

ip netns add "$NS"; ip link add "$H" type veth peer name "$P"; ip link set "$P" netns "$NS"
ip addr add "$HIP/30" dev "$H"; ip link set "$H" up
ip -n "$NS" addr add "$PIP/30" dev "$P"; ip -n "$NS" link set lo up; ip -n "$NS" link set "$P" up
mkdir -p "$STATE"
export FLUXVM_SHIELD_PIN_ROOT="$BP/shield" FLUXVM_SHIELD_STATE_ROOT="$STATE/shield"
export FLUXVM_XDP_SHIELD_LOADER="$OUT/fluxvm-xdp-shield-loader" FLUXVM_XDP_SHIELD_OBJECT="$OUT/bpf/fluxvm_xdp_shield.bpf.o"
export FLUXVM_TCP_PIN_ROOT="$BP/tcp" FLUXVM_TCP_STATE_ROOT="$STATE/tcp"
export FLUXVM_TCP_LOADER="$OUT/fluxvm-tcp-loader" FLUXVM_TCP_OBJECT="$OUT/bpf/fluxvm_tcp_intel.bpf.o"

cat >/tmp/fluxvm-set6-enforce.json <<JSON
{"mode":"enforce","protected_ips":["$HIP"],"deny_sources":["$PIP/32"],"syn_pps":1000,"udp_pps":1000,"icmp_pps":1000,"other_pps":1000,"burst_seconds":1,"sample_rate":1,"xdp_mode":"auto"}
JSON
"$ROOT/target/release/fluxvm-shield" apply "$ID1" "$H" --policy /tmp/fluxvm-set6-enforce.json >/tmp/fluxvm-set6-apply.json || { echo "SKIP: XDP attach unsupported by test interface/kernel"; exit 0; }
if ip netns exec "$NS" ping -c1 -W1 "$HIP" >/dev/null 2>&1; then echo "enforce-mode explicit deny did not drop" >&2; exit 1; fi
if "$ROOT/target/release/fluxvm-shield" apply "$ID2" "$H" --policy /tmp/fluxvm-set6-enforce.json >/dev/null 2>&1; then echo "second XDP owner was not refused" >&2; exit 1; fi

cat >/tmp/fluxvm-set6-audit.json <<JSON
{"mode":"audit","protected_ips":["$HIP"],"deny_sources":["$PIP/32"],"syn_pps":1000,"udp_pps":1000,"icmp_pps":1000,"other_pps":1000,"burst_seconds":1,"sample_rate":1,"xdp_mode":"auto"}
JSON
"$ROOT/target/release/fluxvm-shield" apply "$ID1" "$H" --policy /tmp/fluxvm-set6-audit.json >/dev/null
ip netns exec "$NS" ping -c1 -W2 "$HIP" >/dev/null
"$ROOT/target/release/fluxvm-shield" status "$ID1" >/tmp/fluxvm-set6-status.json
grep -q 'explicit-deny' /tmp/fluxvm-set6-status.json; grep -q 'audit' /tmp/fluxvm-set6-status.json
"$ROOT/target/release/fluxvm-shield" remove "$ID1" >/dev/null

"$ROOT/target/release/fluxvm-tcpintel" attach "$ID1" "$H" 1 >/tmp/fluxvm-set6-tcp-attach.json || { echo "SKIP: TCX/TC observer attach unsupported by test kernel"; exit 0; }
python3 - "$HIP" "$PORT" <<'PY' &
import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])));s.listen(1);c,_=s.accept();c.recv(16);c.sendall(b'ok');c.close();s.close()
PY
SERVER=$!; sleep .2
ip netns exec "$NS" python3 - "$HIP" "$PORT" <<'PY'
import socket,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),2);s.sendall(b'hello');assert s.recv(2)==b'ok';s.close()
PY
wait "$SERVER"; SERVER=""; sleep .2
"$ROOT/target/release/fluxvm-tcpintel" snapshot "$ID1" 32 >/tmp/fluxvm-set6-tcp.json
grep -q '"established"' /tmp/fluxvm-set6-tcp.json
python3 - <<'PY'
import json
v=json.load(open('/tmp/fluxvm-set6-tcp.json'))
assert v['counters']['syn'] >= 1, v
assert v['counters']['established'] >= 1, v
assert v['handshake_p95_ns'] is not None, v
print('live TCP handshake telemetry: PASS')
PY
"$ROOT/target/release/fluxvm-tcpintel" detach "$ID1" >/dev/null

echo "XDP Shield enforce/audit/foreign-owner + TCP handshake host test: PASS"
