#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Privileged functional smoke test for dataplane schema v6.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: run as root'; exit 0; }
for x in ip bpftool python3 tc; do command -v "$x" >/dev/null || { echo "SKIP: $x missing"; exit 0; }; done
[[ -f /usr/include/bpf/bpf_helpers.h ]] || { echo 'SKIP: libbpf development headers missing'; exit 0; }

TMP="$(mktemp -d)"
A="fvs3a$$"; B="fvs3b$$"; NS="fvs3ns$$"
PIN="/sys/fs/bpf/fluxvm/set3-test-$$"
cleanup(){
  tc filter del dev "$A" ingress pref 49152 >/dev/null 2>&1 || true
  tc qdisc del dev "$A" clsact >/dev/null 2>&1 || true
  ip netns del "$NS" >/dev/null 2>&1 || true
  ip link del "$A" >/dev/null 2>&1 || true
  rm -rf "$PIN" "$TMP" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || { echo 'SKIP: bpffs unavailable'; exit 0; }
fi
"$ROOT/scripts/build-ebpf.sh" "$TMP/bpf"
mkdir -p "$PIN/maps" "$PIN/progs"
if ! bpftool prog load "$TMP/bpf/fluxvm_tc.bpf.o" "$PIN/progs/egress" type classifier pinmaps "$PIN/maps" 2>"$TMP/load.err"; then
  echo "SKIP: kernel refused BPF load: $(cat "$TMP/load.err")"
  exit 0
fi

ip link add "$A" type veth peer name "$B"
ip netns add "$NS"
ip link set "$B" netns "$NS"
ip addr add 10.203.0.1/24 dev "$A"
ip link set "$A" up
ip -n "$NS" addr add 10.203.0.2/24 dev "$B"
ip -n "$NS" link set lo up
ip -n "$NS" link set "$B" up
IFINDEX="$(cat /sys/class/net/$A/ifindex)"
IDENTITY=424242

# iface_config v6 keeps the existing 48-byte ABI. Start with a 1 PPS ceiling
# to prove an established conntrack tuple no longer bypasses rate enforcement.
set_iface_config() {
  local pps="$1"
  python3 - "$IFINDEX" "$IDENTITY" "$PIN/maps/fluxvm_id" "$pps" <<'PY'
import struct, subprocess, sys
ifindex=int(sys.argv[1]); identity=int(sys.argv[2]); path=sys.argv[3]; pps=int(sys.argv[4])
key=struct.pack('@I',ifindex)
value=struct.pack('@IIIIIIQQII',identity,1,0,0,0,0,0,pps,0,0)
args=['bpftool','map','update','pinned',path,'key','hex',*map(lambda x:f'{x:02x}',key),'value','hex',*map(lambda x:f'{x:02x}',value)]
subprocess.check_call(args)
PY
}
set_iface_config 1

tc qdisc add dev "$A" clsact
tc filter add dev "$A" ingress pref 49152 handle 1 bpf da pinned "$PIN/progs/egress"

# First packet is allowed and learns CT. The same established tuple must still
# hit the limiter; pre-Set-3 code returned early on ct_hit and bypassed QoS.
ip netns exec "$NS" ping -c 1 -W 1 10.203.0.1 >/dev/null
if ip netns exec "$NS" ping -c 1 -W 1 10.203.0.1 >/dev/null 2>&1; then
  echo 'FAIL: established CT tuple bypassed 1 PPS limiter' >&2
  exit 1
fi
bpftool -j map dump pinned "$PIN/maps/fluxvm_drop_reasons" > "$TMP/reasons-rate.json"
python3 - "$TMP/reasons-rate.json" <<'PY'
import json,struct,sys
rows=json.load(open(sys.argv[1])); found=False
for row in rows:
    raw=row.get('key',[])
    b=bytes(int(x,16) if isinstance(x,str) else x for x in raw)
    if len(b)>=52 and struct.unpack_from('@I',b,44)[0]==7:
        found=True
assert found, 'rate-limit reason code 7 not observed on established conntrack flow'
PY

# Disable the limiter for the migration-continuity portion. CT remains learned.
set_iface_config 0
ip netns exec "$NS" ping -c 1 -W 1 10.203.0.1 >/dev/null

# Enter quiesce. The exact established ICMP tuple must still pass via CT.
python3 - "$IDENTITY" "$PIN/maps/fluxvm_migration" <<'PY'
import struct, subprocess, sys
identity=int(sys.argv[1]); path=sys.argv[2]
key=struct.pack('@I',identity); value=struct.pack('@II',1,1)
subprocess.check_call(['bpftool','map','update','pinned',path,'key','hex',*map(lambda x:f'{x:02x}',key),'value','hex',*map(lambda x:f'{x:02x}',value)])
PY
ip netns exec "$NS" ping -c 1 -W 1 10.203.0.1 >/dev/null

# A new UDP tuple is blocked by the migration gate.
ip netns exec "$NS" python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'new-flow',('10.203.0.1',23456))
PY
sleep .1
bpftool -j map dump pinned "$PIN/maps/fluxvm_drop_reasons" > "$TMP/reasons-quiesce.json"
python3 - "$TMP/reasons-quiesce.json" <<'PY'
import json,struct,sys
rows=json.load(open(sys.argv[1])); found=False
for row in rows:
    raw=row.get('key',[])
    b=bytes(int(x,16) if isinstance(x,str) else x for x in raw)
    if len(b)>=52 and struct.unpack_from('@I',b,44)[0]==9:
        found=True
assert found, 'migration-quiesce reason code 9 not observed'
PY

# Destination-style restoring state gets its own reason code.
python3 - "$IDENTITY" "$PIN/maps/fluxvm_migration" <<'PY'
import struct, subprocess, sys
identity=int(sys.argv[1]); path=sys.argv[2]
key=struct.pack('@I',identity); value=struct.pack('@II',2,2)
subprocess.check_call(['bpftool','map','update','pinned',path,'key','hex',*map(lambda x:f'{x:02x}',key),'value','hex',*map(lambda x:f'{x:02x}',value)])
PY
ip netns exec "$NS" python3 - <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'restore-flow',('10.203.0.1',23457))
PY
sleep .1
bpftool -j map dump pinned "$PIN/maps/fluxvm_drop_reasons" > "$TMP/reasons-restore.json"
python3 - "$TMP/reasons-restore.json" <<'PY'
import json,struct,sys
rows=json.load(open(sys.argv[1])); found=False
for row in rows:
    raw=row.get('key',[])
    b=bytes(int(x,16) if isinstance(x,str) else x for x in raw)
    if len(b)>=52 and struct.unpack_from('@I',b,44)[0]==10:
        found=True
assert found, 'migration-restoring reason code 10 not observed'
PY

echo 'drop-reason + migration-state privileged smoke test: PASS'
