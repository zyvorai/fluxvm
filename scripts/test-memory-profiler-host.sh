#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: root required'; exit 0; }
for c in clang bpftool cc pkg-config python3 cargo; do command -v "$c" >/dev/null || { echo "SKIP: $c missing"; exit 0; }; done
pkg-config --exists libbpf || { echo 'SKIP: libbpf development package missing'; exit 0; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf || { echo 'SKIP: cannot mount bpffs'; exit 0; }

TMP="$(mktemp -d)"
PIN="/sys/fs/bpf/fluxvm-set7-test-$$"
GO="$TMP/go"
cleanup(){ rm -f "$GO"; rm -rf "$PIN" "$TMP"; }
trap cleanup EXIT

"$ROOT/scripts/build-ebpf.sh" "$TMP/bpf"
"$ROOT/scripts/build-memory-profiler.sh" "$TMP/bpf"
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-intelligence-loader.c" -o "$TMP/intel-loader" $(pkg-config --cflags --libs libbpf)
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-memprof-loader.c" -o "$TMP/mem-loader" $(pkg-config --cflags --libs libbpf)
"$TMP/intel-loader" --load "$TMP/bpf/fluxvm_intelligence.bpf.o" "$PIN"
"$TMP/mem-loader" "$TMP/bpf/fluxvm_memprof.bpf.o" "$PIN"

UUID='11111111-2222-4333-8444-555555555555'
KEY="$(python3 - <<'PY'
import uuid
u=uuid.UUID('11111111-2222-4333-8444-555555555555')
h=0xcbf29ce484222325
for b in u.bytes:
    h ^= b; h=(h*0x100000001b3)&((1<<64)-1)
print(h or 1)
PY
)"
python3 - "$GO" <<'PY' &
import os,sys,time
while not os.path.exists(sys.argv[1]): time.sleep(.01)
# Thousands of demand faults in a tracked process; major-fault classification
# is filesystem/cache dependent, but total handle_mm_fault attribution is deterministic.
x=[]
for _ in range(32768): x.append(bytearray(4096))
time.sleep(1)
PY
PID=$!
python3 - "$PID" "$KEY" "$PIN/maps/tracked_tgids" <<'PY'
import subprocess,sys
pid=int(sys.argv[1]); key=int(sys.argv[2]); path=sys.argv[3]
def le(v,n): return [f'{b:02x}' for b in v.to_bytes(n,'little')]
subprocess.check_call(['bpftool','map','update','pinned',path,'key','hex',*le(pid,4),'value','hex',*le(key,8)])
PY
touch "$GO"
wait "$PID"

# The kernel fault counter must be non-zero for the tracked workload.
python3 - "$KEY" "$PIN/memprof/maps/memprof_stats" <<'PY'
import json,subprocess,sys
wanted=int(sys.argv[1]); rows=json.loads(subprocess.check_output(['bpftool','-j','map','dump','pinned',sys.argv[2]]))
def bs(v): return bytes(int(x,16) if isinstance(x,str) else x for x in v)
for r in rows:
    if int.from_bytes(bs(r['key'])[:8],'little')==wanted:
        faults=int.from_bytes(bs(r['value'])[:8],'little')
        assert faults>0, faults
        print('tracked page-fault attribution:',faults)
        break
else: raise SystemExit('missing memprof_stats row for test VM')
PY

export FLUXVM_INTEL_PIN_ROOT="$PIN"
export FLUXVM_MEMPROF_MARKER_ROOT="$TMP/markers"
export FLUXVM_MEMPROF_LOADER="$TMP/mem-loader"
export FLUXVM_MEMPROF_BPF_OBJECT="$TMP/bpf/fluxvm_memprof.bpf.o"
mkdir -p "$TMP/markers"
cargo run -q -p fluxvm-intelligence --bin fluxvm-memprof -- mark "$UUID" snapshot-begin >/dev/null
sleep 0.05
cargo run -q -p fluxvm-intelligence --bin fluxvm-memprof -- mark "$UUID" snapshot-end >/dev/null
MARKER="$TMP/markers/$UUID.json"
python3 - "$MARKER" <<'PY'
import json,sys
m=json.load(open(sys.argv[1]))['markers_ns']
assert m['snapshot-end']>m['snapshot-begin']
print('monotonic snapshot markers: PASS')
PY

echo 'Memory + boot profiler privileged host test: PASS'
