#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN="/sys/fs/bpf/fluxvm-flight-test-$$"
UUID="12345678-1234-5678-9abc-def012345678"
TMP="/var/tmp/fluxvm-flight-test-$$.dat"
PID=""
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  "$ROOT/dist/bin/fluxvm-intelligence-loader" --unload "$PIN" 2>/dev/null || true
  rm -f "$TMP"
}
trap cleanup EXIT
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root" >&2; exit 2; }
for c in bpftool clang cargo pkg-config python3; do command -v "$c" >/dev/null || { echo "$c required" >&2; exit 2; }; done
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

"$ROOT/scripts/build-runtime-intelligence.sh"
"$ROOT/dist/bin/fluxvm-intelligence-loader" --load "$ROOT/dist/bpf/fluxvm_intelligence.bpf.o" "$PIN"
for map in tracked_tgids tracked_tids tracked_cgroups vm_stats kvm_exit_hist latency_hist block_requests flight_counts flight_events; do
  [[ -e "$PIN/maps/$map" ]] || { echo "missing pinned map $map" >&2; exit 1; }
done

# A single long-lived process performs its own writes/fsyncs so any direct
# block submission remains attributable to the registered TID/cgroup.
python3 - "$TMP" <<'PY' &
import os, sys, time
p=sys.argv[1]
with open(p,'wb', buffering=0) as f:
    block=b'x'*(1024*1024)
    while True:
        f.write(block); f.flush(); os.fsync(f.fileno()); f.seek(0); time.sleep(0.01)
PY
PID=$!
FLUXVM_INTEL_PIN_ROOT="$PIN" "$ROOT/target/release/fluxvm-intelligence" register "$UUID" "$PID" >/tmp/fluxvm-flight-register.json
sleep 2
FLUXVM_INTEL_PIN_ROOT="$PIN" "$ROOT/target/release/fluxvm-intelligence" snapshot "$UUID" "$PID" >/tmp/fluxvm-flight-snapshot.json
python3 - <<'PY'
import json
p=json.load(open('/tmp/fluxvm-flight-snapshot.json'))
assert p['ebpf_active'] is True, p
assert p.get('flight',{}).get('available') is True, p
assert p['tracked_tids'], p
print('snapshot Flight Recorder maps: PASS')
PY

# The ring reader must be able to open/consume the production ringbuf even if
# this particular host/filesystem produced no thresholded event in the window.
"$ROOT/dist/bin/fluxvm-flight-reader" --map "$PIN/maps/flight_events" \
  --vm-key "$(python3 - <<'PY'
h=0xcbf29ce484222325
import uuid
for b in uuid.UUID('12345678-1234-5678-9abc-def012345678').bytes:
    h ^= b; h=(h*0x100000001b3)&((1<<64)-1)
print(h or 1)
PY
)" --seconds 1 --limit 4 >/tmp/fluxvm-flight-events.jsonl

# If the host attached block probes and the backing filesystem reached block
# layer in the observation window, insist that completions produced latency.
python3 - <<'PY'
import json
p=json.load(open('/tmp/fluxvm-flight-snapshot.json'))
f=p['flight']; c=f['counters']
if c['block_completed']:
    assert any(b['kind']=='block-io' and b['count'] for b in f['latency']), f
    print('block latency attribution: PASS')
else:
    print('block latency attribution: SKIP (no attributable block completion on this host/filesystem)')
PY

if [[ -e /dev/kvm ]]; then
  echo "KVM is available. Run a FluxVM guest during this test to validate per-vCPU exit_reason counters end-to-end."
else
  echo "KVM exit live counter: SKIP (/dev/kvm unavailable)"
fi

echo "Flight Recorder privileged host smoke: PASS"
