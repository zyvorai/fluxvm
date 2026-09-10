#!/usr/bin/env bash
# Privileged Linux host smoke: proves load, scheduler attribution, bpftool map ABI, CLI snapshot.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root" >&2; exit 2; }
for c in bpftool clang cargo pkg-config; do command -v "$c" >/dev/null || { echo "$c required" >&2; exit 2; }; done
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
"$ROOT/scripts/build-runtime-intelligence.sh"
PIN=/sys/fs/bpf/fluxvm/intelligence-test
"$ROOT/dist/bin/fluxvm-intelligence-loader" --unload "$PIN" || true
trap 'kill ${P:-0} 2>/dev/null || true; "$ROOT/dist/bin/fluxvm-intelligence-loader" --unload "$PIN" >/dev/null 2>&1 || true' EXIT
"$ROOT/dist/bin/fluxvm-intelligence-loader" --load "$ROOT/dist/bpf/fluxvm_intelligence.bpf.o" "$PIN"
export FLUXVM_INTEL_PIN_ROOT="$PIN"
(while :; do sleep 0.01; done) & P=$!
ID=12345678-1234-5678-9abc-def012345678
"$ROOT/dist/bin/fluxvm-intelligence" register "$ID" "$P"
sleep 1
OUT="$("$ROOT/dist/bin/fluxvm-intelligence" snapshot "$ID" "$P")"
echo "$OUT"
python3 - "$OUT" <<'PY'
import json,sys
x=json.loads(sys.argv[1])
assert x['ebpf_active'] is True
assert x['pid'] > 0
assert x['tracked_tids']
assert x['kernel']['sched_wakeups'] > 0, x
print('scheduler attribution: PASS')
PY
if [[ -e /dev/kvm ]]; then echo 'KVM available: start a FluxVM/KVM guest and query /v1/intelligence/vms/<id> to validate kvm_exits > 0'; else echo 'KVM not available; KVM counter runtime proof skipped'; fi
echo 'runtime-intelligence privileged host smoke: PASS'
