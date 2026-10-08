#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Density count: boot VMs of a fixed size one at a time until create is
# refused, host MemAvailable falls below a safety floor, or MAX is reached.
# Records the count, the host MemAvailable delta and per-VM PSS (from
# GET /v1/vms/{id}/memory). Prints a JSON summary.
#
# This CONSUMES HOST MEMORY, so it refuses to run unless
# FLUXVM_BENCH_CONFIRM=1. It only ever deletes VMs it created itself
# (tracked by id; never by name pattern) and never touches other VMs.
#
#   FLUXVM_BENCH_CONFIRM=1 MODE=TUNED MEM_MIB=256 MAX=20 \
#     ./scripts/bench-density-count.sh
#
# MODE is a label for the SERVER configuration this script cannot change:
#   BASELINE  no idle balloon ([sandbox] idle_balloon_secs = 0) and eager
#             restore (server started with FLUXVM_KVM_EAGER_RESTORE=1)
#   TUNED     idle balloon on ([sandbox] idle_balloon_secs > 0), default
#             lazy (copy-on-write) restore
# Set FLUXVM_CONFIG to the server's config file and the idle_balloon_secs
# part is checked against MODE (the eager-restore env is not checkable here).
#
# Env: MEM_MIB (256), MAX (20), MIN_AVAIL_MIB floor (2048, required safety
# floor; refusing anything below 512), SETTLE_SECS (5), IMAGE, KERNEL,
# FLUXVM_API, FLUXVM_TOKEN.
set -euo pipefail

if [[ "${FLUXVM_BENCH_CONFIRM:-}" != "1" ]]; then
  echo "bench-density-count: refusing to run: this consumes host memory." >&2
  echo "bench-density-count: set FLUXVM_BENCH_CONFIRM=1 to proceed." >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-density-count: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
[[ -e /dev/kvm ]] || { echo "bench-density-count: /dev/kvm missing" >&2; exit 0; }

API="${FLUXVM_API:-http://127.0.0.1:7788}"
MODE="${MODE:-BASELINE}"
MEM_MIB="${MEM_MIB:-256}"
MAX="${MAX:-20}"
FLOOR_MIB="${MIN_AVAIL_MIB:-2048}"
SETTLE="${SETTLE_SECS:-5}"
IMAGE="${IMAGE:-${FLUXVM_BENCH_IMAGE:-/var/lib/fluxvm/images/base.raw}}"
KERNEL="${KERNEL:-${FLUXVM_BENCH_KERNEL:-/var/lib/fluxvm/kernels/vmlinux}}"
PREFIX="densitycount-$$"
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

case "$MODE" in
  BASELINE | TUNED) ;;
  *) echo "bench-density-count: MODE must be BASELINE or TUNED" >&2; exit 2 ;;
esac
if ! [[ "$MEM_MIB" =~ ^[0-9]+$ && "$MAX" =~ ^[0-9]+$ && "$FLOOR_MIB" =~ ^[0-9]+$ ]]; then
  echo "bench-density-count: MEM_MIB, MAX and MIN_AVAIL_MIB must be integers" >&2
  exit 2
fi
if ((FLOOR_MIB < 512)); then
  echo "bench-density-count: MIN_AVAIL_MIB below 512 is refused (safety floor)" >&2
  exit 2
fi
[[ -f "$IMAGE" ]] || { echo "bench-density-count: IMAGE not found: $IMAGE" >&2; exit 1; }

# Verify the balloon half of MODE when the server config file is known.
mode_verified="unverified"
if [[ -n "${FLUXVM_CONFIG:-}" && -r "${FLUXVM_CONFIG}" ]]; then
  secs=$(awk -F= '/^[[:space:]]*idle_balloon_secs[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$FLUXVM_CONFIG")
  secs="${secs:-0}"
  if [[ "$MODE" == "BASELINE" && "$secs" != "0" ]] || [[ "$MODE" == "TUNED" && "$secs" == "0" ]]; then
    echo "bench-density-count: MODE=${MODE} contradicts idle_balloon_secs=${secs} in ${FLUXVM_CONFIG}" >&2
    exit 2
  fi
  mode_verified="idle_balloon_secs=${secs}"
fi

curl -sf "${API}/readyz" "${AUTH_HDR[@]}" >/dev/null || {
  echo "bench-density-count: ${API}/readyz is not up" >&2
  exit 1
}

avail_mib() {
  awk '/^MemAvailable:/ {printf "%d\n", $2 / 1024; exit}' /proc/meminfo
}

KERNEL_JSON="null"
if [[ -f "$KERNEL" ]]; then
  KERNEL_JSON=$(printf '%s' "$KERNEL" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
fi

WORKDIR=$(mktemp -d)
CREATED_IDS=()
cleanup() {
  local id
  # Only ids this script created; never delete by pattern.
  for id in "${CREATED_IDS[@]}"; do
    curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

start_avail=$(avail_mib)
if ((start_avail < FLOOR_MIB)); then
  echo "bench-density-count: MemAvailable ${start_avail} MiB already below floor ${FLOOR_MIB} MiB; not starting" >&2
  exit 1
fi
echo "bench-density-count: mode=${MODE} mem=${MEM_MIB}MiB max=${MAX} floor=${FLOOR_MIB}MiB start_avail=${start_avail}MiB" >&2

stop_reason="max_reached"
count=0
: >"$WORKDIR/pss.txt"
for ((i = 1; i <= MAX; i++)); do
  cur=$(avail_mib)
  if ((cur < FLOOR_MIB)); then
    stop_reason="below_floor"
    break
  fi
  # Refuse to create if this VM alone could push us under the floor.
  if ((cur - MEM_MIB < FLOOR_MIB)); then
    stop_reason="below_floor"
    break
  fi
  name="${PREFIX}-${i}"
  if ! body=$(curl -sf -X POST "${API}/v1/vms" "${AUTH_HDR[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"${name}\",\"backend\":\"flux-vm\",\"image\":\"${IMAGE}\",\"kernel\":${KERNEL_JSON},\"vcpus\":1,\"memory_mib\":${MEM_MIB}}"); then
    stop_reason="create_refused"
    break
  fi
  id=$(printf '%s' "$body" | jq -r '.id // empty')
  if [[ -z "$id" ]]; then
    stop_reason="create_refused"
    break
  fi
  CREATED_IDS+=("$id")
  count=$((count + 1))
  sleep "$SETTLE"
  pss=$(curl -sf "${API}/v1/vms/${id}/memory" "${AUTH_HDR[@]}" | jq -r '.usage.pss_kib // empty' || true)
  echo "${id} ${pss:-null}" >>"$WORKDIR/pss.txt"
  echo "bench-density-count: vm ${count} ${id} pss_kib=${pss:-n/a} avail=$(avail_mib)MiB" >&2
done

sleep "$SETTLE"
end_avail=$(avail_mib)
final_floor_hit="false"
if ((end_avail < FLOOR_MIB)); then final_floor_hit="true"; fi

python3 - "$WORKDIR/pss.txt" "$MODE" "$mode_verified" "$MEM_MIB" "$MAX" "$FLOOR_MIB" \
  "$count" "$stop_reason" "$start_avail" "$end_avail" "$final_floor_hit" <<'PY'
import json, sys

(path, mode, verified, mem, mx, floor, count, reason, start, end, hit) = sys.argv[1:]
per_vm = []
for line in open(path):
    vm_id, pss = line.split()
    per_vm.append({"id": vm_id, "pss_kib": None if pss == "null" else int(pss)})
pss_vals = [p["pss_kib"] for p in per_vm if p["pss_kib"] is not None]
start, end = int(start), int(end)
print(json.dumps({
    "mode": mode,
    "mode_config_check": verified,
    "mem_mib": int(mem),
    "max": int(mx),
    "floor_mib": int(floor),
    "count": int(count),
    "stop_reason": reason,
    "below_floor_at_end": hit == "true",
    "host_mem_available_start_mib": start,
    "host_mem_available_end_mib": end,
    "host_mem_available_delta_mib": start - end,
    "host_delta_per_vm_mib": round((start - end) / int(count), 1) if int(count) else None,
    "pss_avg_kib": round(sum(pss_vals) / len(pss_vals)) if pss_vals else None,
    "pss_total_kib": sum(pss_vals),
    "per_vm": per_vm,
}, indent=2))
PY
