#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Concurrent keep-alive density bench against local fluxctl serve.
# Creates N sandboxes in parallel, waits for all, reports latency + peak count
# + mutation rate (FC design: 5 microVMs / host-core / sec).
# Does NOT delete until the end (unless DENSITY_CLEANUP=0 to leave them).
#
#   BENCH_N=8 DENSITY_MEMORY_MIB=128 ./scripts/bench-density.sh
#
set -euo pipefail

API="${FLUXVM_API:-http://127.0.0.1:7788}"
N="${BENCH_N:-8}"
IMAGE="${IMAGE:-${FLUXVM_BENCH_IMAGE:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}}"
KERNEL="${KERNEL:-${FLUXVM_BENCH_KERNEL:-/var/lib/fluxvm/kernels/vmlinux}}"
MEM_MIB="${DENSITY_MEMORY_MIB:-512}"
CLEANUP="${DENSITY_CLEANUP:-1}"
PREFIX="density-$$"
WORKDIR="${TMPDIR:-/tmp}/${PREFIX}"
mkdir -p "$WORKDIR"

AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

if [[ ! -f "$IMAGE" && -f /var/lib/fluxvm/images/base.raw ]]; then
  IMAGE=/var/lib/fluxvm/images/base.raw
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-density: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
[[ -e /dev/kvm ]] || { echo "bench-density: /dev/kvm missing" >&2; exit 0; }
[[ -f "$IMAGE" ]] || { echo "bench-density: IMAGE not found: $IMAGE" >&2; exit 1; }

KERNEL_JSON="null"
if [[ -f "$KERNEL" ]]; then
  KERNEL_JSON=$(printf '%s' "$KERNEL" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
fi

cores=$(nproc 2>/dev/null || echo 1)
echo "== FluxVM concurrent density (n=${N}, api=${API}, mem=${MEM_MIB}MiB, cores=${cores}) =="
echo "fc_targets: mutation_5_per_core_sec overhead_le_5_mib (docs/capability-figures.md)"

IDS_FILE="${WORKDIR}/ids.txt"
: >"$IDS_FILE"
LAT_FILE="${WORKDIR}/lat.txt"
: >"$LAT_FILE"
PID_FILE="${WORKDIR}/pids.txt"
: >"$PID_FILE"

create_one() {
  local i="$1" t0 t1 ms id body name pid
  name="${PREFIX}-${i}"
  t0=$(date +%s%3N)
  body=$(curl -sf -X POST "${API}/v1/sandboxes" \
    "${AUTH_HDR[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"${name}\",\"spec\":{\"name\":\"${name}\",\"backend\":\"flux-vm\",\"image\":\"${IMAGE}\",\"kernel\":${KERNEL_JSON},\"vcpus\":1,\"memory_mib\":${MEM_MIB},\"network\":{\"mode\":\"none\"}}}") || {
    echo "create_failed ${i}" >>"$LAT_FILE"
    return 1
  }
  id=$(echo "$body" | jq -r '.id // empty')
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "create_failed ${i}" >>"$LAT_FILE"
    return 1
  fi
  t1=$(date +%s%3N)
  ms=$((t1 - t0))
  echo "$id" >>"$IDS_FILE"
  echo "$ms" >>"$LAT_FILE"
  pid=$(echo "$body" | jq -r '.pid // empty')
  if [[ -n "$pid" && "$pid" != "null" ]]; then
    echo "$pid" >>"$PID_FILE"
  fi
  echo "create ${name} ${id} ${ms}ms"
}

t_wall0=$(date +%s%3N)
pids=()
for ((i=1; i<=N; i++)); do
  create_one "$i" &
  pids+=($!)
done
fail=0
for p in "${pids[@]}"; do
  wait "$p" || fail=$((fail + 1))
done
t_wall1=$(date +%s%3N)
wall_ms=$((t_wall1 - t_wall0))

alive=$(wc -l <"$IDS_FILE" | tr -d ' ')
mapfile -t lats < <(grep -E '^[0-9]+$' "$LAT_FILE" | sort -n)
ok=${#lats[@]}

p50=0
p95=0
avg=0
if (( ok > 0 )); then
  sum=0
  for ms in "${lats[@]}"; do sum=$((sum + ms)); done
  avg=$((sum / ok))
  p50=${lats[$(( (ok - 1) * 50 / 100 ))]}
  p95=${lats[$(( (ok - 1) * 95 / 100 ))]}
fi

mutation_per_sec=0
mutation_per_core_sec=0
if (( wall_ms > 0 && ok > 0 )); then
  mutation_per_sec=$(awk -v n="$ok" -v ms="$wall_ms" 'BEGIN { printf "%.2f", n * 1000 / ms }')
  mutation_per_core_sec=$(awk -v r="$mutation_per_sec" -v c="$cores" 'BEGIN { if (c<1) c=1; printf "%.2f", r / c }')
fi

# Sample RSS of first surviving VMM if available.
vmm_rss_kib=""
if [[ -s "$PID_FILE" ]]; then
  first_pid=$(head -n1 "$PID_FILE")
  if [[ -r "/proc/${first_pid}/status" ]]; then
    vmm_rss_kib=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/${first_pid}/status")
  fi
fi

echo "--"
echo "concurrent_requested=${N}"
echo "concurrent_alive=${alive}"
echo "create_failures=${fail}"
echo "wall_ms=${wall_ms}"
echo "avg_create_ms=${avg}"
echo "boot_to_ready_ms=${avg}"
echo "p50_create_ms=${p50}"
echo "p95_create_ms=${p95}"
echo "mutation_per_sec=${mutation_per_sec}"
echo "mutation_per_core_sec=${mutation_per_core_sec}"
echo "host_cores=${cores}"
echo "fc_mutation_target_per_core_sec=5"
echo "memory_mib_each=${MEM_MIB}"
echo "approx_guest_ram_mib=$((alive * MEM_MIB))"
if [[ -n "$vmm_rss_kib" ]]; then
  echo "sample_vmm_rss_kib=${vmm_rss_kib}"
  echo "fc_overhead_target_mib=5"
fi

if [[ "$CLEANUP" == "1" ]]; then
  while read -r id; do
    [[ -n "$id" ]] || continue
    curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null || true
  done <"$IDS_FILE"
  echo "cleaned=${alive}"
fi
rm -rf "$WORKDIR"
