#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Rough sandbox cold-start / density benchmark against a local fluxctl serve.
# Requires Linux + KVM + fluxvm built.
#
# Optional:
#   REPORT_RSS=1     sample VMM VmRSS after create (FC-comparable overhead)
#   MEMORY_MIB=128   guest RAM (FC SPEC uses 128 MiB)
#   KEEP_LAST=1      leave the last sandbox running for RSS sampling

set -euo pipefail

API="${FLUXVM_API:-http://127.0.0.1:7788}"
N="${BENCH_N:-5}"
IMAGE="${IMAGE:-${FLUXVM_BENCH_IMAGE:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}}"
KERNEL="${KERNEL:-${FLUXVM_BENCH_KERNEL:-/var/lib/fluxvm/kernels/vmlinux}}"
MEM_MIB="${MEMORY_MIB:-512}"
REPORT_RSS="${REPORT_RSS:-0}"
KEEP_LAST="${KEEP_LAST:-0}"
# Optional bearer (lab/prod with auth.require). Prefer FLUXVM_TOKEN; never commit tokens.
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi
# Fallbacks if lab still uses the old placeholder path.
if [[ ! -f "$IMAGE" && -f /var/lib/fluxvm/images/base.raw ]]; then
  IMAGE=/var/lib/fluxvm/images/base.raw
fi
if [[ ! -f "$IMAGE" && -f /var/lib/fluxvm/images/ubuntu-22.04.ext4 ]]; then
  IMAGE=/var/lib/fluxvm/images/ubuntu-22.04.ext4
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-sandbox: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi

if [[ ! -e /dev/kvm ]]; then
  echo "bench-sandbox: /dev/kvm missing — enable virtualization first" >&2
  exit 0
fi

if [[ ! -f "$IMAGE" ]]; then
  echo "bench-sandbox: IMAGE not found: $IMAGE (set IMAGE=…)" >&2
  exit 1
fi

KERNEL_JSON="null"
if [[ -f "$KERNEL" ]]; then
  KERNEL_JSON=$(printf '%s' "$KERNEL" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
else
  echo "bench-sandbox: KERNEL missing ($KERNEL) — relying on config.fluxvm_kernel" >&2
fi

echo "== FluxVM sandbox benchmark (n=${N}, api=${API}, mem=${MEM_MIB}MiB, image=${IMAGE}, kernel=${KERNEL}) =="
echo "fc_targets: overhead_le_5_mib boot_le_125_ms (see docs/capability-figures.md)"

sample_rss_kib() {
  local pid="$1"
  [[ -n "$pid" && "$pid" != "null" && -r "/proc/${pid}/status" ]] || return 1
  awk '/^VmRSS:/ {print $2; exit}' "/proc/${pid}/status"
}

create_one() {
  local t0 t1 ms id body keep="$1"
  t0=$(date +%s%3N)
  body=$(curl -sf -X POST "${API}/v1/sandboxes" \
    "${AUTH_HDR[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"bench-$RANDOM\",\"spec\":{\"name\":\"b\",\"backend\":\"flux-vm\",\"image\":\"${IMAGE}\",\"kernel\":${KERNEL_JSON},\"vcpus\":1,\"memory_mib\":${MEM_MIB},\"network\":{\"mode\":\"none\"}}}")
  id=$(echo "$body" | jq -r '.id // empty')
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "create failed: $body" >&2
    return 1
  fi
  t1=$(date +%s%3N)
  ms=$((t1 - t0))
  echo "create ${id} ${ms}ms"
  if [[ "$keep" == "1" ]]; then
    LAST_ID="$id"
    LAST_PID=$(echo "$body" | jq -r '.pid // empty')
    if [[ -z "$LAST_PID" || "$LAST_PID" == "null" ]]; then
      LAST_PID=$(curl -sf "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" | jq -r '.pid // empty')
    fi
  else
    curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null || true
  fi
}

LAST_ID=""
LAST_PID=""
total=0
t_wall0=$(date +%s%3N)
for ((i=1; i<=N; i++)); do
  keep=0
  if [[ "$KEEP_LAST" == "1" || "$REPORT_RSS" == "1" ]] && (( i == N )); then
    keep=1
  fi
  line=$(create_one "$keep")
  echo "$line"
  ms=$(echo "$line" | awk '{print $3}' | tr -d ms)
  total=$((total + ms))
done
t_wall1=$(date +%s%3N)
wall_ms=$((t_wall1 - t_wall0))

avg=$((total / N))
# Approximate mutation rate for sequential creates (FC design: 5 / core / sec).
mutation_per_sec=0
if (( wall_ms > 0 )); then
  mutation_per_sec=$(awk -v n="$N" -v ms="$wall_ms" 'BEGIN { printf "%.2f", n * 1000 / ms }')
fi
cores=$(nproc 2>/dev/null || echo 1)
mutation_per_core_sec=$(awk -v r="$mutation_per_sec" -v c="$cores" 'BEGIN { if (c<1) c=1; printf "%.2f", r / c }')

echo "--"
echo "avg_create_ms=${avg}"
echo "boot_to_ready_ms=${avg}"
echo "wall_ms=${wall_ms}"
echo "mutation_per_sec=${mutation_per_sec}"
echo "mutation_per_core_sec=${mutation_per_core_sec}"
echo "host_cores=${cores}"
echo "memory_mib=${MEM_MIB}"
echo "image=${IMAGE}"

if [[ "$REPORT_RSS" == "1" && -n "${LAST_PID:-}" ]]; then
  if rss=$(sample_rss_kib "$LAST_PID"); then
    # Rough VMM overhead: process RSS minus guest RAM (guest pages often
    # appear in the VMM RSS for Firecracker). Prefer comparing bare FC
    # child RSS on a 128 MiB guest against the ≤5 MiB SPEC when the
    # engine is firecracker and guest pages are not yet touched.
    overhead_kib=$((rss > MEM_MIB * 1024 ? rss - MEM_MIB * 1024 : rss))
    overhead_mib=$(awk -v k="$overhead_kib" 'BEGIN { printf "%.2f", k / 1024 }')
    echo "vmm_pid=${LAST_PID}"
    echo "vmm_rss_kib=${rss}"
    echo "vmm_overhead_mib_approx=${overhead_mib}"
    echo "fc_overhead_target_mib=5"
  else
    echo "vmm_rss_kib=unavailable (pid=${LAST_PID:-none})"
  fi
fi

if [[ -n "$LAST_ID" && "$KEEP_LAST" != "1" ]]; then
  curl -sf -X DELETE "${API}/v1/vms/${LAST_ID}" "${AUTH_HDR[@]}" >/dev/null || true
fi
