#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Rough sandbox cold-start / density benchmark against a local fluxvm serve.
# Requires Linux + KVM + fluxvm built.

set -euo pipefail

API="${FLUXVM_API:-http://127.0.0.1:7788}"
N="${BENCH_N:-5}"
IMAGE="${IMAGE:-${FLUXVM_BENCH_IMAGE:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}}"
KERNEL="${KERNEL:-${FLUXVM_BENCH_KERNEL:-/var/lib/fluxvm/kernels/vmlinux}}"
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

echo "== FluxVM sandbox benchmark (n=${N}, api=${API}, image=${IMAGE}, kernel=${KERNEL}) =="

create_one() {
  local t0 t1 ms id body
  t0=$(date +%s%3N)
  body=$(curl -sf -X POST "${API}/v1/sandboxes" \
    "${AUTH_HDR[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"bench-$RANDOM\",\"spec\":{\"name\":\"b\",\"backend\":\"flux-vm\",\"image\":\"${IMAGE}\",\"kernel\":${KERNEL_JSON},\"vcpus\":1,\"memory_mib\":512,\"network\":{\"mode\":\"none\"}}}")
  id=$(echo "$body" | jq -r '.id // empty')
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "create failed: $body" >&2
    return 1
  fi
  t1=$(date +%s%3N)
  ms=$((t1 - t0))
  echo "create ${id} ${ms}ms"
  curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null || true
}

total=0
for ((i=1; i<=N; i++)); do
  line=$(create_one)
  echo "$line"
  ms=$(echo "$line" | awk '{print $3}' | tr -d ms)
  total=$((total + ms))
done

avg=$((total / N))
echo "--"
echo "avg_create_ms=${avg}"
echo "image=${IMAGE}"
