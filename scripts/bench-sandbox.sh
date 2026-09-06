#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Rough sandbox cold-start / density benchmark against a local fluxvm serve.
# Requires Linux + KVM + fluxvm built. Placeholder-friendly when no hardware.

set -euo pipefail

API="${FLUXVM_API:-http://127.0.0.1:7788}"
N="${BENCH_N:-5}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-sandbox: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi

if [[ ! -e /dev/kvm ]]; then
  echo "bench-sandbox: /dev/kvm missing — enable virtualization first" >&2
  exit 0
fi

echo "== FluxVM sandbox benchmark (n=${N}, api=${API}) =="

create_one() {
  local t0 t1 ms id
  t0=$(date +%s%3N)
  id=$(curl -sf -X POST "${API}/v1/sandboxes" \
    -H 'Content-Type: application/json' \
    -d '{"name":"bench-'"$RANDOM"'","spec":{"name":"b","backend":"flux-vm","image":"/var/lib/fluxvm/images/base.raw","vcpus":1,"memory_mib":512,"network":{"mode":"none"}}}' \
    | jq -r '.id')
  t1=$(date +%s%3N)
  ms=$((t1 - t0))
  echo "create ${id} ${ms}ms"
  curl -sf -X DELETE "${API}/v1/vms/${id}" >/dev/null || true
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
echo "avg_create_ms=${avg} (placeholder — tune image path and engine in spec)"
