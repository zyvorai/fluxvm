#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Time POST /v1/vms/{id}/fork for COUNT children of one running flux-vm VM,
# then delete the children (KEEP=1 keeps them).
# Requires a running fluxctl serve and a running VM on the flux-vm backend.
# Linux + KVM. Exits 0 on other hosts so a baseline recorder can keep going.
#
#   VM=<uuid> COUNT=8 API=http://127.0.0.1:7788 ./scripts/bench-fork.sh

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-fork: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
if [[ ! -e /dev/kvm ]]; then
  echo "bench-fork: /dev/kvm missing (skipped)" >&2
  exit 0
fi

API="${FLUXVM_API:-http://127.0.0.1:7788}"
VM="${VM:?set VM to the UUID of a running flux-vm VM}"
COUNT="${COUNT:-8}"
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

if ! curl -sf "${API}/readyz" "${AUTH_HDR[@]}" >/dev/null; then
  echo "bench-fork: ${API}/readyz is not up (skipped)" >&2
  exit 0
fi

t0=$(date +%s%3N)
body=$(curl -sf -X POST "${API}/v1/vms/${VM}/fork" \
  "${AUTH_HDR[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"count\":${COUNT},\"namePrefix\":\"bench-fork-$RANDOM\"}" || true)
t1=$(date +%s%3N)
ms=$((t1 - t0))

ids=$(printf '%s' "$body" | python3 -c 'import json,sys
try:
    for vm in json.load(sys.stdin).get("items", []):
        print(vm["id"])
except Exception:
    pass' 2>/dev/null || true)
server_ms=$(printf '%s' "$body" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("elapsed_ms", ""))
except Exception:
    print("")' 2>/dev/null || true)
n=$(printf '%s\n' "$ids" | grep -c . || true)

echo "fork_count=${n}"
echo "fork_total_ms=${ms}"
echo "fork_server_ms=${server_ms:-none}"
if [[ "$n" -gt 0 ]]; then
  echo "fork_per_child_ms=$((ms / n))"
fi
if [[ "$n" -ne "$COUNT" ]]; then
  echo "fork_error=${body}" >&2
  exit 1
fi

if [[ "${KEEP:-0}" != "1" ]]; then
  while read -r id; do
    [[ -n "$id" ]] && curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null || true
  done <<<"$ids"
fi
echo "note=fork_total_ms covers parent snapshot, ${COUNT} reflinked disks and ${COUNT} memory restores; not guest init"
