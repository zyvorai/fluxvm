#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Time POST /v1/pools/{name}/claim separately from a cold POST /v1/vms.
# Requires a running fluxctl serve and a pool that already has a ready member.
# Linux + KVM. Exits 0 on other hosts so a baseline recorder can keep going.
#
#   POOL=bench API=http://127.0.0.1:7788 ./scripts/bench-warm-claim.sh

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-warm-claim: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
if [[ ! -e /dev/kvm ]]; then
  echo "bench-warm-claim: /dev/kvm missing (skipped)" >&2
  exit 0
fi

API="${FLUXVM_API:-http://127.0.0.1:7788}"
POOL="${POOL:-bench}"
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

if ! curl -sf "${API}/readyz" "${AUTH_HDR[@]}" >/dev/null; then
  echo "bench-warm-claim: ${API}/readyz is not up (skipped)" >&2
  exit 0
fi

t0=$(date +%s%3N)
body=$(curl -sf -X POST "${API}/v1/pools/${POOL}/claim" \
  "${AUTH_HDR[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"warm-claim-$RANDOM\"}" || true)
t1=$(date +%s%3N)
ms=$((t1 - t0))
id=$(printf '%s' "$body" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("id") or "")
except Exception:
    print("")' 2>/dev/null || true)

echo "warm_claim_ms=${ms}"
echo "warm_claim_id=${id:-none}"
if [[ -z "$id" ]]; then
  echo "warm_claim_error=${body}" >&2
  exit 1
fi
echo "note=warm_claim_ms is pool claim latency, not cold create and not guest init"
