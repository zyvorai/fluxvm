#!/usr/bin/env bash
# Create COUNT sandboxes of PROFILE on a running daemon, run a command in each, print the density report, delete them.
# Usage: scripts/density-smoke.sh [COUNT] [PROFILE]     (FLUXVM_URL, default http://127.0.0.1:7788; FLUXVM_TOKEN if auth is on)
set -euo pipefail

COUNT="${1:-4}"
PROFILE="${2:-tiny}"
URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
AUTH=()
[[ -n "${FLUXVM_TOKEN:-}" ]] && AUTH=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")

call() { curl -sf ${AUTH[@]+"${AUTH[@]}"} -H 'Content-Type: application/json' "$@"; }

ids=()
cleanup() { for id in ${ids[@]+"${ids[@]}"}; do call -X DELETE "$URL/v1/vms/$id" >/dev/null || true; done; }
trap cleanup EXIT

echo "creating $COUNT $PROFILE sandboxes"
for i in $(seq 1 "$COUNT"); do
  start=$(date +%s)
  id=$(call -X POST "$URL/v1/sandboxes" -d "{\"name\":\"density-$i-$$\",\"profile\":\"$PROFILE\",\"ttl_seconds\":600}" | jq -r .id)
  ids+=("$id")
  echo "  density-$i: $id ($(( $(date +%s) - start )) s)"
done

for id in "${ids[@]}"; do
  out=$(call -X POST "$URL/v1/sandboxes/$id/process" -d '{"command":"nproc; free -m | awk \"/Mem:/{print \\$2}\""}' | jq -r .stdout | tr '\n' ' ')
  echo "  $id: vcpus/mem_mib $out"
done

echo "density report"
call "$URL/v1/sandboxes/density" | jq .
