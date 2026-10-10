#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end smoke test of agent sandboxes on a Mac, against a running `fluxctl serve`:
# health, a default (warm-pool) sandbox, COUNT sandboxes of PROFILE, a command and a file round trip in each, the density report,
# the metrics, and cleanup. With AGENT_MICRO=1 one sandbox uses the agent-micro image and must be answered by the guest agent.
#
#   scripts/e2e-smoke.sh            (FLUXVM_URL, default http://127.0.0.1:7788; FLUXVM_TOKEN if auth is on; COUNT=2, PROFILE=tiny)
set -euo pipefail

URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
COUNT="${COUNT:-2}"
PROFILE="${PROFILE:-tiny}"
AUTH=()
[[ -n "${FLUXVM_TOKEN:-}" ]] && AUTH=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
call() { curl -sf ${AUTH[@]+"${AUTH[@]}"} -H 'Content-Type: application/json' "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

ids=()
cleanup() { for id in ${ids[@]+"${ids[@]}"}; do call -X DELETE "$URL/v1/vms/$id" >/dev/null || true; done; }
trap cleanup EXIT

created=""
create() {   # body; sets $created (not a subshell, so cleanup sees every id)
  local t0
  t0=$(date +%s)
  created=$(call -X POST "$URL/v1/sandboxes" -d "$1" | jq -r .id) || fail "create $1"
  [[ -n "$created" && "$created" != null ]] || fail "create $1 returned no id"
  ids+=("$created")
  echo "  created $created in $(( $(date +%s) - t0 )) s: $1"
}

check() {    # id: a command and a file round trip
  local id=$1 out data
  out=$(call -X POST "$URL/v1/sandboxes/$id/process" -d '{"command":"echo ok; exit 3"}')
  [[ $(jq -r .exit_code <<<"$out") == 3 && $(jq -r .stdout <<<"$out") == "ok" ]] || fail "exec in $id: $out"
  data=$(printf 'smoke %s' "$id" | base64)
  call -X POST "$URL/v1/sandboxes/$id/fs/write" -d "{\"path\":\"/tmp/smoke.txt\",\"content_base64\":\"$data\"}" >/dev/null \
    || fail "write in $id"
  out=$(call -X POST "$URL/v1/sandboxes/$id/fs/read" -d '{"path":"/tmp/smoke.txt"}')
  [[ $(jq -r .content_base64 <<<"$out") == "$data" ]] || fail "read back in $id: $out"
  echo "  $id: exec and files ok"
}

echo "== health"
call "$URL/healthz" >/dev/null || fail "no daemon at $URL"

echo "== default sandbox (warm pool)"
create '{"ttl_seconds":300}'; check "$created"

echo "== $COUNT $PROFILE sandboxes"
for _ in $(seq 1 "$COUNT"); do
  create "{\"profile\":\"$PROFILE\",\"ttl_seconds\":300}"; check "$created"
done

if [[ "${AGENT_MICRO:-0}" == 1 ]]; then
  echo "== agent-micro sandbox (guest agent over vsock)"
  before=$(call "$URL/metrics" | awk '/^fluxvm_vz_agent_calls_total /{print $2}')
  create '{"image":"agent-micro","profile":"tiny","offline":true,"ttl_seconds":300}'; check "$created"
  after=$(call "$URL/metrics" | awk '/^fluxvm_vz_agent_calls_total /{print $2}')
  (( after > before )) || fail "agent-micro requests were not answered by the guest agent (fell back to SSH)"
fi

echo "== density"
call "$URL/v1/sandboxes/density" | jq .

echo "== metrics"
call "$URL/metrics" | grep -E '^fluxvm_(sandbox_|vz_agent_|host_mem)' || true

echo "PASS"
