#!/usr/bin/env bash
# Live-node Set 15 telemetry gate. This script does not create policy by itself;
# it validates that an already-running Secure Containers workload is visible in
# the observer and that both directional hooks are healthy.
set -euo pipefail

: "${OBSERVER_URL:=http://127.0.0.1:9091}"
: "${POD_ID:?set POD_ID to the numeric FluxVM Pod identity to validate}"
: "${VM_ID:=}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 2; }; }
need curl

metrics="$(curl -fsS "$OBSERVER_URL/metrics")"
match_base="pod_id=\"$POD_ID\""
if [[ -n "$VM_ID" ]]; then
  match_base="vm=\"$VM_ID\".*$match_base|$match_base.*vm=\"$VM_ID\""
fi

assert_metric_one() {
  local metric="$1" direction="$2"
  if ! grep -E "^${metric}\{[^}]*direction=\"${direction}\"[^}]*(${match_base})[^}]*\} 1$|^${metric}\{[^}]*(${match_base})[^}]*direction=\"${direction}\"[^}]*\} 1$" <<<"$metrics" >/dev/null; then
    echo "FAIL: expected $metric direction=$direction pod_id=$POD_ID == 1" >&2
    exit 1
  fi
}

assert_metric_one fluxvm_sentinel_policy_hook_required egress
assert_metric_one fluxvm_sentinel_policy_hook_required ingress
assert_metric_one fluxvm_sentinel_policy_hook_attached egress
assert_metric_one fluxvm_sentinel_policy_hook_attached ingress

if ! grep -E '^fluxvm_sentinel_dataplane_schema_compatible\{[^}]*\} 1$' <<<"$metrics" >/dev/null; then
  echo "FAIL: no schema-compatible VM found in observer output" >&2
  exit 1
fi

printf 'PASS: Set 15 observer reports healthy ingress+egress hooks for pod_id=%s\n' "$POD_ID"
printf 'Tip: generate allowed/denied traffic and watch fluxvm_sentinel_policy_packets_total by direction/verdict.\n'
