#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# S10 — real multi-host fleet canary/wave/rollback evidence.
#
# Requires ≥2 SSH-reachable hosts with host-key trust (no ssh shim).
# Env:
#   FLUXVM_FLEET_PLAN   rollout plan JSON (nodes[].host must be real)
#   FLUXVM_FLEET_E2E=1
#   /etc/fluxvm-fleet-lab marker on the operator host
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${FLUXVM_FLEET_E2E:-0}" != 1 ]]; then
  echo "SKIP: set FLUXVM_FLEET_E2E=1" >&2
  exit 0
fi
[[ -f /etc/fluxvm-fleet-lab ]] || { echo "refusing: /etc/fluxvm-fleet-lab missing" >&2; exit 2; }
: "${FLUXVM_FLEET_PLAN:?set FLUXVM_FLEET_PLAN to a multi-host rollout JSON}"

command -v fluxvm-fleet >/dev/null || {
  "$ROOT/scripts/install-sentinel-fleet-rollout.sh"
}
command -v jq >/dev/null || { echo "missing jq" >&2; exit 2; }

NODES=$(jq -r '.nodes | length' "$FLUXVM_FLEET_PLAN")
if [[ "$NODES" -lt 2 ]]; then
  echo "S10 requires >=2 nodes in plan (got $NODES)" >&2
  exit 2
fi

# Real SSH host-key probe (StrictHostKeyChecking=yes via fleet tool).
fluxvm-fleet validate "$FLUXVM_FLEET_PLAN"
fluxvm-fleet probe "$FLUXVM_FLEET_PLAN"

# Refuse loopback-only inventories unless explicitly allowed for nested labs.
HOSTS=$(jq -r '.nodes[].host' "$FLUXVM_FLEET_PLAN" | sort -u)
UNIQUE=$(echo "$HOSTS" | wc -l | tr -d ' ')
if [[ "$UNIQUE" -lt 2 && "${FLUXVM_FLEET_ALLOW_SINGLE_HOST:-0}" != 1 ]]; then
  echo "S10 requires distinct SSH hosts (got unique=$UNIQUE). Set FLUXVM_FLEET_ALLOW_SINGLE_HOST=1 only for nested-VM labs." >&2
  exit 2
fi

# Canary → approve → remaining waves. With strategy.require_canary_approval,
# the first `run` stops after wave 0 until `approve` + `resume`.
STATE_DIR="${FLUXVM_FLEET_STATE_DIR:-/tmp/fluxvm-s10-fleet-state}"
mkdir -p "$STATE_DIR"
fluxvm-fleet --state-dir "$STATE_DIR" plan "$FLUXVM_FLEET_PLAN" | tee /tmp/fluxvm-s10-plan.json
fluxvm-fleet --state-dir "$STATE_DIR" run "$FLUXVM_FLEET_PLAN" 2>/tmp/fluxvm-s10-canary.log \
  | tee /tmp/fluxvm-s10-canary-out.json
echo "S10 canary log:" && tail -n 40 /tmp/fluxvm-s10-canary.log || true
CANARY_STATUS=$(jq -r '.status // empty' /tmp/fluxvm-s10-canary-out.json)
case "$CANARY_STATUS" in
  awaiting-canary-approval|complete|paused) ;;
  *)
    echo "S10 canary run unexpected status: ${CANARY_STATUS:-missing}" >&2
    exit 2
    ;;
esac

if [[ "$CANARY_STATUS" == "awaiting-canary-approval" || "$CANARY_STATUS" == "paused" ]]; then
  fluxvm-fleet --state-dir "$STATE_DIR" approve "$FLUXVM_FLEET_PLAN" | tee /tmp/fluxvm-s10-approve.json
  fluxvm-fleet --state-dir "$STATE_DIR" resume "$FLUXVM_FLEET_PLAN" 2>/tmp/fluxvm-s10-resume.log \
    | tee /tmp/fluxvm-s10-resume-out.json
  FINAL=$(jq -r '.status // empty' /tmp/fluxvm-s10-resume-out.json)
  [[ "$FINAL" == "complete" ]] || {
    echo "S10 resume expected complete, got: ${FINAL:-missing}" >&2
    exit 2
  }
fi

fluxvm-fleet --state-dir "$STATE_DIR" evidence "$FLUXVM_FLEET_PLAN" | tee /tmp/fluxvm-s10-evidence-path.txt
# Wave failure path rolls back via rollback_wave inside run; surface journal for audit.
fluxvm-fleet --state-dir "$STATE_DIR" status "$FLUXVM_FLEET_PLAN" | tee /tmp/fluxvm-s10-status.json

echo "S10 REAL MULTI-HOST FLEET: PASS"
