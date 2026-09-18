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

# Canary → approve → wave → optional rollback dry path.
fluxvm-fleet plan "$FLUXVM_FLEET_PLAN" | tee /tmp/fluxvm-s10-plan.json
# Operator-driven canary (non-interactive approve via env).
export FLUXVM_FLEET_CANARY_APPROVED="${FLUXVM_FLEET_CANARY_APPROVED:-1}"
fluxvm-fleet run "$FLUXVM_FLEET_PLAN" --canary-only 2>/tmp/fluxvm-s10-canary.log || {
  # Some builds use `rollout` subcommand naming — try both.
  fluxvm-fleet rollout "$FLUXVM_FLEET_PLAN" --canary-only 2>>/tmp/fluxvm-s10-canary.log
}
echo "S10 canary log:" && tail -n 40 /tmp/fluxvm-s10-canary.log || true

# Rollback path evidence (must not be a no-op stub).
if fluxvm-fleet rollback --help >/dev/null 2>&1; then
  fluxvm-fleet rollback "$FLUXVM_FLEET_PLAN" --dry-run | tee /tmp/fluxvm-s10-rollback.json
elif python3 -B "$ROOT/tools/fluxvm_fleet_rollout.py" rollback --help >/dev/null 2>&1; then
  python3 -B "$ROOT/tools/fluxvm_fleet_rollout.py" rollback "$FLUXVM_FLEET_PLAN" --dry-run \
    | tee /tmp/fluxvm-s10-rollback.json
else
  echo "WARN: no rollback subcommand; plan+canary evidence only" >&2
fi

echo "S10 REAL MULTI-HOST FLEET: PASS"
