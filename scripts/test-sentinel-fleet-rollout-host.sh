#!/usr/bin/env bash
set -euo pipefail
if [[ "${FLUXVM_FLEET_E2E:-0}" != 1 ]]; then echo "SKIP: set FLUXVM_FLEET_E2E=1 on a disposable SSH lab"; exit 0; fi
[[ -f /etc/fluxvm-fleet-lab ]] || { echo "refusing: /etc/fluxvm-fleet-lab marker missing" >&2; exit 2; }
: "${FLUXVM_FLEET_PLAN:?set FLUXVM_FLEET_PLAN}"
fluxvm-fleet validate "$FLUXVM_FLEET_PLAN"
fluxvm-fleet probe "$FLUXVM_FLEET_PLAN"
fluxvm-fleet plan "$FLUXVM_FLEET_PLAN"
echo "Host gate validated inventory/planning only; rollout remains an explicit operator action."
