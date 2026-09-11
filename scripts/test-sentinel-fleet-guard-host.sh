#!/usr/bin/env bash
set -euo pipefail
[[ "${FLUXVM_FLEET_GUARD_HOST_TEST:-0}" == 1 ]] || { echo 'SKIP: set FLUXVM_FLEET_GUARD_HOST_TEST=1 on a disposable SSH-capable lab'; exit 0; }
: "${FLUXVM_FLEET_GUARD_PLAN:?set FLUXVM_FLEET_GUARD_PLAN}"
python3 "$(dirname "$0")/../tools/fluxvm_fleet_guard.py" validate "$FLUXVM_FLEET_GUARD_PLAN"
python3 "$(dirname "$0")/../tools/fluxvm_fleet_guard.py" check "$FLUXVM_FLEET_GUARD_PLAN"
echo 'Set 16E host smoke: PASS'
