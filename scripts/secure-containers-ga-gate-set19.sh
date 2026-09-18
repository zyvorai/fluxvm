#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
need(){ command -v "$1" >/dev/null || { echo "GA gate missing $1" >&2; exit 2; }; }
need kubectl; need python3; need go
: "${FLUXVM_RUNTIMECLASS:?set FLUXVM_RUNTIMECLASS to the Secure Containers RuntimeClass}"

# Reuse the repository's existing Sentinel certification framework; Set 19 is
# a feature completion pack, not a second certification authority.
if [[ -x "$ROOT/scripts/test-sentinel-ga-static.sh" ]]; then
  "$ROOT/scripts/test-sentinel-ga-static.sh"
fi
python3 "$ROOT/scripts/benchmark-policy-observer-set19.py" \
  --vms "${GA_OBSERVER_VMS:-1000}" --rules "${GA_OBSERVER_RULES:-64}" \
  > "${GA_OBSERVER_SIZING_OUT:-/tmp/fluxvm-observer-sizing.json}"

# S1 + same-CNI multi-node starter: real Secure Containers TCP statefulness.
if [[ -x "$ROOT/scripts/test-networkpolicy-stateful-set17.sh" ]]; then
  REQUIRE_MULTI_NODE="${REQUIRE_MULTI_NODE:-1}" "$ROOT/scripts/test-networkpolicy-stateful-set17.sh"
else
  echo "missing Set 17 live stateful gate" >&2; exit 2
fi

# S4: real EndpointSlice readiness/drain/backend transitions.
if [[ -x "$ROOT/scripts/test-networkpolicy-endpointslice-set18.sh" ]]; then
  "$ROOT/scripts/test-networkpolicy-endpointslice-set18.sh"
else
  echo "missing Set 18 EndpointSlice gate" >&2; exit 2
fi

# S2 second CNI / policy-engine (multi-node same-CNI already ran above).
export FLUXVM_SECOND_CNI_GATE="${FLUXVM_SECOND_CNI_GATE:-$ROOT/scripts/evidence-networkpolicy-second-cni.sh}"
# S9 Kata-equivalence matrix (soft legs unless FLUXVM_KATA_REQUIRE_ALL=1).
export FLUXVM_KATA_GATE="${FLUXVM_KATA_GATE:-FLUXVM_KATA_SOFT=1 $ROOT/scripts/evidence-kata-p0p1-matrix.sh}"
# S10 skips unless FLUXVM_FLEET_E2E=1 + lab marker; S11 runs attached migration.
export FLUXVM_REAL_FLEET_GATE="${FLUXVM_REAL_FLEET_GATE:-$ROOT/scripts/evidence-fleet-multihost.sh}"
export FLUXVM_ATTACHED_MIGRATION_GATE="${FLUXVM_ATTACHED_MIGRATION_GATE:-FLUXVM_ATTACHED_MIGRATION=1 $ROOT/scripts/evidence-migration-attached-vm.sh}"

# S1 depth (mid-flow kill + SYN anti-replay) when enabled.
if [[ "${FLUXVM_S1_DEPTH:-1}" == 1 && -x "$ROOT/scripts/e2e-networkpolicy-s1-depth.sh" ]]; then
  RUNTIME_CLASS="${FLUXVM_RUNTIMECLASS}" "$ROOT/scripts/e2e-networkpolicy-s1-depth.sh"
fi

bash -lc "$FLUXVM_SECOND_CNI_GATE"
bash -lc "$FLUXVM_KATA_GATE"
bash -lc "$FLUXVM_REAL_FLEET_GATE"
bash -lc "$FLUXVM_ATTACHED_MIGRATION_GATE"

echo "SECURE CONTAINERS GA ACCEPTANCE: PASS"
