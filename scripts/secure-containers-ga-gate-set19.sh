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

# S2 production requirement includes a second CNI, not only multiple nodes.
: "${FLUXVM_SECOND_CNI_GATE:?set to the real NetworkPolicy allow/deny command for a second supported CNI}"
# S9 Kata-equivalence is deliberately deployment/lab-owned.
: "${FLUXVM_KATA_GATE:?set to the OCI/Multus/hostPath/NOTIF_ADDFD/TTY/warm-pool conformance command}"
# S10/S11 require real topology and credentials.
: "${FLUXVM_REAL_FLEET_GATE:?set to a command that runs fluxvm-fleet canary/wave/rollback on >=2 real hosts}"
: "${FLUXVM_ATTACHED_MIGRATION_GATE:?set to a command that runs fluxvm-migrate against a live attached VM}"

bash -lc "$FLUXVM_SECOND_CNI_GATE"
bash -lc "$FLUXVM_KATA_GATE"
bash -lc "$FLUXVM_REAL_FLEET_GATE"
bash -lc "$FLUXVM_ATTACHED_MIGRATION_GATE"

echo "SECURE CONTAINERS GA ACCEPTANCE: PASS"
