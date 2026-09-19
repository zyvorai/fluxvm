#!/usr/bin/env bash
# Calico/flannel-shaped CNI churn. Creates and deletes a bridge+veth
# (Calico workload shape) and a flannel.1 stand-in, ROUNDS times, without
# touching a live cluster. If FLUXVM_SECOND_CNI_KUBECONFIG points at a
# second cluster, this script only records that path — S2's kube run is
# scripts/evidence-networkpolicy-second-cni.sh.
set -euo pipefail

ROUNDS="${FLUXVM_CNI_CHURN_ROUNDS:-20}"
SFX="$(printf '%04x' $$)"
IP="${IP:-ip}"
if [[ "$(id -u)" -ne 0 ]]; then
  IP="sudo -n ip"
fi

pass() { printf '✅ %s\n' "$*"; }
fail() { printf '❌ %s\n' "$*" >&2; exit 1; }

cleanup() {
  $IP link del "fvca${SFX}" 2>/dev/null || true
  $IP link del "fvcb${SFX}" 2>/dev/null || true
  $IP link del "brfc${SFX}" 2>/dev/null || true
  $IP link del "fln${SFX}" 2>/dev/null || true
}
trap cleanup EXIT

churn_bridge() {
  local br="$1" a="$2" b="$3"
  $IP link del "$a" 2>/dev/null || true
  $IP link del "$b" 2>/dev/null || true
  $IP link del "$br" 2>/dev/null || true
  $IP link add "$br" type bridge
  $IP link set "$br" up
  $IP link add "$a" type veth peer name "$b"
  $IP link set "$a" master "$br"
  $IP link set "$a" up
  $IP link set "$b" up
  $IP link del "$a"
  $IP link del "$br"
}

for i in $(seq 1 "$ROUNDS"); do
  churn_bridge "brfc${SFX}" "fvca${SFX}" "fvcb${SFX}" || fail "calico-shaped churn round $i"
  $IP link del "fln${SFX}" 2>/dev/null || true
  # flannel.1 is normally vxlan. A live cluster may already own VNI 1 / UDP
  # 8472, so this stand-in uses its own VNI and falls back to a bridge.
  if ! $IP link add "fln${SFX}" type vxlan id 4093 dstport 8473 2>/dev/null; then
    $IP link add "fln${SFX}" type bridge || fail "flannel-shaped link round $i"
  fi
  $IP link set "fln${SFX}" up || fail "flannel-shaped link up round $i"
  $IP link del "fln${SFX}" || fail "flannel-shaped link del round $i"
done

pass "calico/flannel churn ${ROUNDS} rounds"
if [[ -n "${FLUXVM_SECOND_CNI_KUBECONFIG:-}" ]]; then
  pass "second CNI kubeconfig set: ${FLUXVM_SECOND_CNI_KUBECONFIG}"
else
  printf '⚠️  no FLUXVM_SECOND_CNI_KUBECONFIG — live second-cluster S2 still uses the nftables stand-in\n'
fi
