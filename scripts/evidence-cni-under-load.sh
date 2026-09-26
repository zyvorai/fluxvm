#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live multi-CNI under load — closes the Secure Containers P0 CNI honesty bound.
#
# Legs (all required unless soft-skipped by env):
#   1) Calico/Flannel-shaped host churn at high round count (stand-in under load)
#   2) Cilium primary cluster: rapid RuntimeClass Pod Ready create/delete cycles
#   3) Second cluster (FLUXVM_SECOND_CNI_KUBECONFIG): concurrent Pod churn
#
# Env:
#   FLUXVM_CNI_UNDER_LOAD=1          required (else SKIP)
#   FLUXVM_CNI_CHURN_ROUNDS          default 80
#   FLUXVM_CNI_LOAD_CYCLES           Pod create/delete cycles per cluster (default 6)
#   FLUXVM_RUNTIMECLASS              primary RuntimeClass (default fluxvm)
#   FLUXVM_SECOND_CNI_RUNTIMECLASS   second cluster RC (default runc; from drop-in)
#   FLUXVM_CNI_UNDER_LOAD_SOFT=1     soft-skip a missing second kubeconfig
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-second-cni-env.sh"

if [[ "${FLUXVM_CNI_UNDER_LOAD:-0}" != 1 ]]; then
  echo "SKIP: set FLUXVM_CNI_UNDER_LOAD=1" >&2
  exit 0
fi

ROUNDS="${FLUXVM_CNI_CHURN_ROUNDS:-80}"
CYCLES="${FLUXVM_CNI_LOAD_CYCLES:-6}"
RC_PRIMARY="${FLUXVM_RUNTIMECLASS:-fluxvm}"
RC_SECOND="${FLUXVM_SECOND_CNI_RUNTIMECLASS:-runc}"
SOFT="${FLUXVM_CNI_UNDER_LOAD_SOFT:-0}"
OUT_DIR="${FLUXVM_EVIDENCE_DIR:-$ROOT/docs/benchmarks/evidence}"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/sc-live-cni-under-load-${TS}.txt"

pass() { printf '✅ %s\n' "$*"; }
fail() { printf '❌ %s\n' "$*" >&2; exit 1; }

{
  echo "FluxVM multi-CNI under load @ $TS"
  echo "host=$(hostname) rounds=$ROUNDS cycles=$CYCLES"
  echo "primary_rc=$RC_PRIMARY second_rc=$RC_SECOND"
  echo "second_kubeconfig=${FLUXVM_SECOND_CNI_KUBECONFIG:-unset}"
  echo
} | tee "$OUT"

# ---- 1) Calico/Flannel-shaped churn under load ----
echo "== leg1: calico/flannel-shaped churn (${ROUNDS} rounds) ==" | tee -a "$OUT"
FLUXVM_CNI_CHURN_ROUNDS="$ROUNDS" "$ROOT/scripts/evidence-cni-churn.sh" | tee -a "$OUT"
pass "leg1 host churn"

# ---- 2) Cilium primary: RuntimeClass Pod Ready churn (no guest exec) ----
echo "== leg2: Cilium primary Pod Ready churn ==" | tee -a "$OUT"
command -v kubectl >/dev/null || fail "missing kubectl"
kubectl get runtimeclass "$RC_PRIMARY" >/dev/null 2>&1 \
  || fail "RuntimeClass $RC_PRIMARY missing on primary"
CILIUM_MARKERS=0
[[ -S /var/run/cilium/cilium.sock ]] && CILIUM_MARKERS=$((CILIUM_MARKERS + 1))
compgen -G '/etc/cni/net.d/*cilium*' >/dev/null 2>&1 && CILIUM_MARKERS=$((CILIUM_MARKERS + 1))
[[ "$CILIUM_MARKERS" -ge 1 ]] || fail "no Cilium markers on primary"

NS_P="fluxvm-cni-load-p-$$"
cleanup_p() { kubectl delete ns "$NS_P" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup_p EXIT
kubectl create ns "$NS_P" >/dev/null
for i in $(seq 1 "$CYCLES"); do
  NAME="probe-$i"
  kubectl -n "$NS_P" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
spec:
  runtimeClassName: ${RC_PRIMARY}
  restartPolicy: Never
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.9
EOF
  kubectl -n "$NS_P" wait --for=condition=Ready "pod/${NAME}" --timeout=180s >/dev/null \
    || fail "primary cycle $i: pod not Ready"
  IP=$(kubectl -n "$NS_P" get pod "$NAME" -o jsonpath='{.status.podIP}')
  [[ -n "$IP" ]] || fail "primary cycle $i: empty PodIP"
  kubectl -n "$NS_P" delete pod "$NAME" --wait=true --timeout=120s >/dev/null \
    || fail "primary cycle $i: delete"
  echo "  primary cycle $i ok ip=$IP" | tee -a "$OUT"
done
cleanup_p
trap - EXIT
pass "leg2 Cilium primary ${CYCLES} Ready cycles (rc=$RC_PRIMARY)"

# ---- 3) Second cluster concurrent-shaped churn ----
echo "== leg3: second-cluster Pod churn ==" | tee -a "$OUT"
if [[ -z "${FLUXVM_SECOND_CNI_KUBECONFIG:-}" || ! -r "${FLUXVM_SECOND_CNI_KUBECONFIG}" ]]; then
  if [[ "$SOFT" == 1 ]]; then
    echo "SKIP/soft: no readable FLUXVM_SECOND_CNI_KUBECONFIG" | tee -a "$OUT"
  else
    fail "FLUXVM_SECOND_CNI_KUBECONFIG required (or set FLUXVM_CNI_UNDER_LOAD_SOFT=1)"
  fi
else
  K2=(kubectl --kubeconfig "$FLUXVM_SECOND_CNI_KUBECONFIG")
  "${K2[@]}" get nodes >/dev/null || fail "second cluster unreachable"
  # Prefer configured RC; fall back to runc/none if missing.
  if ! "${K2[@]}" get runtimeclass "$RC_SECOND" >/dev/null 2>&1; then
    if "${K2[@]}" get runtimeclass runc >/dev/null 2>&1; then
      RC_SECOND=runc
    else
      RC_SECOND=""
    fi
  fi
  NS_S="fluxvm-cni-load-s-$$"
  cleanup_s() { "${K2[@]}" delete ns "$NS_S" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
  trap cleanup_s EXIT
  "${K2[@]}" create ns "$NS_S" >/dev/null
  for i in $(seq 1 "$CYCLES"); do
    NAME="probe-$i"
    if [[ -n "$RC_SECOND" ]]; then
      "${K2[@]}" -n "$NS_S" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
spec:
  runtimeClassName: ${RC_SECOND}
  restartPolicy: Never
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.9
EOF
    else
      "${K2[@]}" -n "$NS_S" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${NAME}
spec:
  restartPolicy: Never
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.9
EOF
    fi
    "${K2[@]}" -n "$NS_S" wait --for=condition=Ready "pod/${NAME}" --timeout=180s >/dev/null \
      || fail "second cycle $i: pod not Ready"
    IP=$("${K2[@]}" -n "$NS_S" get pod "$NAME" -o jsonpath='{.status.podIP}')
    [[ -n "$IP" ]] || fail "second cycle $i: empty PodIP"
    "${K2[@]}" -n "$NS_S" delete pod "$NAME" --wait=true --timeout=120s >/dev/null \
      || fail "second cycle $i: delete"
    echo "  second cycle $i ok ip=$IP rc=${RC_SECOND:-default}" | tee -a "$OUT"
  done
  cleanup_s
  trap - EXIT
  pass "leg3 second cluster ${CYCLES} Ready cycles (kubeconfig + rc=${RC_SECOND:-default})"
fi

{
  echo
  echo "CNI UNDER LOAD: PASS"
  echo "legs: calico/flannel-churn(${ROUNDS}) + cilium-primary(${CYCLES}) + second-cluster(${CYCLES})"
} | tee -a "$OUT"
echo "wrote $OUT"
