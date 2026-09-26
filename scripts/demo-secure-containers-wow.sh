#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Human-facing “wow” demo for Secure Containers on a provisioned lab.
# Wraps existing e2e scripts — does not invent new gates.
#
# Requires: FLUXVM_SECURE_CONTAINERS_E2E=1, RuntimeClass fluxvm, kubectl,
#           FLUXVM_CONTAINER_USERNS=1 on the shim (provision script default).
#
# Usage:
#   FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/demo-secure-containers-wow.sh
# Optional:
#   FLUXVM_SC_DEMO_SELINUX=1   — also run mountLabel green e2e
#   FLUXVM_SC_DEMO_MULTI=1     — also run k8s-multi distinct userns (N=2)
#   FLUXVM_SC_DEMO_POLICY=1    — apply a deny-all NetworkPolicy smoke (Sentinel path)
#   FLUXVM_SC_DEMO_NS=default FLUXVM_SC_DEMO_RC=fluxvm
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "demo-secure-containers-wow: set FLUXVM_SECURE_CONTAINERS_E2E=1" >&2
  exit 1
fi

NS="${FLUXVM_SC_DEMO_NS:-default}"
RC="${FLUXVM_SC_DEMO_RC:-fluxvm}"
NP_NAME="fluxvm-sc-wow-deny-$$"

kubectl() {
  # Prefer a readable kubeconfig; fall back to k3s (common lab layout where
  # /etc/rancher/k3s/k3s.yaml is root-only and breaks bare `kubectl`).
  if [[ -n "${KUBECONFIG:-}" && -r "${KUBECONFIG}" ]]; then
    command kubectl "$@"
    return
  fi
  if [[ -r "${HOME}/.kube/config" ]] && command -v kubectl >/dev/null 2>&1; then
    command kubectl "$@"
    return
  fi
  if command -v k3s >/dev/null 2>&1; then
    sudo k3s kubectl "$@"
    return
  fi
  command kubectl "$@"
}
export -f kubectl

echo "== wow: RuntimeClass ${RC} must exist =="
kubectl get runtimeclass "$RC" >/dev/null

echo "== wow: k8s userns (N=1) =="
export FLUXVM_USERNS_MODE=k8s
export FLUXVM_USERNS_LOAD_N=1
bash "$ROOT/scripts/e2e-secure-containers-userns-load.sh" "$NS" "$RC"

if [[ "${FLUXVM_SC_DEMO_MULTI:-0}" == 1 ]]; then
  echo "== wow: k8s-multi distinct userns (N=2) =="
  export FLUXVM_USERNS_MODE=k8s-multi
  export FLUXVM_USERNS_LOAD_N=2
  bash "$ROOT/scripts/e2e-secure-containers-userns-load.sh" "$NS" "$RC"
fi

if [[ "${FLUXVM_SC_DEMO_SELINUX:-0}" == 1 ]]; then
  echo "== wow: SELinux mountLabel green =="
  bash "$ROOT/scripts/e2e-secure-containers-selinux-mountlabel.sh"
fi

if [[ "${FLUXVM_SC_DEMO_POLICY:-0}" == 1 ]]; then
  echo "== wow: NetworkPolicy deny-all (Sentinel / Observer path) =="
  kubectl -n "$NS" apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${NP_NAME}
  namespace: ${NS}
  labels:
    fluxvm.io/wow-demo: "1"
spec:
  podSelector:
    matchLabels:
      fluxvm.io/userns-load: "1"
  policyTypes: ["Egress"]
  egress: []
EOF
  kubectl -n "$NS" get networkpolicy "$NP_NAME" -o wide
  kubectl -n "$NS" delete networkpolicy "$NP_NAME" --wait=false
  echo "  (observer scrape archive: docs/benchmarks/evidence/policy-observer-scrape-20260918T035554Z.txt)"
  echo "  (sentinel wedge: docs/sentinel-wedge.md)"
fi

echo "WOW DEMO: OK"
echo "  flip runbook: docs/secure-containers-flip-runtimeclass.md"
echo "  supported profile: docs/secure-containers-supported-profile.md"
echo "  evidence pack: docs/benchmarks/evidence/sc-hotcake-bundle-20260926.txt"
