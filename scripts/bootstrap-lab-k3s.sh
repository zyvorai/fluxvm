#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Idempotent single-node k3s bootstrap for live Kubernetes-facing tests
# (e.g. scripts/test-networkpolicy-live.sh). This is lab/CI infrastructure,
# not a FluxVM product component: it exists because no kind/k3s/kubeadm
# bootstrap existed anywhere in this repo before Set 13's completion, and
# scripts/test-kube-operator.sh and friends all *assume* a cluster already
# runs at $KUBECONFIG rather than installing one.
#
# Safe to re-run: does nothing if k3s is already installed and active.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (sudo -E $0)" >&2
  exit 2
fi

KUBECONFIG_PATH="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

if command -v k3s >/dev/null && systemctl is-active --quiet k3s 2>/dev/null; then
  echo "k3s already installed and active; nothing to do"
else
  command -v curl >/dev/null || { echo "curl required to install k3s" >&2; exit 2; }
  echo "installing k3s (single node, throwaway lab cluster)..."
  # --write-kubeconfig-mode so a non-root test runner can read it without
  # sudo; --disable traefik/servicelb since this test needs neither and
  # they slow node-ready convergence for no benefit here.
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644 --disable traefik --disable servicelb" sh -
fi

echo "waiting for node Ready..."
for _ in $(seq 1 60); do
  if k3s kubectl get nodes --no-headers 2>/dev/null | grep -q ' Ready'; then
    echo "node Ready"
    k3s kubectl get nodes
    echo "KUBECONFIG=$KUBECONFIG_PATH"
    exit 0
  fi
  sleep 2
done
echo "k3s node did not become Ready in time" >&2
exit 1
