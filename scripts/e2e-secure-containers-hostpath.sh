#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Opt-in KVM check that an allowlisted hostPath is a virtiofs export.
# Unit coverage lives in fluxvm-core (symlink escape) and the shim.
# Set FLUXVM_SECURE_CONTAINERS_E2E=1 on a node with containerd to run it.

set -euo pipefail
if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != "1" ]]; then
  echo "e2e-secure-containers-hostpath: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi
if [[ "$(uname -s)" != "Linux" || ! -e /dev/kvm ]]; then
  echo "e2e-secure-containers-hostpath: Linux/KVM required" >&2
  exit 1
fi
ALLOW=${FLUXVM_HOSTPATH_ALLOW:-/var/fluxvm-hostpath-allow}
mkdir -p "${ALLOW}/demo"
echo fluxvm > "${ALLOW}/demo/marker"
export FLUXVM_HOSTPATH_ALLOW="${ALLOW}"
echo "e2e-secure-containers-hostpath: export ${ALLOW} is set; run a RuntimeClass=fluxvm pod with annotation fluxvm.io/hostpath-allow=${ALLOW} and read /run/fluxvm/hostpath-allow/demo/marker"
echo "marker-ready"
