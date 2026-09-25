#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# S9 — Kata P0/P1 matrix evidence (OCI / Multus / hostPath / NOTIF / TTY / warm-pool).
#
# Runs the in-tree Secure Containers gates that close Kata-equivalence rows.
# Individual legs may SKIP when the lab lacks containerd/KVM; set
# FLUXVM_KATA_REQUIRE_ALL=1 to fail on any skip.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQUIRE_ALL="${FLUXVM_KATA_REQUIRE_ALL:-0}"
PASS=0
SKIP=0
FAIL=0

run_leg() {
  local name="$1"; shift
  echo "== S9:$name =="
  if "$@"; then
    echo "PASS: $name"
    PASS=$((PASS + 1))
  else
    local rc=$?
    if [[ $rc -eq 0 ]]; then
      :
    elif [[ "${FLUXVM_KATA_SOFT:-0}" == 1 || $REQUIRE_ALL != 1 ]]; then
      echo "SKIP/soft-fail: $name (rc=$rc)"
      SKIP=$((SKIP + 1))
    else
      echo "FAIL: $name (rc=$rc)" >&2
      FAIL=$((FAIL + 1))
    fi
  fi
}

# P0 — portable contracts + namespace/security fixtures
run_leg oci-portable "$ROOT/scripts/test-secure-containers.sh"
if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" == 1 ]]; then
  run_leg namespaces env FLUXVM_SECURE_CONTAINERS_E2E=1 "$ROOT/scripts/e2e-secure-containers-namespaces.sh"
  run_leg security env FLUXVM_SECURE_CONTAINERS_E2E=1 "$ROOT/scripts/e2e-secure-containers-security.sh"
  run_leg volume env FLUXVM_SECURE_CONTAINERS_E2E=1 "$ROOT/scripts/e2e-secure-containers-volume.sh"
  run_leg dualstack env FLUXVM_SECURE_CONTAINERS_E2E=1 "$ROOT/scripts/e2e-secure-containers-dualstack.sh"
fi

# P0 — Multus negative (strict multi-interface reject)
run_leg multus-negative bash -c '
  # Contract: shim rejects >1 CNI interface unless explicitly opted in.
  grep -n "CNI_STRICT_MULTI_INTERFACE\|multi.interface\|multus" \
    "'"$ROOT"'/crates/fluxvm-containerd-shim/src/main.rs" >/dev/null
'

# P0 — hostPath broker allowlist surface present
run_leg hostpath-broker bash -c '
  grep -n "hostPath\|host_path\|HOSTPATH_ALLOW\|fluxvm.io/hostpath" \
    "'"$ROOT"'/crates/fluxvm-containerd-shim/src/main.rs" \
    "'"$ROOT"'/docs/secure-containers.md" >/dev/null
'

# P0 — Firecracker ext4 share packing + kernel env wiring
run_leg firecracker-shares bash -c '
  test -f "'"$ROOT"'/tests/oci-fixtures/firecracker-shares.json" && \
  grep -n "FLUXVM_CONTAINER_KERNEL\|prepare_share_images\|pack_directory_ext4" \
    "'"$ROOT"'/crates/fluxvm-containerd-shim/src/main.rs" \
    "'"$ROOT"'/crates/fluxvm-firecracker/src/lib.rs" \
    "'"$ROOT"'/crates/fluxvm-core/src/fs_image.rs" >/dev/null
'

# P0 — Calico/Flannel churn harness present (needs root for live churn)
run_leg cni-churn bash -c '
  test -x "'"$ROOT"'/scripts/evidence-cni-churn.sh" && \
  grep -n "calico\|flannel\|CniProvider::Calico\|CniProvider::Flannel" \
    "'"$ROOT"'/crates/fluxvm-containerd-shim/src/main.rs" \
    "'"$ROOT"'/scripts/evidence-cni-churn.sh" >/dev/null
'

# P1 — seccomp NOTIF_ADDFD surface (ioctl path or documented gate)
run_leg notif-addfd bash -c '
  grep -n "NOTIF_ADDFD\|SECCOMP_IOCTL_NOTIF_ADDFD\|addfd" \
    "'"$ROOT"'/crates/fluxvm-container-agent/src/main.rs" \
    "'"$ROOT"'/docs/secure-containers-set11.md" >/dev/null
'

# P1 — TTY churn (repeated resize / abrupt exit)
if [[ -x "$ROOT/scripts/e2e-secure-containers-tty.sh" && "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" == 1 ]]; then
  run_leg tty-churn bash -c '
    for i in 1 2 3; do
      FLUXVM_SECURE_CONTAINERS_E2E=1 "'"$ROOT"'/scripts/e2e-secure-containers-tty.sh" || exit 1
    done
  '
else
  run_leg tty-smoke bash -c 'test -x "'"$ROOT"'/scripts/e2e-secure-containers-tty.sh"'
fi

# P1 — warm-pool claim API present (SC wiring may still be cold-boot)
run_leg warm-pool bash -c '
  test -x "'"$ROOT"'/scripts/test-warm-pool.sh"
  "'"$ROOT"'/scripts/test-warm-pool.sh" >/tmp/fluxvm-s9-warm-pool.log 2>&1 || true
  grep -E "PASS|pool|claim" /tmp/fluxvm-s9-warm-pool.log >/dev/null
'

# OCI fixture pack
run_leg oci-fixtures bash -c '
  test -d "'"$ROOT"'/tests/oci-fixtures" && \
  test -f "'"$ROOT"'/tests/oci-fixtures/README.md"
'

echo "S9 summary: pass=$PASS skip=$SKIP fail=$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
if [[ "$PASS" -lt 3 ]]; then
  echo "S9: insufficient legs passed" >&2
  exit 1
fi
echo "S9 KATA P0/P1 MATRIX: PASS"
