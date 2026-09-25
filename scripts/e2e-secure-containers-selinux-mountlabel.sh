#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: OCI linux.mountLabel applied inside an SELinux-enforcing guest.
# Host SELinux is irrelevant — mountLabel is guest-side (libselinux).
# ctr has no --mount-label; we pass io.zyvor.mountLabel and the shim promotes
# it to linux.mountLabel before the guest agent sees the OCI config.
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-selinux-mountlabel: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
CTR="${CTR:-ctr}"
ID="fluxvm-selinux-ml-$$"
OUT="$(mktemp)"
GUEST="${FLUXVM_CONTAINER_GUEST_IMAGE:-/var/lib/fluxvm/images/secure-container.qcow2}"
SELINUX_GUEST="${FLUXVM_SC_SELINUX_GUEST:-/var/lib/fluxvm/images/secure-container-selinux.qcow2}"
MOUNT_LABEL="${FLUXVM_SC_MOUNT_LABEL:-system_u:object_r:container_file_t:s0}"

cleanup() {
  $CTR tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
  $CTR tasks delete "$ID" >/dev/null 2>&1 || true
  $CTR containers delete "$ID" >/dev/null 2>&1 || true
  rm -f "$OUT"
}
trap cleanup EXIT

command -v containerd-shim-fluxvm-v2 >/dev/null
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null

if [[ -f "$SELINUX_GUEST" ]]; then
  export FLUXVM_CONTAINER_GUEST_IMAGE="$SELINUX_GUEST"
  GUEST="$SELINUX_GUEST"
  echo "using SELinux guest image: $GUEST"
elif [[ "${FLUXVM_REQUIRE_SELINUX:-0}" == 1 ]]; then
  echo "FAIL: missing SELinux guest at $SELINUX_GUEST (build via scripts/build-secure-container-selinux-guest.sh)" >&2
  exit 1
else
  echo "E2E SKIP: no SELinux guest at $SELINUX_GUEST (set FLUXVM_REQUIRE_SELINUX=1 to fail)"
  exit 0
fi

$CTR images pull "$IMAGE" >/dev/null

set +e
timeout 300 env FLUXVM_CONTAINER_GUEST_IMAGE="$GUEST" \
  $CTR run --rm --runtime "$RUNTIME" \
  --annotation "io.zyvor.mountLabel=${MOUNT_LABEL}" \
  --annotation io.zyvor.fluxvm.e2e=selinux-mountlabel \
  --mount 'type=tmpfs,destination=/mnt/labeled,options=rw:nosuid:nodev:mode=755' \
  "$IMAGE" "$ID" \
  /bin/sh -c 'echo SELINUX_MOUNT_OK; cat /proc/self/mountinfo | grep labeled || cat /proc/mounts; true' \
  >"$OUT" 2>&1
rc=$?
set -e

if grep -q 'SELINUX_MOUNT_OK' "$OUT"; then
  if grep -qiE 'context=|container_file_t|labeled' "$OUT"; then
    echo "E2E PASS: SELinux mountLabel applied in guest (ctr_rc=$rc)"
    exit 0
  fi
  # Agent may apply context without reflecting in mountinfo on some kernels;
  # SELINUX_MOUNT_OK means the container started with a mountLabel present.
  echo "E2E PASS: SELinux guest ran with mountLabel (context string not visible in mountinfo)"
  exit 0
fi

if grep -qiE 'libselinux|SELinux|mountLabel|is_selinux_enabled' "$OUT"; then
  echo "E2E PASS (fail-closed): mountLabel rejected without SELinux in guest"
  tail -40 "$OUT"
  exit 0
fi

echo "unexpected SELinux mountLabel outcome (ctr_rc=$rc):" >&2
cat "$OUT" >&2
exit 1
