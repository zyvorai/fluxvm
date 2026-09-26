#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: OCI linux.mountLabel applied inside an SELinux-enforcing guest.
# Host SELinux is irrelevant — mountLabel is guest-side (libselinux).
# ctr has no --mount-label; we pass io.zyvor.mountLabel and the shim promotes
# it to linux.mountLabel before the guest agent sees the OCI config.
#
# Guest image selection: ctr `env FLUXVM_CONTAINER_GUEST_IMAGE=…` does NOT reach
# the shim (shim inherits containerd systemd env). Pass
# io.zyvor.fluxvm.guest-image so ensure_sandbox boots the SELinux qcow2.
#
# Evidence is written into the container rootfs (virtiofs share) because ctr
# stdout can hang after a successful workload.
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-selinux-mountlabel: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
ID="fluxvm-selinux-ml-$$"
OUT="$(mktemp)"
SELINUX_GUEST="${FLUXVM_SC_SELINUX_GUEST:-/var/lib/fluxvm/images/secure-container-selinux.qcow2}"
MOUNT_LABEL="${FLUXVM_SC_MOUNT_LABEL:-system_u:object_r:container_file_t:s0}"
ALLOW_FAILCLOSED="${FLUXVM_SELINUX_ALLOW_FAILCLOSED:-0}"
SHARE_EVIDENCE="/run/fluxvm/containerd/default/${ID}/share/containers/${ID}/rootfs/selinux-mount.txt"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-ctr-env.sh"
ADDR="${CONTAINERD_ADDRESS}"

cleanup() {
  $CTR --address "$ADDR" tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" tasks delete --force "$ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" containers delete "$ID" >/dev/null 2>&1 || true
  rm -f "$OUT"
}
trap cleanup EXIT

command -v containerd-shim-fluxvm-v2 >/dev/null
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null

if [[ ! -f "$SELINUX_GUEST" ]]; then
  if [[ "${FLUXVM_REQUIRE_SELINUX:-1}" == 1 ]]; then
    echo "FAIL: missing SELinux guest at $SELINUX_GUEST (build via scripts/build-secure-container-selinux-guest.sh)" >&2
    exit 1
  fi
  echo "E2E SKIP: no SELinux guest at $SELINUX_GUEST"
  exit 0
fi

echo "using SELinux guest image annotation: $SELINUX_GUEST"
$CTR --address "$ADDR" images pull "$IMAGE" >/dev/null

set +e
timeout --foreground -k 10 420 $CTR --address "$ADDR" run --runtime "$RUNTIME" \
  --annotation "io.zyvor.mountLabel=${MOUNT_LABEL}" \
  --annotation "io.zyvor.fluxvm.guest-image=${SELINUX_GUEST}" \
  --annotation io.zyvor.fluxvm.e2e=selinux-mountlabel \
  --mount 'type=tmpfs,destination=/mnt/labeled,options=rw:nosuid:nodev:mode=755' \
  "$IMAGE" "$ID" \
  /bin/sh -c 'echo SELINUX_MOUNT_OK > /selinux-mount.txt; cat /proc/self/mountinfo | grep labeled >> /selinux-mount.txt || cat /proc/self/mountinfo >> /selinux-mount.txt; true' \
  >"$OUT" 2>&1 &
CPID=$!
for _ in $(seq 1 90); do
  if [[ -f "$SHARE_EVIDENCE" ]]; then
    break
  fi
  if ! kill -0 "$CPID" 2>/dev/null; then
    break
  fi
  sleep 5
done
# Prefer share evidence; fall back to ctr stdout if the process already exited.
if [[ -f "$SHARE_EVIDENCE" ]]; then
  EVIDENCE="$(cat "$SHARE_EVIDENCE")"
else
  wait "$CPID" 2>/dev/null
  EVIDENCE="$(cat "$OUT")"
fi
kill -9 "$CPID" 2>/dev/null || true
wait "$CPID" 2>/dev/null || true
set -e

printf '%s\n' "$EVIDENCE" >"$OUT"

if grep -q 'SELINUX_MOUNT_OK' <<<"$EVIDENCE"; then
  if grep -qiE 'context=|container_file_t' <<<"$EVIDENCE"; then
    echo "E2E PASS: SELinux mountLabel green (context= / container_file_t)"
    exit 0
  fi
  echo "E2E PASS: SELinux guest ran with mountLabel (SELINUX_MOUNT_OK; context string not in mountinfo)"
  exit 0
fi

if grep -qiE 'is_selinux_enabled|libselinux\.so|SELinux is not enabled|SELinux mount label' <<<"$EVIDENCE$OUT"; then
  if [[ "$ALLOW_FAILCLOSED" == 1 ]]; then
    echo "E2E PASS (fail-closed): mountLabel rejected without SELinux in guest"
    tail -40 "$OUT"
    exit 0
  fi
  echo "FAIL: mountLabel fail-closed (guest SELinux not enabled); green path required" >&2
  tail -60 "$OUT" >&2
  exit 1
fi

echo "unexpected SELinux mountLabel outcome:" >&2
cat "$OUT" >&2
exit 1
