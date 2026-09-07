#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# In-tree KVM linux-loader smoke: load a real vmlinux/bzImage via
# fluxvm-hypervisor (from_boot_config), confirm loader notes, then KVM_RUN
# briefly and look for a Linux serial banner.
#
# Usage (Linux/KVM host):
#   sudo ./scripts/test-kvm-linux-boot-smoke.sh
#   KERNEL=/var/lib/fluxvm/kernels/vmlinux \
#     ROOTFS=/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4 \
#     sudo -E ./scripts/test-kvm-linux-boot-smoke.sh
#
# Env:
#   FLUXVM_HYPERVISOR  binary (default: target/release or PATH)
#   KERNEL             ELF/bzImage path
#   ROOTFS             optional virtio-blk image
#   TIMEOUT_SECS       wall clock for KVM_RUN (default 25)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
TIMEOUT_SECS="${TIMEOUT_SECS:-25}"

[ "$(uname -s)" = "Linux" ] || { echo "requires Linux/KVM" >&2; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm missing" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "KERNEL not found: $KERNEL" >&2; exit 1; }

BIN="${FLUXVM_HYPERVISOR:-}"
if [ -z "$BIN" ]; then
    if [ -x "${PROJECT_DIR}/target/release/fluxvm-hypervisor" ]; then
        BIN="${PROJECT_DIR}/target/release/fluxvm-hypervisor"
    elif command -v fluxvm-hypervisor >/dev/null 2>&1; then
        BIN="$(command -v fluxvm-hypervisor)"
    else
        echo "building fluxvm-hypervisor (release)…"
        (cd "$PROJECT_DIR" && cargo build --release -p fluxvm-hypervisor)
        BIN="${PROJECT_DIR}/target/release/fluxvm-hypervisor"
    fi
fi

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
section() { echo ""; echo "=== $1 ==="; }

CMDLINE="console=ttyS0 earlyprintk=serial,ttyS0,115200 reboot=k panic=1 pci=off root=/dev/vda rw \
virtio_mmio.device=0x200@0xfeb00000:5 \
virtio_mmio.device=0x200@0xfeb00200:6"

ARGS=(--guest linux --memory-mib 256 --cpus 1 --kernel "$KERNEL" --cmdline "$CMDLINE")
if [ -f "$ROOTFS" ]; then
    ARGS+=(--disk "$ROOTFS")
fi

section "dry-run: linux-loader / boot_params notes"
DRY_OUT="$("$BIN" --dry-run "${ARGS[@]}" 2>&1)" || {
    fail "dry-run failed"
    echo "$DRY_OUT" >&2
    exit 1
}
echo "$DRY_OUT" | sed -n '1,40p'
if echo "$DRY_OUT" | grep -qE 'linux-loader|loaded (bzImage|ELF)|boot_params'; then
    pass "dry-run mentions linux-loader / boot_params"
else
    fail "dry-run missing loader notes"
fi
if echo "$DRY_OUT" | grep -qE 'raw dump path'; then
    fail "fell back to raw dump (loader did not accept kernel)"
fi

section "KVM_RUN for up to ${TIMEOUT_SECS}s (serial banner)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
LOG="${TMP}/run.log"
set +e
timeout --signal=KILL "${TIMEOUT_SECS}" "$BIN" "${ARGS[@]}" >"$LOG" 2>&1
RC=$?
set -e
# 124 = timeout, 137 = SIGKILL — both OK if we saw a banner first.
tail -n 80 "$LOG" || true
if grep -qE 'Linux version|linux-loader path|\[ok\] guest printed Linux' "$LOG"; then
    pass "serial/log shows Linux boot banner (or ok path)"
elif grep -qE 'KVM_EXIT_FAIL_ENTRY|instantiate failed|neither bzImage' "$LOG"; then
    fail "KVM/loader hard failure"
else
    # Soft fail: loader worked in dry-run but guest may lack earlyprintk/virtio yet.
    fail "no Linux banner within ${TIMEOUT_SECS}s (loader dry-run OK — guest may need more devices)"
fi

section "Summary"
echo "  pass: ${PASS}  fail: ${FAIL}"
echo "  kernel: $KERNEL"
[ -f "$ROOTFS" ] && echo "  rootfs: $ROOTFS" || echo "  rootfs: (none)"
[ "$FAIL" -eq 0 ]
