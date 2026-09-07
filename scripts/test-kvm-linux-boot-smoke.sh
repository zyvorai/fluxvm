#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# In-tree KVM boot smoke: linux-loader dry-run, then KVM_RUN through
# virtio-blk root mount into a console userspace probe (ttyS0).
#
# Usage (Linux/KVM host):
#   sudo ./scripts/test-kvm-linux-boot-smoke.sh
#
# Env:
#   FLUXVM_HYPERVISOR  binary (default: target/release or PATH)
#   KERNEL             ELF/bzImage path
#   ROOTFS             base virtio-blk image (copied + probe init injected)
#   TIMEOUT_SECS       wall clock for KVM_RUN (default 30)
#   MEMORY_MIB         guest RAM (default 512)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
TIMEOUT_SECS="${TIMEOUT_SECS:-30}"
MEMORY_MIB="${MEMORY_MIB:-512}"

[ "$(uname -s)" = "Linux" ] || { echo "requires Linux/KVM" >&2; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm missing" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "KERNEL not found: $KERNEL" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo) — needs loop-mount to inject probe init." >&2; exit 1; }

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

TMP="$(mktemp -d)"
MNT=""
cleanup() {
    [ -n "$MNT" ] && umount "$MNT" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

PROBE_DISK=""
INIT_ARG=""
if [ -f "$ROOTFS" ]; then
    PROBE_DISK="${TMP}/probe.ext4"
    cp -a "$ROOTFS" "$PROBE_DISK"
    e2fsck -fy "$PROBE_DISK" >/dev/null 2>&1 || true
    MNT="${TMP}/mnt"
    mkdir -p "$MNT"
    mount -o loop "$PROBE_DISK" "$MNT"
    cat > "${MNT}/userspace-probe.sh" <<'EOF'
#!/bin/sh
# Bind stdio to the UART so PID1 has a console without agetty.
if [ -c /dev/ttyS0 ]; then
  exec >/dev/ttyS0 2>&1 </dev/ttyS0
elif [ -c /dev/console ]; then
  exec >/dev/console 2>&1 </dev/console
fi
echo FLUXVM_USERSPACE_OK
echo FLUXVM_PROMPT_READY
# Block for one line from the host UART inject / stdin path.
IFS= read -r line || line=
echo "FLUXVM_STDIN_OK:${line}"
exec sleep 3600
EOF
    chmod +x "${MNT}/userspace-probe.sh"
    umount "$MNT"
    MNT=""
    INIT_ARG="init=/userspace-probe.sh"
fi

CMDLINE="console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw ${INIT_ARG} \
virtio_mmio.device=0x200@0xfeb00000:5 \
virtio_mmio.device=0x200@0xfeb00200:6"

ARGS=(--guest linux --memory-mib "$MEMORY_MIB" --cpus 1 --kernel "$KERNEL" --cmdline "$CMDLINE")
if [ -n "$PROBE_DISK" ]; then
    ARGS+=(--disk "$PROBE_DISK")
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

section "KVM_RUN for up to ${TIMEOUT_SECS}s (console stdin round-trip)"
LOG="${TMP}/run.log"
set +e
timeout --signal=KILL "$((TIMEOUT_SECS + 5))" \
  env FLUXVM_KVM_RUN_SECS="${TIMEOUT_SECS}" FLUXVM_SERIAL_INJECT="ping" \
  "$BIN" "${ARGS[@]}" >"$LOG" 2>&1
RC=$?
set -e
tail -n 120 "$LOG" || true

if grep -qE 'FLUXVM_STDIN_OK|\[ok\] guest console stdin' "$LOG"; then
    pass "guest console stdin round-trip"
elif grep -qE 'FLUXVM_USERSPACE_OK|FLUXVM_PROMPT_READY|\[ok\] guest reached userspace' "$LOG"; then
    pass "guest reached console userspace"
    fail "stdin round-trip missing (userspace OK but no FLUXVM_STDIN_OK)"
elif grep -qE "can't access tty|login:" "$LOG"; then
    pass "guest reached userspace (shell without probe banner)"
    fail "stdin round-trip missing"
elif grep -qE 'VFS: Mounted root|Freeing unused kernel memory|\[ok\] guest reached root' "$LOG"; then
    pass "guest reached root mount"
    fail "userspace console marker missing"
elif grep -qE 'Linux version|\[ok\] guest printed Linux' "$LOG"; then
    pass "serial/log shows Linux boot banner (or ok path)"
    if grep -qE 'Kernel panic|alloc_low_pages' "$LOG"; then
        fail "kernel panicked after banner (e820/memory)"
    else
        fail "stopped before root/userspace"
    fi
elif grep -qE 'KVM_EXIT_FAIL_ENTRY|instantiate failed|neither bzImage' "$LOG"; then
    fail "KVM/loader hard failure"
else
    fail "no Linux banner within ${TIMEOUT_SECS}s"
fi

section "Summary"
echo "  pass: ${PASS}  fail: ${FAIL}"
echo "  kernel: $KERNEL"
[ -n "$PROBE_DISK" ] && echo "  rootfs: probe from $ROOTFS" || echo "  rootfs: (none)"
[ "$FAIL" -eq 0 ]
