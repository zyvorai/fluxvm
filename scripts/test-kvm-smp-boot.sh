#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Multi-vCPU (SMP) boot smoke for the in-tree fluxvm-hypervisor.
# Soft-skips when KERNEL/ROOTFS/KVM are unavailable (CI without KVM).
#
# Usage (Linux/KVM host):
#   sudo ./scripts/test-kvm-smp-boot.sh
#
# Env: same as test-kvm-linux-boot-smoke.sh, plus:
#   CPUS           guest vCPU count (default 2)
#   TIMEOUT_SECS   default 60 (AP bring-up needs headroom)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"
MEMORY_MIB="${MEMORY_MIB:-512}"
CPUS="${CPUS:-2}"

if [ "$(uname -s)" != "Linux" ] || [ ! -e /dev/kvm ]; then
  echo "SKIP: requires Linux/KVM"
  exit 0
fi
if [ ! -f "$KERNEL" ]; then
  echo "SKIP: KERNEL not found: $KERNEL"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: run as root to inject userspace probe (or set SKIP_ROOTFS=1)"
  if [ "${SKIP_ROOTFS:-0}" != "1" ]; then
    exit 0
  fi
fi

BIN="${FLUXVM_HYPERVISOR:-}"
if [ -z "$BIN" ]; then
  if [ -x "${PROJECT_DIR}/target/release/fluxvm-hypervisor" ]; then
    BIN="${PROJECT_DIR}/target/release/fluxvm-hypervisor"
  elif command -v fluxvm-hypervisor >/dev/null 2>&1; then
    BIN="$(command -v fluxvm-hypervisor)"
  else
    (cd "$PROJECT_DIR" && cargo build --release -p fluxvm-hypervisor)
    BIN="${PROJECT_DIR}/target/release/fluxvm-hypervisor"
  fi
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PROBE_DISK=""
INIT_ARG=""
if [ -f "$ROOTFS" ] && [ "${SKIP_ROOTFS:-0}" != "1" ]; then
  PROBE_DISK="${TMP}/probe.ext4"
  cp -a "$ROOTFS" "$PROBE_DISK"
  e2fsck -fy "$PROBE_DISK" >/dev/null 2>&1 || true
  MNT="${TMP}/mnt"
  mkdir -p "$MNT"
  mount -o loop "$PROBE_DISK" "$MNT"
  cat > "${MNT}/userspace-probe.sh" <<'EOF'
#!/bin/sh
# Running as init: /proc and /sys are not mounted yet, and without them
# getconf/nproc guess instead of reading the real online CPU set.
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
if [ -c /dev/ttyS0 ]; then
  exec >/dev/ttyS0 2>&1 </dev/ttyS0
fi
echo FLUXVM_USERSPACE_OK
nproc=$(grep -c '^cpu[0-9]' /proc/stat 2>/dev/null || echo 1)
echo "FLUXVM_NPROC:${nproc}"
# One reader per CPU so QueueNotify writes come from every vCPU at once.
i=0
while [ "$i" -lt "$nproc" ]; do
  dd if=/dev/vda of=/dev/null bs=64k skip=$((i * 256)) count=1024 2>/dev/null &
  i=$((i + 1))
done
wait
echo FLUXVM_IO_OK
echo FLUXVM_STDIN_OK
exec sleep 3600
EOF
  chmod +x "${MNT}/userspace-probe.sh"
  umount "$MNT"
  INIT_ARG="init=/userspace-probe.sh"
fi

CMDLINE="console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw ${INIT_ARG}"

ARGS=(--guest linux --memory-mib "$MEMORY_MIB" --cpus "$CPUS" --kernel "$KERNEL" --cmdline "$CMDLINE")
if [ -n "$PROBE_DISK" ]; then
  ARGS+=(--disk "$PROBE_DISK")
fi

echo "=== SMP boot: cpus=${CPUS} timeout=${TIMEOUT_SECS}s ==="
LOG="${TMP}/run.log"
set +e
timeout --signal=KILL "$((TIMEOUT_SECS + 5))" \
  env FLUXVM_KVM_RUN_SECS="${TIMEOUT_SECS}" FLUXVM_SERIAL_INJECT= \
  "$BIN" "${ARGS[@]}" >"$LOG" 2>&1
RC=$?
set -e
tail -n 160 "$LOG" || true
grep -aE 'smp: Brought up|smpboot: Total of|FLUXVM_NPROC' "$LOG" || true

FAIL=0
if grep -qE 'do_boot_cpu failed|smpboot:.*failed' "$LOG"; then
  echo "FAIL: AP bring-up failed (do_boot_cpu)"
  FAIL=1
fi
if ! grep -qE 'FLUXVM_USERSPACE_OK|Run /sbin/init|Freeing unused kernel memory|VFS: Mounted root' "$LOG"; then
  echo "FAIL: guest did not reach userspace/root within ${TIMEOUT_SECS}s"
  FAIL=1
else
  echo "PASS: guest reached userspace/root"
fi
if grep -q 'FLUXVM_NPROC:' "$LOG"; then
  if grep -q 'FLUXVM_IO_OK' "$LOG"; then
    echo "PASS: parallel virtio-blk reads from ${CPUS} vCPUs completed"
  else
    echo "FAIL: parallel virtio-blk reads did not complete"
    FAIL=1
  fi
fi
if grep -qE "FLUXVM_NPROC:${CPUS}\\b|Brought up [0-9]+ nodes?, ${CPUS} CPUs" "$LOG"; then
  echo "PASS: guest reports ${CPUS} CPUs"
elif grep -q 'FLUXVM_NPROC:' "$LOG"; then
  echo "FAIL: guest nproc mismatch (want ${CPUS})"
  grep 'FLUXVM_NPROC:' "$LOG" || true
  FAIL=1
else
  echo "WARN: no explicit nproc marker (kernel log may still show SMP OK)"
  if ! grep -qE "Brought up [0-9]+ nodes?, ${CPUS} CPUs" "$LOG"; then
    # Soft-fail only when userspace OK but no SMP evidence at all.
    if grep -q 'FLUXVM_USERSPACE_OK' "$LOG"; then
      echo "FAIL: userspace OK but no evidence ${CPUS} CPUs came up"
      FAIL=1
    fi
  fi
fi

[ "$FAIL" -eq 0 ]
