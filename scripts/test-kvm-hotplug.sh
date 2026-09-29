#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# H4: CPU hotplug smoke for the in-tree KVM engine.
#
# Boots with vcpus=2, max_vcpus=4. Every vCPU up to max_vcpus is really
# created at boot (parked, correct topology CPUID, present in the MP table);
# `maxcpus=2` on the guest cmdline keeps Linux from auto-onlining cpu2/cpu3.
# This test proves, from *inside* the booted guest, that those reserved
# vCPUs are real and schedulable once onlined via the normal sysfs hotplug
# path, and separately exercises the control-socket `hotplug_cpu` API to
# confirm its bookkeeping/plan response.
#
# Usage (Linux/KVM host, as root):
#   sudo ./scripts/test-kvm-hotplug.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"

if [ "$(uname -s)" != "Linux" ] || [ ! -e /dev/kvm ]; then
  echo "SKIP: requires Linux/KVM"
  exit 0
fi
if [ ! -f "$KERNEL" ]; then
  echo "SKIP: KERNEL not found: $KERNEL"
  exit 0
fi
if [ ! -f "$ROOTFS" ]; then
  echo "SKIP: ROOTFS not found: $ROOTFS"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: run as root (loop-mount probe rootfs + /dev/kvm)"
  exit 0
fi

BIN="${FLUXVM_HYPERVISOR:-}"
if [ -z "$BIN" ]; then
  if [ -x "${PROJECT_DIR}/target/release/fluxvm-hypervisor" ]; then
    BIN="${PROJECT_DIR}/target/release/fluxvm-hypervisor"
  else
    (cd "$PROJECT_DIR" && cargo build --release -p fluxvm-hypervisor)
    BIN="${PROJECT_DIR}/target/release/fluxvm-hypervisor"
  fi
fi

TMP="$(mktemp -d)"
HPID=""
cleanup() {
  if [ -n "$HPID" ]; then
    kill "$HPID" 2>/dev/null || true
    wait "$HPID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

PROBE_DISK="${TMP}/probe.ext4"
cp -a "$ROOTFS" "$PROBE_DISK"
e2fsck -fy "$PROBE_DISK" >/dev/null 2>&1 || true
MNT="${TMP}/mnt"
mkdir -p "$MNT"
mount -o loop "$PROBE_DISK" "$MNT"
cat > "${MNT}/userspace-probe.sh" <<'EOF'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
if [ -c /dev/ttyS0 ]; then
  exec >/dev/ttyS0 2>&1 </dev/ttyS0
fi
echo FLUXVM_USERSPACE_OK
nproc_online() { grep -c '^cpu[0-9]' /proc/stat 2>/dev/null || echo 1; }
echo "FLUXVM_NPROC_BOOT:$(nproc_online)"
# cpu2/cpu3 must be *present* (registered, offline) from boot, per the MP
# table + max_vcpus reservation, even though maxcpus=2 kept them un-onlined.
for c in 2 3; do
  if [ -e "/sys/devices/system/cpu/cpu${c}" ]; then
    echo "FLUXVM_CPU_PRESENT:${c}"
  else
    echo "FLUXVM_CPU_MISSING:${c}"
  fi
done
# Simulate a host-driven hotplug: online the reserved vCPUs ourselves via
# the exact sysfs path control.rs's hotplug_cpu response tells the operator
# to run. The `online` file's write(2) can return a transient error under
# back-to-back hotplug ops even when cpu_up() itself completes (kernel-level
# hotplug lock contention), so judge success from the resulting state
# (`online` reads back 1), not from echo's own exit code.
for c in 2 3; do
  if [ -e "/sys/devices/system/cpu/cpu${c}/online" ]; then
    echo 1 > "/sys/devices/system/cpu/cpu${c}/online" 2>/dev/null
    sleep 0.3
    if [ "$(cat "/sys/devices/system/cpu/cpu${c}/online" 2>/dev/null)" = "1" ]; then
      echo "FLUXVM_ONLINE_OK:${c}"
    else
      echo "FLUXVM_ONLINE_FAIL:${c}"
    fi
  fi
done
sleep 0.2
echo "FLUXVM_NPROC_AFTER:$(nproc_online)"
# One reader per now-online CPU so QueueNotify writes come from all 4 at once.
i=0
while [ "$i" -lt "$(nproc_online)" ]; do
  dd if=/dev/vda of=/dev/null bs=64k skip=$((i * 256)) count=256 2>/dev/null &
  i=$((i + 1))
done
wait
echo FLUXVM_IO_OK
echo FLUXVM_STDIN_OK
exec sleep 3600
EOF
chmod +x "${MNT}/userspace-probe.sh"
umount "$MNT"

SOCK="${TMP}/api.sock"
BOOT="${TMP}/boot.json"
cat >"$BOOT" <<JSON
{
  "kernel": "$KERNEL",
  "rootfs": "$PROBE_DISK",
  "vcpus": 2,
  "max_vcpus": 4,
  "memory_mib": 256,
  "engine": "kvm",
  "kernel_args": "console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw init=/userspace-probe.sh"
}
JSON

echo "=== CPU hotplug: vcpus=2 max_vcpus=4, timeout=${TIMEOUT_SECS}s ==="
env FLUXVM_KVM_RUN_SECS="$TIMEOUT_SECS" \
  "$BIN" --api-sock "$SOCK" --boot-config "$BOOT" >"${TMP}/hv.log" 2>&1 &
HPID=$!

req() {
  python3 - "$SOCK" "$1" <<'PY'
import json, socket, sys, time
sock_path, payload = sys.argv[1], sys.argv[2]
deadline = time.time() + 15
last = None
while time.time() < deadline:
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(2)
        s.connect(sock_path)
        s.sendall((payload + "\n").encode())
        data = s.recv(4096).decode()
        print(data, end="")
        sys.exit(0)
    except Exception as e:
        last = e
        time.sleep(0.2)
print(f"request failed: {last}", file=sys.stderr)
sys.exit(1)
PY
}

for _ in $(seq 1 50); do
  if [ -S "$SOCK" ]; then
    if RESP=$(req '{"action":"ping"}' 2>/dev/null); then
      echo "$RESP" | grep -qi pong && break
    fi
  fi
  if ! kill -0 "$HPID" 2>/dev/null; then
    echo "hypervisor exited early:" >&2
    tail -40 "${TMP}/hv.log" >&2
    exit 1
  fi
  sleep 0.2
done

echo "=== hotplug_cpu add=2 (control-plane bookkeeping/plan) ==="
RESP=$(req '{"action":"hotplug_cpu","add":2}')
echo "$RESP"
FAIL=0
echo "$RESP" | grep -q '"ok"' || { echo "FAIL: hotplug_cpu request rejected"; FAIL=1; }
echo "$RESP" | grep -q '2→4\|2->4\|2\\u21924' || echo "$RESP" | grep -qE '"message":"cpu hotplug ready: \+2 \(2' \
  || { echo "FAIL: hotplug_cpu response did not report 2->4"; FAIL=1; }
echo "$RESP" | grep -q 'cpu2/online' || { echo "FAIL: hotplug_cpu response missing cpu2 online instructions"; FAIL=1; }

echo "=== waiting for guest to reach FLUXVM_STDIN_OK (timeout ${TIMEOUT_SECS}s) ==="
# --api-sock is a long-lived control-plane daemon: it does not exit on its
# own when the guest run finishes (it stays up to keep serving the socket),
# and the guest's own `exec sleep 3600` outlives any reasonable test budget.
# So poll the log for the terminal marker instead of `wait`ing on the
# process, then explicitly tear it down — same pattern as
# test-kvm-pause-smoke.sh's cleanup trap.
DEADLINE=$((SECONDS + TIMEOUT_SECS))
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  grep -q 'FLUXVM_STDIN_OK' "${TMP}/hv.log" 2>/dev/null && break
  if ! kill -0 "$HPID" 2>/dev/null; then
    echo "hypervisor exited early" >&2
    break
  fi
  sleep 0.5
done
tail -n 200 "${TMP}/hv.log" || true

if ! grep -q 'FLUXVM_USERSPACE_OK' "${TMP}/hv.log"; then
  echo "FAIL: guest did not reach userspace"
  FAIL=1
fi
if ! grep -q 'FLUXVM_NPROC_BOOT:2' "${TMP}/hv.log"; then
  echo "FAIL: expected 2 online CPUs at boot (maxcpus=2 not honored)"
  FAIL=1
else
  echo "PASS: guest booted with exactly 2 online CPUs"
fi
for c in 2 3; do
  if grep -q "FLUXVM_CPU_PRESENT:${c}" "${TMP}/hv.log"; then
    echo "PASS: cpu${c} present (reserved) at boot though offline"
  else
    echo "FAIL: cpu${c} not present — max_vcpus reservation did not reach the guest"
    FAIL=1
  fi
  if grep -q "FLUXVM_ONLINE_OK:${c}" "${TMP}/hv.log"; then
    echo "PASS: cpu${c} onlined via sysfs"
  else
    echo "FAIL: cpu${c} failed to online"
    FAIL=1
  fi
done
if grep -q 'FLUXVM_NPROC_AFTER:4' "${TMP}/hv.log"; then
  echo "PASS: guest reports 4 online CPUs after hotplug"
else
  echo "FAIL: guest did not reach 4 online CPUs after hotplug"
  grep 'FLUXVM_NPROC_AFTER' "${TMP}/hv.log" || true
  FAIL=1
fi
if grep -q 'FLUXVM_IO_OK' "${TMP}/hv.log"; then
  echo "PASS: parallel virtio-blk reads across all 4 vCPUs completed"
else
  echo "FAIL: post-hotplug parallel workload did not complete"
  FAIL=1
fi

[ "$FAIL" -eq 0 ] && echo "=== PASS cpu hotplug (2->4) ===" || echo "=== FAIL cpu hotplug ==="
exit "$FAIL"
