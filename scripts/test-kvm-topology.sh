#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Guest CPU topology smoke for the in-tree fluxvm-hypervisor: boots a Linux
# guest with CPUS vCPUs and asserts what the guest kernel derived from our
# CPUID (leaves 1, 4, 0xB, 0x1F): one package, every vCPU its own core, no SMT
# siblings, core_siblings covering all CPUs, and nproc == CPUS.
# Soft-skips (prints a line starting with "SKIP") when KVM/assets are missing.
#
# Usage (Linux/KVM host, root for the loop-mounted probe):
#   sudo env FLUXVM_HYPERVISOR=... CPUS=4 ./scripts/test-kvm-topology.sh
#
# Env: KERNEL, ROOTFS, MEMORY_MIB, TIMEOUT_SECS (default 60), CPUS (default 2),
# MAX_CPUS (optional hotplug headroom passed as --max-cpus; the guest topology
# must NOT depend on it), TOPO_LOG_COPY (optional path to keep the full run log).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"
MEMORY_MIB="${MEMORY_MIB:-512}"
CPUS="${CPUS:-2}"
MAX_CPUS="${MAX_CPUS:-}"

if [ "$(uname -s)" != "Linux" ] || [ ! -e /dev/kvm ]; then
  echo "SKIP: requires Linux/KVM"
  exit 0
fi
if [ ! -f "$KERNEL" ] || [ ! -f "$ROOTFS" ]; then
  echo "SKIP: KERNEL or ROOTFS not found ($KERNEL, $ROOTFS)"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: run as root to inject the userspace probe"
  exit 0
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
trap 'umount "${TMP}/mnt" 2>/dev/null || true; rm -rf "$TMP"' EXIT

PROBE_DISK="${TMP}/probe.ext4"
cp -a "$ROOTFS" "$PROBE_DISK"
e2fsck -fy "$PROBE_DISK" >/dev/null 2>&1 || true
mkdir -p "${TMP}/mnt"
mount -o loop "$PROBE_DISK" "${TMP}/mnt"
cat > "${TMP}/mnt/topology-probe.sh" <<'EOF'
#!/bin/sh
# Running as init: mount /proc and /sys before reading anything.
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
if [ -c /dev/ttyS0 ]; then
  exec >/dev/ttyS0 2>&1 </dev/ttyS0
fi
echo FLUXVM_USERSPACE_OK
for d in /sys/devices/system/cpu/cpu[0-9]*; do
  n=${d##*cpu}
  t=$d/topology
  echo "TOPO cpu=$n core=$(cat $t/core_id) pkg=$(cat $t/physical_package_id) tsib=$(cat $t/thread_siblings_list) csib=$(cat $t/core_siblings_list)"
done
echo "TOPO_NPROC=$(grep -c '^cpu[0-9]' /proc/stat)"
echo "TOPO_VENDOR=$(grep -m1 '^vendor_id' /proc/cpuinfo | cut -d: -f2 | tr -d ' ')"
echo "TOPO_CPUINFO siblings=$(grep -m1 '^siblings' /proc/cpuinfo | cut -d: -f2 | tr -d ' ') cores=$(grep -m1 '^cpu cores' /proc/cpuinfo | cut -d: -f2 | tr -d ' ')"
echo FLUXVM_TOPO_DONE
echo FLUXVM_STDIN_OK
exec sleep 3600
EOF
chmod +x "${TMP}/mnt/topology-probe.sh"
umount "${TMP}/mnt"

CMDLINE="console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw init=/topology-probe.sh"
LOG="${TMP}/run.log"
echo "=== topology: cpus=${CPUS} max_cpus=${MAX_CPUS:-unset} timeout=${TIMEOUT_SECS}s ==="
set +e
timeout --signal=KILL "$((TIMEOUT_SECS + 5))" \
  env FLUXVM_KVM_RUN_SECS="${TIMEOUT_SECS}" FLUXVM_SERIAL_INJECT= \
  "$BIN" --guest linux --memory-mib "$MEMORY_MIB" --cpus "$CPUS" ${MAX_CPUS:+--max-cpus "$MAX_CPUS"} \
  --kernel "$KERNEL" --cmdline "$CMDLINE" --disk "$PROBE_DISK" >"$LOG" 2>&1
set -e

grep -aE '^(TOPO|FLUXVM_)' "$LOG" | sed 's/\r$//' || true
if [ -n "${TOPO_LOG_COPY:-}" ]; then cp "$LOG" "$TOPO_LOG_COPY"; fi

python3 - "$LOG" "$CPUS" <<'PY'
import os
import re
import sys

log, want = sys.argv[1], int(sys.argv[2])
text = open(log, errors="replace").read().replace("\r", "")
# Two views of the guest's serial output, either of which can be imperfect:
# the live stream has the VMM's own [blk]/[net]/... log lines spliced into
# guest lines (removing those lines, newline included, rejoins the guest line),
# and the dump the VMM prints at exit occasionally loses the start of a line.
# Take whatever complete records either view holds.
dump = text.rsplit("[kvm] serial log:", 1)[-1] if "[kvm] serial log:" in text else ""
live = re.sub(r"\[(?:blk|net|vsock|rng|balloon|kvm|bus)\][^\n]*\n", "", text.split("[kvm] serial log:", 1)[0])
views = [dump, live]
rows = {}
for view in views:
    for m in re.finditer(r"^TOPO cpu=(\d+) core=(\d+) pkg=(\d+) tsib=(\S+) csib=(\S+)$", view, re.M):
        cpu, core, pkg, tsib, csib = m.groups()
        rows[int(cpu)] = (int(core), int(pkg), tsib, csib)
def first(pattern):
    for view in views:
        m = re.search(pattern, view, re.M)
        if m:
            return m
    return None
nproc = first(r"^TOPO_NPROC=(\d+)$")
info = first(r"^TOPO_CPUINFO siblings=(\d*) cores=(\d*)$")
vendor = first(r"^TOPO_VENDOR=(\S*)$")
want_vendor = os.environ.get("WANT_VENDOR_ID")
text = dump + "\n" + live
errs = []
if want_vendor and (not vendor or vendor.group(1) != want_vendor):
    errs.append(f"vendor_id={vendor.group(1) if vendor else None!r}, want {want_vendor!r}")
if not info:
    errs.append("no /proc/cpuinfo siblings/cpu cores line")
elif (info.group(1), info.group(2)) != (str(want), str(want)):
    errs.append(f"/proc/cpuinfo siblings={info.group(1)!r} cpu cores={info.group(2)!r}, want {want} and {want}")
if "FLUXVM_TOPO_DONE" not in text:
    errs.append("probe did not finish (guest did not reach userspace or hung)")
if sorted(rows) != list(range(want)):
    errs.append(f"cpus seen {sorted(rows)}, want 0..{want - 1}")
if not nproc or int(nproc.group(1)) != want:
    errs.append(f"nproc {nproc.group(1) if nproc else None}, want {want}")
if rows:
    if len({r[1] for r in rows.values()}) != 1:
        errs.append(f"more than one package: {sorted({r[1] for r in rows.values()})}")
    if sorted(r[0] for r in rows.values()) != list(range(want)):
        errs.append(f"core ids {sorted(r[0] for r in rows.values())}, want distinct 0..{want - 1}")
    want_csib = "0" if want == 1 else f"0-{want - 1}"
    for cpu, (core, pkg, tsib, csib) in sorted(rows.items()):
        if tsib != str(cpu):
            errs.append(f"cpu{cpu} thread_siblings_list={tsib}, want {cpu} (no SMT)")
        if csib != want_csib:
            errs.append(f"cpu{cpu} core_siblings_list={csib}, want {want_csib}")
if errs:
    for e in errs:
        print("FAIL:", e)
    sys.exit(1)
print(f"PASS: guest topology for {want} vCPU(s): 1 package, {want} core(s), no SMT siblings, nproc={want}")
PY
