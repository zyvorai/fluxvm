#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Snapshot forward-progress test for the in-tree KVM engine.
#
# The plain snapshot smoke only proves restore returns ok. This one boots a
# guest that prints an ever-increasing TICK every second and runs a CPU loop
# plus a checksummed disk workload, then: pause -> snapshot -> resume (guest
# runs on) -> restore, and asserts the restored guest
#   * continues from the snapshot moment (its tick counter rewinds to about
#     the snapshot value, not the later value it had reached),
#   * keeps ticking at ~1/s of wall time (timers, LAPIC, kvm-clock work),
#   * keeps the disk workload running with no checksum mismatch.
#
#   sudo ./scripts/test-kvm-snapshot-progress.sh            # VCPUS=1 (default)
#   sudo VCPUS=2 ./scripts/test-kvm-snapshot-progress.sh
#   sudo MODE=v4 ./scripts/test-kvm-snapshot-progress.sh    # informational
#
# MODE=v4 downgrades the saved vmstate to the old register-only FLUXKVM1 v4
# layout before restoring and reports (never fails on) what that does; it
# documents what full-fidelity v5 restore fixed.
#
# Soft-skips (printing a line starting with SKIP) when KVM, assets or root are
# missing; CI treats SKIP as a failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
VCPUS="${VCPUS:-1}"
MODE="${MODE:-v5}"
MEMORY_MIB="${MEMORY_MIB:-256}"
BOOT_WAIT="${BOOT_WAIT:-90}"

[ "$(uname -s)" = "Linux" ] && [ -e /dev/kvm ] || { echo "SKIP: requires Linux/KVM"; exit 0; }
[ -f "$KERNEL" ] || { echo "SKIP: KERNEL not found: $KERNEL"; exit 0; }
[ -f "$ROOTFS" ] || { echo "SKIP: ROOTFS not found: $ROOTFS"; exit 0; }
[ "$(id -u)" -eq 0 ] || { echo "SKIP: run as root (loop mount to inject the probe)"; exit 0; }

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
  mountpoint -q "${TMP}/mnt" 2>/dev/null && umount "${TMP}/mnt" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; tail -n 40 "${TMP}/hv.log" | grep -av '^\[blk\]' >&2 || true; exit 1; }

# --- probe disk: a private copy of the rootfs with the probe as init ---------
DISK="${TMP}/probe.ext4"
cp --sparse=always "$ROOTFS" "$DISK"
e2fsck -fy "$DISK" >/dev/null 2>&1 || true
mkdir -p "${TMP}/mnt"
mount -o loop "$DISK" "${TMP}/mnt"
cat > "${TMP}/mnt/probe.sh" <<'EOF'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
if [ -c /dev/ttyS0 ]; then
  exec >/dev/ttyS0 2>&1 </dev/ttyS0
fi
echo PROBE_START
# checksummed disk workload
(
  i=0
  while true; do
    dd if=/dev/urandom of=/wl.bin bs=64k count=16 2>/dev/null
    a=$(md5sum /wl.bin | cut -d' ' -f1)
    sync
    b=$(md5sum /wl.bin | cut -d' ' -f1)
    if [ "$a" = "$b" ]; then echo "DISK_OK $i"; else echo "DISK_BAD $i"; fi
    i=$((i + 1))
  done
) &
# CPU workload
( while true; do i=0; while [ "$i" -lt 20000 ]; do i=$((i + 1)); done; done ) &
n=0
while true; do
  up=$(cut -d' ' -f1 /proc/uptime)
  echo "TICK $n $up"
  n=$((n + 1))
  sleep 1
done
EOF
chmod +x "${TMP}/mnt/probe.sh"
umount "${TMP}/mnt"

SOCK="${TMP}/api.sock"
BOOT="${TMP}/boot.json"
SNAP="${TMP}/snap"
cat >"$BOOT" <<JSON
{
  "kernel": "$KERNEL",
  "rootfs": "$DISK",
  "vcpus": ${VCPUS},
  "memory_mib": ${MEMORY_MIB},
  "engine": "kvm",
  "kernel_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/probe.sh"
}
JSON

"$BIN" --api-sock "$SOCK" --boot-config "$BOOT" >"${TMP}/hv.log" 2>&1 &
HPID=$!

req() {
  python3 - "$SOCK" "$1" "${2:-30}" <<'PY'
import socket, sys, time
sock_path, payload, timeout = sys.argv[1], sys.argv[2], float(sys.argv[3])
deadline = time.time() + timeout
last = None
while time.time() < deadline:
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(max(5.0, timeout))
        s.connect(sock_path)
        s.sendall((payload + "\n").encode())
        print(s.recv(8192).decode(), end="")
        sys.exit(0)
    except Exception as e:
        last = e
        time.sleep(0.2)
print(f"request failed: {last}", file=sys.stderr)
sys.exit(1)
PY
}

# Last "TICK n uptime" line after line number $1 (default 0).
last_tick() { awk -v from="${1:-0}" 'NR>from && /TICK [0-9]+ [0-9]+\.[0-9][0-9]/ {l=$0} END{print l}' "${TMP}/hv.log" | grep -ao 'TICK [0-9]* [0-9]*\.[0-9][0-9]' | tail -1; }
tick_field() { echo "$1" | awk -v f="$2" '{print $f}'; }
log_lines() { wc -l < "${TMP}/hv.log" | tr -d ' '; }
wait_ticks() {  # wait_ticks FROM_LINE MIN_COUNT TIMEOUT
  local from="$1" want="$2" t="$3" end=$((SECONDS + $3)) c
  while [ "$SECONDS" -lt "$end" ]; do
    c=$(awk -v from="$from" 'NR>from && /TICK [0-9]+ [0-9]+\.[0-9][0-9]/ {n++} END{print n+0}' "${TMP}/hv.log")
    [ "$c" -ge "$want" ] && return 0
    kill -0 "$HPID" 2>/dev/null || fail "hypervisor exited"
    sleep 0.5
  done
  return 1
}

echo "=== snapshot progress: mode=${MODE} vcpus=${VCPUS} ==="
for _ in $(seq 1 50); do
  [ -S "$SOCK" ] && req '{"action":"ping"}' 5 2>/dev/null | grep -qi pong && break
  kill -0 "$HPID" 2>/dev/null || fail "hypervisor exited early"
  sleep 0.2
done

wait_ticks 0 6 "$BOOT_WAIT" || fail "guest never produced 6 ticks (boot problem, not a snapshot problem)"
sleep 3   # let the CPU and disk workloads get going

echo "=== pause + snapshot ==="
req '{"action":"pause"}' 30 | grep -q '"lifecycle":"paused"' || fail "pause failed"
T0="$(last_tick)"
N0="$(tick_field "$T0" 2)"; U0="$(tick_field "$T0" 3)"
D0="$(grep -ac 'DISK_OK' "${TMP}/hv.log")"
echo "at snapshot: tick=${N0} uptime=${U0}"
RESP="$(req "{\"action\":\"snapshot_save\",\"path\":\"${SNAP}\"}" 180)"
echo "$RESP" | grep -q '"status":"ok"' || fail "snapshot_save: $RESP"

echo "=== resume: the original guest keeps running past the snapshot ==="
L1="$(log_lines)"
req '{"action":"resume"}' 30 | grep -q '"lifecycle":"running"' || fail "resume failed"
wait_ticks "$L1" 8 40 || fail "guest did not keep ticking after resume"
T1="$(last_tick)"
N1="$(tick_field "$T1" 2)"; U1="$(tick_field "$T1" 3)"
echo "before restore: tick=${N1} uptime=${U1}"
[ "$N1" -ge $((N0 + 6)) ] || fail "guest advanced too little after resume (tick ${N0} -> ${N1})"

if [ "$MODE" = "v4" ]; then
  echo "=== downgrading vmstate to register-only FLUXKVM1 v4 ==="
  python3 - "${SNAP}.vmstate" <<'PY'
import struct, sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
assert b[:8] == b"FLUXKVM1" and struct.unpack_from("<I", b, 8)[0] == 5
ncpu = struct.unpack_from("<I", b, 20)[0]
off = 24 + ncpu * (144 + 312)
ndev = struct.unpack_from("<I", b, off)[0]; off += 4
for _ in range(ndev):
    off += 4 + 8 + 8 + 4 + 4
    nq = struct.unpack_from("<I", b, off)[0]; off += 4
    off += nq * 34
off += ncpu * 4
assert struct.unpack_from("<I", b, off)[0] < 0x20, "v5 section tag expected after the v4 payload"
struct.pack_into("<I", b, 8, 4)
open(p, "wb").write(bytes(b[:off]))
PY
fi

echo "=== restore ==="
L2="$(log_lines)"
RESP="$(req "{\"action\":\"snapshot_restore\",\"path\":\"${SNAP}\"}" 180 || true)"
echo "$RESP" | head -c 200; echo
if [ "$MODE" = "v5" ]; then
  echo "$RESP" | grep -q '"status":"ok"' || fail "snapshot_restore: $RESP"
fi
RL="$(awk -v from="$L2" 'NR>from && /restored FLUXKVM1 snapshot/ {n=NR} END{print n+0}' "${TMP}/hv.log")"
[ "$RL" -gt 0 ] || { [ "$MODE" = "v4" ] && { echo "OBSERVED v4-style restore: restore did not complete"; exit 0; }; fail "no restore line in the hypervisor log"; }

START=$SECONDS
if ! wait_ticks "$RL" 8 60; then
  if [ "$MODE" = "v4" ]; then
    echo "OBSERVED v4-style (register-only) restore: progress=NO (no ticks within 60 s of restore)"
    exit 0
  fi
  fail "restored guest produced no ticks (hung after restore)"
fi
ELAPSED=$((SECONDS - START))
T2="$(awk -v from="$RL" 'NR>from && /TICK [0-9]+ [0-9]+\.[0-9][0-9]/ {print}' "${TMP}/hv.log" | grep -ao 'TICK [0-9]* [0-9]*\.[0-9][0-9]' | head -1)"
T3="$(last_tick "$RL")"
N2="$(tick_field "$T2" 2)"; U2="$(tick_field "$T2" 3)"
N3="$(tick_field "$T3" 2)"
BAD="$(awk -v from="$RL" 'NR>from && /DISK_BAD/ {n++} END{print n+0}' "${TMP}/hv.log")"
OK="$(awk -v from="$RL" 'NR>from && /DISK_OK/ {n++} END{print n+0}' "${TMP}/hv.log")"
echo "after restore: first tick=${N2} (uptime ${U2}), last tick=${N3}, ticks in ${ELAPSED}s wall, DISK_OK=${OK} DISK_BAD=${BAD}"

REWOUND=no; [ "$N2" -le $((N0 + 3)) ] && [ "$N2" -lt "$N1" ] && REWOUND=yes
# The guest clock (kvm-clock/TSC) must resume from the pause instant, not jump
# by the wall time spent between save and restore.
CLOCK=no
awk -v u2="$U2" -v u0="$U0" -v u1="$U1" 'BEGIN{exit !(u2 >= u0 - 1 && u2 <= u0 + 4 && u2 < u1)}' && CLOCK=yes
TIMERS=no;  [ "$N3" -ge $((N2 + 6)) ] && [ "$ELAPSED" -le 20 ] && TIMERS=yes
DISK=no;    [ "$BAD" -eq 0 ] && [ "$OK" -ge 1 ] && DISK=yes
echo "rewound-to-snapshot=${REWOUND} clock-resumed=${CLOCK} timers=${TIMERS} disk=${DISK}"

if [ "$MODE" = "v4" ]; then
  if [ "$REWOUND" = yes ] && [ "$CLOCK" = yes ] && [ "$TIMERS" = yes ] && [ "$DISK" = yes ]; then
    echo "OBSERVED v4-style (register-only) restore: progress=YES (this guest tolerated it)"
  else
    echo "OBSERVED v4-style (register-only) restore: progress=NO"
  fi
  exit 0
fi

[ "$REWOUND" = yes ] || fail "restored guest did not continue from the snapshot (snapshot tick ${N0}, pre-restore tick ${N1}, first restored tick ${N2})"
[ "$CLOCK" = yes ]   || fail "guest clock did not resume from the snapshot (uptime at snapshot ${U0}, before restore ${U1}, first restored ${U2})"
[ "$TIMERS" = yes ]  || fail "restored guest's timers did not run at ~1/s (last tick ${N3}, ${ELAPSED}s wall)"
[ "$DISK" = yes ]    || fail "disk workload broke after restore (DISK_OK=${OK} DISK_BAD=${BAD})"
echo "=== PASS snapshot forward progress (vcpus=${VCPUS}) ==="
