#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Smoke: in-tree KVM pause parks the vCPU thread (no KVM_RUN) and resume
# continues. Uses the JSON-line UDS control API on fluxvm-hypervisor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"

[ "$(uname -s)" = "Linux" ] || { echo "requires Linux/KVM" >&2; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm missing" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "KERNEL missing: $KERNEL" >&2; exit 1; }
[ -f "$ROOTFS" ] || { echo "ROOTFS missing: $ROOTFS" >&2; exit 1; }

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

SOCK="${TMP}/api.sock"
BOOT="${TMP}/boot.json"
cat >"$BOOT" <<JSON
{
  "kernel": "$KERNEL",
  "rootfs": "$ROOTFS",
  "vcpus": 1,
  "memory_mib": 256,
  "engine": "kvm",
  "kernel_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/bin/sleep -- 3600 virtio_mmio.device=0x200@0xfeb00000:5 virtio_mmio.device=0x200@0xfeb00200:6"
}
JSON

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

# Wait until Ping works (API bound + boot started).
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

echo "=== Pause ==="
RESP=$(req '{"action":"pause"}')
echo "$RESP"
echo "$RESP" | grep -q '"lifecycle":"paused"' || {
  echo "pause failed: $RESP" >&2
  tail -40 "${TMP}/hv.log" >&2
  exit 1
}
sleep 0.5
echo "=== Resume ==="
RESP=$(req '{"action":"resume"}')
echo "$RESP"
echo "$RESP" | grep -q '"lifecycle":"running"' || {
  echo "resume failed: $RESP" >&2
  exit 1
}
echo "=== PASS pause/resume ==="
