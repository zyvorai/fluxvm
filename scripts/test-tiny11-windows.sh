#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Gated Windows smoke for Tiny11/Tiny10 (or any Kryton golden) on FluxVM QEMU.
# Skips unless WINDOWS_IMAGE or KRYTON_WINDOWS_IMAGE is set.
#
# Usage:
#   WINDOWS_IMAGE=/var/lib/fluxvm/images/windows-tiny11-golden.qcow2 \
#     sudo -E ./scripts/test-tiny11-windows.sh
#   KRYTON_WINDOWS_IMAGE=../kryton/out/windows-tiny11-golden.qcow2 \
#     sudo -E ./scripts/test-tiny11-windows.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
BIN="${FLUXVM_BIN:-$ROOT/target/release/fluxvm}"
FIRMWARE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}"

WINDOWS_IMAGE="${WINDOWS_IMAGE:-${KRYTON_WINDOWS_IMAGE:-}}"

if [[ -z "${WINDOWS_IMAGE}" ]]; then
  echo "skip: set WINDOWS_IMAGE or KRYTON_WINDOWS_IMAGE to a Windows qcow2"
  exit 0
fi

if [[ ! -f "$WINDOWS_IMAGE" ]]; then
  echo "error: image does not exist: $WINDOWS_IMAGE" >&2
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  if command -v fluxvm >/dev/null 2>&1; then
    BIN="$(command -v fluxvm)"
  else
    echo "Building fluxvm-cli…"
    (cd "$ROOT" && cargo build --release -p fluxvm-cli -p fluxvm-image)
    BIN="$ROOT/target/release/fluxvm"
  fi
fi

SPEC_DIR="$(mktemp -d)"
OUT="$SPEC_DIR/tiny11-custom.qcow2"
ID=""

cleanup() {
  if [[ -n "$ID" ]]; then
    "$BIN" --config "$CONFIG" delete "$ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$SPEC_DIR"
}
trap cleanup EXIT

SRC_JSON=$(printf '%s' "$WINDOWS_IMAGE" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
OUT_JSON=$(printf '%s' "$OUT" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
FW_JSON=$(printf '%s' "$FIRMWARE" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')

cat >"$SPEC_DIR/build.json" <<EOF
{
  "source": $SRC_JSON,
  "output": $OUT_JSON,
  "format": "qcow2",
  "windows": {
    "hostname": "tiny-smoke",
    "enable_rdp": true,
    "firewall_open": [{ "name": "RDP", "port": 3389, "protocol": "tcp" }]
  }
}
EOF

cat >"$SPEC_DIR/create.json" <<EOF
{
  "name": "tiny11-smoke",
  "backend": "qemu",
  "image": $OUT_JSON,
  "vcpus": 2,
  "memory_mib": 2048,
  "disk_size_gib": 32,
  "firmware": $FW_JSON,
  "network": {
    "mode": "user",
    "forwards": [{ "host_port": 13389, "guest_port": 3389, "protocol": "tcp" }]
  },
  "qga": { "enabled": true },
  "ttl_seconds": 900
}
EOF

echo "==> build-image"
sudo -E "$BIN" --config "$CONFIG" build-image --spec "$SPEC_DIR/build.json"

echo "==> create"
CREATE_OUT="$("$BIN" --config "$CONFIG" create --spec "$SPEC_DIR/create.json")"
echo "$CREATE_OUT"
ID="$(printf '%s\n' "$CREATE_OUT" | python3 -c '
import json,sys,re
raw=sys.stdin.read()
try:
    print(json.loads(raw).get("id",""))
except Exception:
    m=re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", raw, re.I)
    print(m.group(0) if m else "")
')"
if [[ -z "$ID" ]]; then
  echo "error: could not parse VM id from create output" >&2
  exit 1
fi
echo "id=$ID"

echo "==> list"
"$BIN" --config "$CONFIG" list

echo "==> qga ping (best-effort; guest must finish boot)"
for _ in $(seq 1 30); do
  if "$BIN" --config "$CONFIG" qga ping "$ID"; then
    echo "qga ready"
    exit 0
  fi
  sleep 10
done

echo "warn: qga did not come up in 300s; VM deleted by trap"
exit 1
