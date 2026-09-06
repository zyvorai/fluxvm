#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Gated Windows offline-customize smoke test. Skips unless WINDOWS_IMAGE is set
# to a Windows qcow2/raw disk. Does not boot the guest.
#
# Usage:
#   WINDOWS_IMAGE=/path/to/win.qcow2 \
#   WINDOWS_AGENT_EXE=/path/to/guestkitd.exe \
#   [VIRTIO_SERIAL_DIR=/usr/share/virtio-win/vioserial/w10/amd64] \
#   sudo -E ./scripts/test-windows-customize.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FLUXVM_BIN="${FLUXVM_BIN:-$ROOT/target/release/fluxvm}"
OUT_DIR="${OUT_DIR:-/tmp/fluxvm-windows-customize}"
mkdir -p "$OUT_DIR"

if [[ -z "${WINDOWS_IMAGE:-}" ]]; then
  echo "SKIP: set WINDOWS_IMAGE to a Windows disk image to run this test"
  exit 0
fi

if [[ ! -f "$WINDOWS_IMAGE" ]]; then
  echo "ERROR: WINDOWS_IMAGE not found: $WINDOWS_IMAGE" >&2
  exit 1
fi

if [[ ! -x "$FLUXVM_BIN" ]]; then
  echo "Building fluxvm-cli…"
  (cd "$ROOT" && cargo build --release -p fluxvm-cli -p fluxvm-image)
  FLUXVM_BIN="$ROOT/target/release/fluxvm"
fi

SPEC="$OUT_DIR/build-image-windows.json"
OUTPUT="$OUT_DIR/windows-custom.qcow2"
rm -f "$OUTPUT"

AGENT_JSON="null"
if [[ -n "${WINDOWS_AGENT_EXE:-}" ]]; then
  DRIVER_JSON="null"
  if [[ -n "${VIRTIO_SERIAL_DIR:-}" ]]; then
    DRIVER_JSON=$(printf '%s' "$VIRTIO_SERIAL_DIR" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
  fi
  BIN_JSON=$(printf '%s' "$WINDOWS_AGENT_EXE" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
  if [[ "$DRIVER_JSON" == "null" ]]; then
    AGENT_JSON=$(printf '{"binary":%s}' "$BIN_JSON")
  else
    AGENT_JSON=$(printf '{"binary":%s,"virtio_serial_driver":%s}' "$BIN_JSON" "$DRIVER_JSON")
  fi
fi

SRC_JSON=$(printf '%s' "$WINDOWS_IMAGE" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
OUT_JSON=$(printf '%s' "$OUTPUT" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')

cat >"$SPEC" <<EOF
{
  "source": $SRC_JSON,
  "output": $OUT_JSON,
  "format": "qcow2",
  "windows": {
    "hostname": "fluxvm-win-test",
    "enable_rdp": true,
    "firewall_open": [
      { "name": "FluxVMTest", "port": 18080, "protocol": "tcp" }
    ],
    "scripts": [
      {
        "name": "marker",
        "powershell": true,
        "content": "Set-Content -Path C:\\\\fluxvm-customize-ok.txt -Value ok\\r\\n"
      }
    ],
    "agent": $AGENT_JSON
  }
}
EOF

# Drop agent key entirely when no binary was provided (null is invalid for the struct).
if [[ "$AGENT_JSON" == "null" ]]; then
  python3 - "$SPEC" <<'PY'
import json, sys
p = sys.argv[1]
with open(p) as f:
    d = json.load(f)
d["windows"].pop("agent", None)
with open(p, "w") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY
fi

echo "Running: $FLUXVM_BIN build-image --spec $SPEC"
"$FLUXVM_BIN" build-image --spec "$SPEC"
echo "OK: wrote $OUTPUT"
