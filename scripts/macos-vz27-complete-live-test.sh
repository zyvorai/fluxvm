#!/bin/bash
set -euo pipefail
: "${FLUXVM_TEST_VM:?set FLUXVM_TEST_VM to a running Linux VZ VM id}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v sw_vers >/dev/null
[[ "$(uname -m)" == arm64 ]]
major="$(sw_vers -productVersion | cut -d. -f1)"
(( major >= 27 )) || { echo "macOS 27+ required" >&2; exit 2; }

cargo build -p fluxvm-apple
cargo test -p fluxvm-apple
cargo clippy -p fluxvm-apple -- -D warnings
bash -n "$ROOT/crates/fluxvm-apple/macos/vmnetd/build-install.sh"
bash -n "$ROOT/crates/fluxvm-apple/macos/usbd/build-install.sh"

RUNNER="${FLUXVM_VZ_RUNNER:-$(find target -name fluxvm-vz-runner -type f | head -1)}"
"$RUNNER" host-capabilities | python3 -m json.tool

cat <<EOF
MANUAL/HARDWARE STEPS REQUIRED:
  1. Build/load guest/virtio-flux/virtio_flux.ko in VM $FLUXVM_TEST_VM.
  2. Run fluxvm-virtioctl ping, capabilities, bulk-test.
  3. Install vmnetd and boot two VMs with the same apple.vmnet.name; verify TCP+UDP.
  4. Install FluxVMUSBAccess.app, grant a USB device in Accessory Access, list/attach/detach it.
  5. Register two Macs with fluxvm-agent central and verify capability-aware VZ placement.
EOF
