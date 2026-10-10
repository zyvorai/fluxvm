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

# EFI Secure Boot: an EFI guest with an empty disk stays in firmware long enough to read the variable store.
SB="$(mktemp -d /tmp/fluxvm-sb.XXXXXX)"
trap 'rm -rf "$SB"' EXIT
mkfile -n 64m "$SB/disk.raw"
sb_run() {
    cat >"$SB/cfg.json" <<JSON
{"id":"5b0b0000-0000-4000-8000-000000000001","workspace":"$SB","cpus":2,"memory_mib":1024,"guest_os":"linux",
 "disk":"$SB/disk.raw","control_socket":"$SB/c.sock","serial_log":"$SB/serial.log","ip_file":"$SB/ip",
 "network_none":true,"audio_output":false,"usb_controller":true,"label":"fluxvm secure boot test","secure_boot":$1}
JSON
    rm -f "$SB/c.sock"
    "$RUNNER" run --config "$SB/cfg.json" >"$SB/out.log" 2>&1 &
    for _ in $(seq 1 100); do [[ -S "$SB/c.sock" ]] && break; sleep 0.05; done
    printf '{"cmd":"secure-boot-status"}\n' | nc -U -w 2 "$SB/c.sock"
    printf '{"cmd":"usb-list"}\n' | nc -U -w 2 "$SB/c.sock" >/dev/null
    printf '{"cmd":"stop"}\n' | nc -U -w 2 "$SB/c.sock" >/dev/null || true
    wait || true
}
sb_run true | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["ok"] and s["enabled"] and s["kek"] > 0 and s["db"] > 0, s; print("secure boot on:", s)'
sb_run false | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["ok"] and not s["enabled"], s; print("secure boot off:", s)'

cat <<EOF
MANUAL/HARDWARE STEPS REQUIRED:
  1. Build/load guest/virtio-flux/virtio_flux.ko in VM $FLUXVM_TEST_VM.
  2. Run fluxvm-virtioctl ping, capabilities, bulk-test.
  3. Install vmnetd and boot two VMs with the same apple.vmnet.name; verify TCP+UDP.
  4. Install FluxVMUSBAccess.app, grant a USB device in Accessory Access, list/attach/detach it.
  5. Register two Macs with fluxvm-agent central and verify capability-aware VZ placement.
  6. With apple.custom_virtio: virtio-status shows driver_ok; virtio-reset bumps resets and the driver re-probes;
     snapshot save + restore keeps the request counters.
  7. Boot a Microsoft-signed distro (shim) with secure_boot: true and check mokutil --sb-state in the guest.
  8. Save a VM with a passed-through USB device: the reply lists usb_detached and the restore succeeds.
EOF
