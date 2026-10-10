#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live test of `vz` devices on a Linux guest: extra disks of every kind and controller (image on virtio, NVMe and USB, a
# host block device, an NBD export), a USB disk hot-attached and detached while running, a named console port both
# ways, and the Linux display size.
#   scripts/vz-devices-live-test.sh [path/to/arm64-linux-image.raw]
# Needs Apple silicon with macOS 14 or later, the Xcode command line tools, Rust and python3. Without an image argument
# FluxVM fetches the built-in `debian-13`.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-devices.XXXXXX")"; PORT="${FLUXVM_LIVE_PORT:-7797}"; NBD_PORT="${FLUXVM_LIVE_NBD_PORT:-10899}"
RAM=""
cleanup() {
  [[ -n "${DPID:-}" ]] && kill "$DPID" 2>/dev/null || true
  [[ -n "${NPID:-}" ]] && kill "$NPID" 2>/dev/null || true
  pkill -f "fluxvm-vz-runner run --config $T" 2>/dev/null || true
  sleep 1; [[ -n "$RAM" ]] && hdiutil detach "$RAM" >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; [[ -f "$T/daemon.log" ]] && tail -5 "$T/daemon.log"; exit 1; }
MIB=$((1 << 20))

cargo build -p fluxctl -j 4 2>&1 | tail -1
IMG="${1:-debian-13}"
ssh-keygen -q -t ed25519 -N "" -f "$T/key" && PUB="$(cat "$T/key.pub")"

# One size per disk, so the guest can tell them apart.
mkfile -n 64m "$T/virtio.img"; mkfile -n 96m "$T/nvme.img"; mkfile -n 80m "$T/usb.img"; mkfile -n 48m "$T/nbd.img"
RAM="$(hdiutil attach -nomount ram://147456 2>/dev/null | awk '{print $1}')"   # 72 MiB
[[ -r "$RAM" && -w "$RAM" ]] && ok "host block device $RAM" || bad "could not make a RAM disk"
python3 scripts/nbd-test-server.py "$T/nbd.img" "$NBD_PORT" disk & NPID=$!
sleep 1; kill -0 "$NPID" && ok "NBD test server on 127.0.0.1:$NBD_PORT" || bad "NBD server did not start"

cat > "$T/fluxvm.toml" <<EOT
listen = "127.0.0.1:$PORT"
state_dir = "$T/state"
run_dir = "/tmp/fluxvm-run-devices"
EOT
./target/debug/fluxctl --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && ok "daemon is up" || bad "daemon did not start"

B="http://127.0.0.1:$PORT/v1/vms"
DISKS="[
  {\"name\":\"vblk\",\"path\":\"$T/virtio.img\"},
  {\"name\":\"fast\",\"path\":\"$T/nvme.img\",\"controller\":\"nvme\",\"caching\":\"uncached\",\"sync\":\"fsync\"},
  {\"name\":\"stick\",\"path\":\"$T/usb.img\",\"controller\":\"usb\"},
  {\"name\":\"raw\",\"kind\":\"block\",\"path\":\"$RAM\"},
  {\"name\":\"net\",\"kind\":\"nbd\",\"url\":\"nbd://127.0.0.1:$NBD_PORT/disk\"}
]"
REQ="{\"name\":\"devices\",\"backend\":\"vz\",\"image\":\"$IMG\",\"vcpus\":2,\"memory_mib\":2048,
  \"apple\":{\"usb_controller\":true,\"display_width\":1600,\"display_height\":900,\"console_ports\":[\"test\"],\"extra_disks\":$DISKS},
  \"cloud_init\":{\"hostname\":\"devices\",\"user\":\"velora\",\"ssh_authorized_keys\":[\"$PUB\"]}}"
RESP="$(curl -sS -X POST "$B" -H 'Content-Type: application/json' -d "$REQ")"
ID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$RESP" 2>/dev/null)" || bad "create: $RESP"
V="$B/$ID"
field() { curl -fs "$V" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
[[ "$(field status)" == running ]] && ok "VM with five extra disks is running" || bad "status $(field status)"
IP=""; for _ in $(seq 1 60); do IP="$(field guest_ip)"; [[ -n "$IP" ]] && break; sleep 3; done
[[ -n "$IP" ]] || bad "no guest_ip"
sshc() { ssh -i "$T/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 "velora@$IP" "$@"; }
for _ in $(seq 1 30); do sshc true >/dev/null 2>&1 && break; sleep 3; done
sshc true || bad "ssh to $IP"
ok "SSH to the guest at $IP"

# name:transport for the disk of a given size, e.g. "nvme0n1:nvme".
disk_of() { sshc "lsblk -bdnr -o NAME,SIZE,TRAN" | awk -v s=$(( $1 * MIB )) '$2 == s { print $1 ":" $3 }' | head -1; }
check_disk() { # size_mib label want_prefix want_tran
  local d; d="$(disk_of "$1")"
  [[ "$d" == "$3"*":$4" || ( -z "$4" && "$d" == "$3"* ) ]] && ok "$2: /dev/${d%%:*}" || bad "$2: got '$d'; lsblk: $(sshc 'lsblk -bdn -o NAME,SIZE,TRAN' | tr '\n' ';')"
  # Write a marker through the guest and read it back from a fresh open.
  sshc "echo $2-ok | sudo dd of=/dev/${d%%:*} bs=512 count=1 conv=fsync status=none && sudo dd if=/dev/${d%%:*} bs=512 count=1 iflag=direct status=none | head -c ${#2}" \
    | grep -qx "$2" && ok "$2: guest write and read back" || bad "$2: I/O failed"
}
check_disk 64 virtio vd ""
check_disk 96 nvme nvme nvme
check_disk 80 usb sd usb
check_disk 72 block vd ""
check_disk 48 nbd vd ""
[[ "$(head -c 6 "$T/nbd.img")" == nbd-ok ]] && ok "nbd: the guest's write reached the export on the host" || bad "nbd write not on the host"

# Hot-plug: a 1 GiB USB disk attached and detached while the VM runs.
ATT="$(curl -sS -X POST "$V/disks" -H 'Content-Type: application/json' -d '{"name":"hot","size_gib":1,"controller":"usb"}')"
for _ in $(seq 1 20); do [[ -n "$(disk_of 1024)" ]] && break; sleep 1; done
[[ "$(disk_of 1024)" == sd*:usb ]] && ok "hot-attach: a USB disk appears in the running guest ($(disk_of 1024))" || bad "hot-attach: $ATT"
curl -fsS "$V/disks" | grep -q '"hot"' && ok "the disk is listed" || bad "hot disk not listed"
curl -fsS -X DELETE "$V/disks/hot" >/dev/null || bad "detach request failed"
for _ in $(seq 1 20); do [[ -z "$(disk_of 1024)" ]] && break; sleep 1; done
[[ -z "$(disk_of 1024)" ]] && ok "hot-detach: the USB disk is gone from the guest" || bad "hot-detach: still $(disk_of 1024)"

# Console port: host to guest and back over the runner's unix socket.
SOCK="/tmp/fluxvm-$(id -u)/$(tr -d - <<<"$ID").port-test"
[[ -S "$SOCK" ]] && ok "console port socket $SOCK" || bad "no console port socket"
sshc '[ -e /dev/virtio-ports/test ]' && ok "guest sees /dev/virtio-ports/test" || bad "no /dev/virtio-ports/test in the guest"
# The host connects first (guest output with no client is dropped) and answers once the guest has spoken (input to a
# port the guest has not opened is dropped); the guest keeps one descriptor open for both directions.
python3 - "$SOCK" > "$T/port.out" <<'EOF' & HPID=$!
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.settimeout(30)
buf = b""
while b"from-guest" not in buf:
    chunk = s.recv(256)
    if not chunk:
        break
    buf += chunk
s.sendall(b"from-host\n")
print(buf.decode(errors="replace").strip())
EOF
sleep 1
sshc 'sudo sh -c "exec 3<>/dev/virtio-ports/test; echo from-guest >&3; timeout 20 head -n1 <&3 > /tmp/port.in"' || true
wait "$HPID" || true
GOT="$(cat "$T/port.out")"
[[ "$(sshc 'cat /tmp/port.in')" == from-host ]] && ok "console port: host to guest" || bad "console port: guest read '$(sshc 'cat /tmp/port.in')'"
[[ "$GOT" == *from-guest* ]] && ok "console port: guest to host" || bad "console port: host read '$GOT'"

# Display: the Linux scanout takes display_width x display_height.
MODE="$(sshc 'cat /sys/class/drm/card*-Virtual-1/modes 2>/dev/null | head -1')"
if [[ -n "$MODE" ]]; then
  [[ "$MODE" == 1600x900 ]] && ok "display: the guest's preferred mode is 1600x900" || bad "display mode $MODE"
else
  echo "skip display: the guest kernel has no virtio-gpu DRM device ($(sshc 'ls /sys/class/drm 2>&1 | tr "\n" " "'))"
fi

curl -fs -X DELETE "$V" >/dev/null || true
echo "all vz device checks passed"
