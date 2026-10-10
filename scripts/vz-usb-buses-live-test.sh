#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live test of `apple.usb_controllers`: two XHCI buses, a USB disk hot-attached to each, and a detach of the second.
#   scripts/vz-usb-buses-live-test.sh [image]
# Needs Apple silicon macOS 15+, the Xcode command line tools, Rust and python3.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-usbbus.XXXXXX")"; PORT="${FLUXVM_LIVE_PORT:-7799}"
cleanup() {
  [[ -n "${DPID:-}" ]] && kill "$DPID" 2>/dev/null || true
  pkill -f "fluxvm-vz-runner run --config $T" 2>/dev/null || true
  sleep 1; rm -rf "$T"
}
trap cleanup EXIT
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; [[ -f "$T/daemon.log" ]] && tail -5 "$T/daemon.log"; exit 1; }
cargo build -p fluxctl -j 4 2>&1 | tail -1
IMG="${1:-debian-13}"
ssh-keygen -q -t ed25519 -N "" -f "$T/key" && PUB="$(cat "$T/key.pub")"
mkfile -n 64m "$T/a.img"; mkfile -n 96m "$T/b.img"
cat > "$T/fluxvm.toml" <<EOT
listen = "127.0.0.1:$PORT"
state_dir = "$T/state"
run_dir = "/tmp/fluxvm-run-usbbus"
EOT
./target/debug/fluxctl --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
B="http://127.0.0.1:$PORT/v1/vms"
code() { curl -s -o /dev/null -w '%{http_code}' -X POST "$@"; }
[[ "$(code "$B" -H 'Content-Type: application/json' -d "{\"name\":\"bad\",\"backend\":\"vz\",\"image\":\"$IMG\",\"apple\":{\"usb_controllers\":9}}")" == 400 ]] \
  && ok "9 controllers refused" || bad "9 controllers accepted"
REQ="{\"name\":\"usbbus\",\"backend\":\"vz\",\"image\":\"$IMG\",\"vcpus\":2,\"memory_mib\":2048,\"apple\":{\"usb_controllers\":2},
  \"cloud_init\":{\"hostname\":\"usbbus\",\"user\":\"velora\",\"ssh_authorized_keys\":[\"$PUB\"]}}"
RESP="$(curl -sS -X POST "$B" -H 'Content-Type: application/json' -d "$REQ")"
ID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$RESP" 2>/dev/null)" || bad "create: $RESP"
V="$B/$ID"
field() { curl -fs "$V" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
IP=""; for _ in $(seq 1 60); do IP="$(field guest_ip)"; [[ -n "$IP" ]] && break; sleep 3; done
[[ -n "$IP" ]] || bad "no guest_ip"
sshc() { ssh -i "$T/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 "velora@$IP" "$@"; }
for _ in $(seq 1 30); do sshc true >/dev/null 2>&1 && break; sleep 3; done
sshc true || bad "ssh to $IP"
XHCI="$(sshc 'cat /sys/bus/pci/devices/*/class 2>/dev/null | grep -c 0x0c0330 || true')"
[[ "$XHCI" -ge 2 ]] && ok "the guest sees $XHCI XHCI controllers (2 configured)" || bad "guest sees $XHCI XHCI controllers"
attach() { curl -sS -X POST "$V/disks" -H 'Content-Type: application/json' -d "{\"name\":\"$1\",\"path\":\"$T/$1.img\",\"controller\":\"usb\",\"usb_bus\":$2}"; }
attach a 0 | grep -q '"name"' && ok "disk a hot-attached on bus 0" || bad "attach a failed"
attach b 1 | grep -q '"name"' && ok "disk b hot-attached on bus 1" || bad "attach b failed"
[[ "$(code "$V/disks" -H 'Content-Type: application/json' -d "{\"name\":\"c\",\"path\":\"$T/a.img\",\"controller\":\"usb\",\"usb_bus\":2}")" == 400 ]] \
  && ok "bus 2 refused (only 2 controllers)" || bad "bus 2 accepted"
sleep 3
SIZES="$(sshc 'lsblk -bdnr -o NAME,SIZE,TRAN | awk "\$3==\"usb\"{print \$2}" | sort -n | tr "\n" " "')"
[[ "$SIZES" == "67108864 100663296 " ]] && ok "both USB disks visible in the guest ($SIZES)" || bad "guest sees '$SIZES'"
BUSES="$(sshc 'for d in /sys/block/sd*; do readlink -f $d | grep -o "usb[0-9]*" | head -1; done | sort -u | wc -l')"
[[ "$BUSES" -ge 2 ]] && ok "the disks sit on $BUSES different USB buses" || bad "disks share one bus ($BUSES)"
curl -fs -X DELETE "$V/disks/b" >/dev/null && ok "bus-1 disk detached" || bad "detach b failed"
sleep 2
[[ "$(sshc 'lsblk -dnr -o TRAN | grep -c usb')" == 1 ]] && ok "one USB disk left" || bad "detach did not reach the guest"
curl -fs -X DELETE "$V" >/dev/null || true
echo "usb buses: PASS"
