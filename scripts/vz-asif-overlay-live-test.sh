#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live test of `apple.asif_overlay` on a Linux guest (macOS 27+ host): guest writes land in the sparse
# `disk-overlay.asif`, not in the base `root.raw`.
#   scripts/vz-asif-overlay-live-test.sh [image]
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-asif.XXXXXX")"; PORT="${FLUXVM_LIVE_PORT:-7801}"
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
cat > "$T/fluxvm.toml" <<EOT
listen = "127.0.0.1:$PORT"
state_dir = "$T/state"
run_dir = "/tmp/fluxvm-run-asif"
EOT
./target/debug/fluxctl --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
B="http://127.0.0.1:$PORT/v1/vms"
REQ="{\"name\":\"asif\",\"backend\":\"vz\",\"image\":\"$IMG\",\"vcpus\":2,\"memory_mib\":2048,\"apple\":{\"asif_overlay\":true},
  \"cloud_init\":{\"hostname\":\"asif\",\"user\":\"velora\",\"ssh_authorized_keys\":[\"$PUB\"]}}"
RESP="$(curl -sS -X POST "$B" -H 'Content-Type: application/json' -d "$REQ")"
ID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$RESP" 2>/dev/null)" || bad "create: $RESP"
V="$B/$ID"; WS="$T/state/instances/$ID"
field() { curl -fs "$V" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
IP=""; for _ in $(seq 1 60); do IP="$(field guest_ip)"; [[ -n "$IP" ]] && break; sleep 3; done
[[ -n "$IP" ]] || bad "no guest_ip"
sshc() { ssh -i "$T/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 "velora@$IP" "$@"; }
for _ in $(seq 1 30); do sshc true >/dev/null 2>&1 && break; sleep 3; done
sshc true || bad "ssh to $IP"
BEFORE="$(shasum "$WS/root.raw" | cut -d' ' -f1)"
sshc 'sudo sh -c "dd if=/dev/urandom of=/var/asif-test bs=1M count=64 status=none && sync"' || bad "guest write"
OV="$WS/disk-overlay.asif"
[[ -f "$OV" ]] && ok "overlay $OV exists" || bad "no disk-overlay.asif"
SIZE="$(stat -f %z "$OV")"
[[ "$SIZE" -gt $((64 << 20)) ]] && ok "overlay holds the guest's 64 MiB write ($SIZE bytes)" || bad "overlay only $SIZE bytes"
[[ "$(shasum "$WS/root.raw" | cut -d' ' -f1)" == "$BEFORE" ]] && ok "base root.raw is unchanged" || bad "base root.raw changed"
curl -fs -X DELETE "$V" >/dev/null || true
echo "asif overlay: PASS"
