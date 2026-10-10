#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Needs a prepared template (docs/macos.md, "macOS guests"). If the key is refused on a fresh clone, FileVault is on in the template: see "Key login on a fresh clone".
# Live test of a macOS guest on the `vz` backend: clones a prepared template through the REST API, checks that the API reports the
# guest's address and that SSH works, then deletes it. See docs/macos.md ("macOS guests") for how to prepare a template.
#   FLUXVM_MACOS_TEMPLATE=/Volumes/X/mac1/disk.raw FLUXVM_MACOS_KEY=~/.ssh/key [FLUXVM_MACOS_USER=zeus] \
#     TMPDIR=/Volumes/X/tmp scripts/macos-guest-live-test.sh
# The template and TMPDIR must be on the same APFS volume, or the "clone" copies the whole 20+ GB disk.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
: "${FLUXVM_MACOS_TEMPLATE:?path to the template disk.raw}" "${FLUXVM_MACOS_KEY:?path to an SSH private key authorised in the template}"
USERNAME="${FLUXVM_MACOS_USER:-zeus}"; PORT="${FLUXVM_LIVE_PORT:-7798}"
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-macos-live.XXXXXX")"
cleanup() { [[ -n "${DPID:-}" ]] && kill "$DPID" 2>/dev/null || true; pkill -f "fluxvm-vz-runner run --config $T" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; exit 1; }
cargo build -p fluxctl -j 4 2>&1 | tail -1
cat > "$T/fluxvm.toml" <<EOT
listen = "127.0.0.1:$PORT"
state_dir = "$T/state"
run_dir = "/tmp/fluxvm-run-macos-live"
EOT
./target/debug/fluxctl --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
B="http://127.0.0.1:$PORT/v1/vms"
START=$SECONDS
RESP="$(curl -fs -X POST "$B" -H 'Content-Type: application/json' -d "{\"name\":\"mac-live\",\"backend\":\"vz\",\"image\":\"$FLUXVM_MACOS_TEMPLATE\",\"vcpus\":4,\"memory_mib\":8192,\"network\":{\"mode\":\"user\"},\"apple\":{\"guest_os\":\"macos\"}}")" || bad "macOS guest create failed: $(tail -3 "$T/daemon.log")"
ID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$RESP")"
ok "macOS guest created from the template in $((SECONDS-START))s"
IP=""; for _ in $(seq 1 180); do IP="$(curl -fs "$B/$ID" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("guest_ip") or "")')"; [[ -n "$IP" ]] && break; sleep 5; done
[[ -n "$IP" ]] && ok "the API reports its address ($IP) after $((SECONDS-START))s" || bad "no guest_ip"
OUT=""; for _ in $(seq 1 90); do
  OUT="$(timeout 25 ssh -i "$FLUXVM_MACOS_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10 "$USERNAME@$IP" 'sw_vers -productName; sw_vers -productVersion; ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber' 2>"$T/ssh.err" || true)"
  [[ "$OUT" == macOS* ]] && break; sleep 10
done
SUMMARY="$(echo $OUT)"
[[ "$OUT" == macOS* ]] && ok "SSH works after $((SECONDS-START))s: $SUMMARY" || bad "no SSH login to $USERNAME@$IP: $(tail -1 "$T/ssh.err")"
curl -fs -X DELETE "$B/$ID" >/dev/null || bad "delete failed"
sleep 3
pgrep -f "fluxvm-vz-runner run --config $T" >/dev/null && bad "the macOS runner is still running" || ok "deleted, nothing left running"
echo "PASS"
