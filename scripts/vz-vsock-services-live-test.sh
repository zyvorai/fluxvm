#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live test of `apple.vsock_services` on a Linux guest: the `metadata` and `telemetry` built-ins and an allow-listed
# port relayed to a host Unix socket, and that a port not in the list stays closed.
#   scripts/vz-vsock-services-live-test.sh [image]
# Needs Apple silicon macOS, the Xcode command line tools, Rust and python3. Defaults to the built-in `debian-13`.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-vsock.XXXXXX")"; PORT="${FLUXVM_LIVE_PORT:-7798}"
cleanup() {
  [[ -n "${DPID:-}" ]] && kill "$DPID" 2>/dev/null || true
  [[ -n "${SPID:-}" ]] && kill "$SPID" 2>/dev/null || true
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
run_dir = "/tmp/fluxvm-run-vsock"
EOT
./target/debug/fluxctl --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && ok "daemon is up" || bad "daemon did not start"
B="http://127.0.0.1:$PORT/v1/vms"

# Unknown built-ins and reserved ports are refused at create.
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B" -H 'Content-Type: application/json' \
  -d "{\"name\":\"bad\",\"backend\":\"vz\",\"image\":\"$IMG\",\"apple\":{\"vsock_services\":[{\"port\":3128,\"builtin\":\"metadata\"}]}}")"
[[ "$CODE" == 400 || "$CODE" == 422 ]] && ok "reserved port refused ($CODE)" || bad "reserved port gave HTTP $CODE"

REQ="{\"name\":\"vsock\",\"backend\":\"vz\",\"image\":\"$IMG\",\"vcpus\":2,\"memory_mib\":2048,
  \"apple\":{\"vsock_services\":[{\"port\":5001,\"builtin\":\"metadata\"},{\"port\":5002,\"builtin\":\"telemetry\"},{\"port\":5003,\"socket\":\"echo\"}]},
  \"cloud_init\":{\"hostname\":\"vsock\",\"user\":\"velora\",\"ssh_authorized_keys\":[\"$PUB\"]}}"
# The host end of the allow-listed port must exist before the guest connects; the id is only known after create, so
# start the VM, then listen.
RESP="$(curl -sS -X POST "$B" -H 'Content-Type: application/json' -d "$REQ")"
ID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$RESP" 2>/dev/null)" || bad "create: $RESP"
V="$B/$ID"
field() { curl -fs "$V" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
IP=""; for _ in $(seq 1 60); do IP="$(field guest_ip)"; [[ -n "$IP" ]] && break; sleep 3; done
[[ -n "$IP" ]] || bad "no guest_ip"
sshc() { ssh -i "$T/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 "velora@$IP" "$@"; }
for _ in $(seq 1 30); do sshc true >/dev/null 2>&1 && break; sleep 3; done
sshc true || bad "ssh to $IP"
ok "SSH to the guest at $IP"

SVC="/tmp/fluxvm-$(id -u)/$(tr -d - <<<"$ID").svc-echo"
python3 -c '
import os, socket, sys
p = sys.argv[1]
try: os.unlink(p)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX); s.bind(p); s.listen(4)
while True:
    c, _ = s.accept()
    c.sendall(b"echo:" + c.recv(64)); c.close()
' "$SVC" & SPID=$!
for _ in $(seq 1 20); do [[ -S "$SVC" ]] && break; sleep 0.5; done
[[ -S "$SVC" ]] || bad "host service socket $SVC did not appear"

vs() { sshc "python3 -c 'import socket,sys; s=socket.socket(socket.AF_VSOCK); s.settimeout(8); s.connect((2,$1)); s.sendall(sys.stdin.buffer.read() if $2 else b\"\"); s.shutdown(socket.SHUT_WR) if $2 else None; sys.stdout.buffer.write(s.recv(4096))'" ; }
META="$(vs 5001 0 </dev/null)"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["name"]=="vsock" and d["vcpus"]==2 and d["memory_mib"]==2048' "$META" \
  && ok "metadata built-in: $META" || bad "metadata gave '$META'"
echo "boot ok" | vs 5002 1 >/dev/null || true
sleep 1
LOG="$(find "$T/state" -name telemetry.log -print -quit)"
[[ -n "$LOG" ]] && grep -q "boot ok" "$LOG" && ok "telemetry built-in wrote $LOG" || bad "no telemetry line (log '${LOG:-none}')"
ECHO="$(echo hello | vs 5003 1)"
[[ "$ECHO" == echo:hello* ]] && ok "allow-listed port relayed to the host socket" || bad "relay gave '$ECHO'"
if vs 5999 0 </dev/null >/dev/null 2>&1; then bad "port 5999 is not allow-listed but accepted a connection"; else ok "unlisted port stays closed"; fi
curl -fs -X DELETE "$V" >/dev/null || true
echo "vsock services: PASS"
