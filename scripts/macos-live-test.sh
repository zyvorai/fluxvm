#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live test of the macOS (Apple Virtualization.framework) backend: starts the daemon, creates a real ARM64 Linux VM
# through the REST API, SSHes into it, pauses/resumes, stops and restarts it, then deletes it.
#   scripts/macos-live-test.sh [path/to/arm64-linux-image.raw]
# Needs Apple silicon, the Xcode command line tools and Rust. Without an image argument it asks FluxVM for the built-in `debian-13`.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-live.XXXXXX")"; PORT="${FLUXVM_LIVE_PORT:-7799}"
cleanup() { [[ -n "${DPID:-}" ]] && kill "$DPID" 2>/dev/null || true; pkill -f "fluxvm-vz-runner run --config $T" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; exit 1; }

cargo build -p fluxctl -j 4 2>&1 | tail -1
# Default: the built-in name `debian-13`, which FluxVM downloads and checksum-verifies itself (~400 MB, cached).
IMG="${1:-debian-13}"
FWD="${FLUXVM_LIVE_FWD_PORT:-22722}"; mkdir "$T/share" && echo "from-the-mac" > "$T/share/marker.txt"
ssh-keygen -q -t ed25519 -N "" -f "$T/key" && PUB="$(cat "$T/key.pub")"
cat > "$T/fluxvm.toml" <<EOT
listen = "127.0.0.1:$PORT"
state_dir = "$T/state"
run_dir = "/tmp/fluxvm-run-live"
EOT
./target/debug/fluxctl --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && ok "daemon is up on macOS" || bad "daemon did not start: $(tail -3 "$T/daemon.log")"

B="http://127.0.0.1:$PORT/v1/vms"
RESP="$(curl -fs -X POST "$B" -H 'Content-Type: application/json' -d "{\"name\":\"live\",\"backend\":\"vz\",\"image\":\"$IMG\",\"vcpus\":2,\"memory_mib\":2048,\"network\":{\"mode\":\"user\",\"forwards\":[{\"host_port\":$FWD,\"guest_port\":22}]},\"shared_folders\":[{\"host_path\":\"$T/share\",\"guest_path\":\"/mnt/share\"}],\"cloud_init\":{\"hostname\":\"live\",\"user\":\"velora\",\"ssh_authorized_keys\":[\"$PUB\"]}}")" || bad "create failed"
ID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$RESP")"; V="$B/$ID"
field() { curl -fs "$V" | python3 -c "import sys,json;print(json.load(sys.stdin).get('$1') or '')"; }
[[ "$(field status)" == running ]] && ok "VM created and running through the vz backend" || bad "status $(field status)"
ip_wait() { local ip=""; for _ in $(seq 1 60); do ip="$(field guest_ip)"; [[ -n "$ip" ]] && break; sleep 3; done; echo "$ip"; }
sshc() { ssh -i "$T/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 "velora@$1" "$2"; }
IP="$(ip_wait)"; [[ -n "$IP" ]] && ok "guest address reported by the API: $IP" || bad "no guest_ip"
for _ in $(seq 1 20); do sshc "$IP" hostname >/dev/null 2>&1 && break; sleep 3; done
[[ "$(sshc "$IP" hostname)" == live ]] && ok "SSH into the guest works (hostname from cloud-init)" || bad "ssh failed"

FWDOUT="$(ssh -i "$T/key" -p "$FWD" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 velora@127.0.0.1 hostname 2>&1 || true)"
[[ "$FWDOUT" == live ]] && ok "port forward: ssh -p $FWD 127.0.0.1 reaches the guest" || bad "port forward: $FWDOUT"
for _ in $(seq 1 10); do [[ "$(sshc "$IP" 'cat /mnt/share/marker.txt' 2>/dev/null)" == from-the-mac ]] && break; sleep 3; done
[[ "$(sshc "$IP" 'cat /mnt/share/marker.txt' 2>/dev/null)" == from-the-mac ]] && ok "shared folder: the guest reads a file from the Mac" || bad "shared folder not mounted"
sshc "$IP" 'echo from-the-guest > /mnt/share/back.txt'; [[ "$(cat "$T/share/back.txt" 2>/dev/null)" == from-the-guest ]] && ok "shared folder: the guest's write lands on the Mac" || bad "write-back"

# Snapshot the running guest, change it, then stop and restore: memory (a running process) and disk both roll back.
# (Restoring needs an unlocked login session: Virtualization.framework's saved-state key is not usable on a locked Mac.)
sshc "$IP" 'echo before > /var/tmp/marker; nohup sh -c "while :; do date +%s >> /var/tmp/tick; sleep 1; done" >/dev/null 2>&1 &' || bad "could not set up the snapshot test"
SNAP="$(curl -s -X POST "$V/snapshot" -H 'Content-Type: application/json' -d '{"tag":"s1"}')"
echo "$SNAP" | grep -q '"ok":true' && ok "snapshot of the running VM" || bad "snapshot: $SNAP"
[[ "$(field status)" == running ]] && ok "the VM keeps running after a snapshot" || bad "status after snapshot: $(field status)"
sshc "$IP" 'echo after > /var/tmp/marker' && sleep 2
curl -fs -X POST "$V/stop" >/dev/null; sleep 6
RESTORE="$(curl -s -X POST "$V/restore" -H 'Content-Type: application/json' -d '{"tag":"s1"}')"
[[ "$(field status)" == running ]] && ok "restore: the VM is running again" || bad "restore: $RESTORE"
IP="$(ip_wait)"; [[ -n "$IP" ]] && ok "restore: the guest address is reported again" || bad "no guest_ip after restore"
for _ in $(seq 1 20); do sshc "$IP" true >/dev/null 2>&1 && break; sleep 2; done
[[ "$(sshc "$IP" 'cat /var/tmp/marker')" == before ]] && ok "restore: the disk is back as it was at the snapshot" || bad "restore: marker is $(sshc "$IP" 'cat /var/tmp/marker')"
T1="$(sshc "$IP" 'tail -1 /var/tmp/tick')"; sleep 3; T2="$(sshc "$IP" 'tail -1 /var/tmp/tick')"
[[ -n "$T1" && "$T2" -gt "$T1" ]] && ok "restore: the process that was running keeps running (memory restored, no reboot)" || bad "tick did not advance: $T1 -> $T2"
sshc "$IP" 'echo shared-after-restore > /mnt/share/after.txt'; [[ "$(cat "$T/share/after.txt" 2>/dev/null)" == shared-after-restore ]] && ok "restore: the shared folder still works" || bad "shared folder after restore"
curl -fs "$V/snapshots" | grep -q '"s1"' && ok "snapshot listed" || bad "snapshot not listed"

curl -fs -X POST "$V/pause" >/dev/null && [[ "$(field status)" == paused ]] && ok "pause" || bad "pause"
curl -fs -X POST "$V/resume" >/dev/null && [[ "$(field status)" == running ]] && ok "resume" || bad "resume"
curl -fs -X POST "$V/stop" >/dev/null; sleep 6; [[ "$(field status)" == stopped ]] && ok "stop" || bad "stop: $(field status)"
pgrep -f "fluxvm-vz-runner run --config $T" >/dev/null && bad "runner still running after stop" || ok "runner process exited"
curl -fs -X POST "$V/start" >/dev/null; IP="$(ip_wait)"
for _ in $(seq 1 20); do sshc "$IP" hostname >/dev/null 2>&1 && break; sleep 3; done
[[ "$(sshc "$IP" hostname)" == live ]] && ok "restart: the VM boots again and reports its address" || bad "restart ssh"
curl -fs -X DELETE "$V" >/dev/null && sleep 3 && ok "delete"
pgrep -f "fluxvm-vz-runner run --config $T" >/dev/null && bad "runner still running after delete" || ok "no runner left behind"
# `fluxctl run` through the daemon's REST API. The first run builds a warm template (cold boot + snapshot); the next
# restores it, and must see none of the first run's changes.
FX=("$PWD/target/debug/fluxctl" --server "http://127.0.0.1:$PORT")
RUNOUT="$("${FX[@]}" run -- 'touch /var/tmp/leak; echo run-ok' 2>/dev/null </dev/null)" || bad "fluxctl run failed"
[[ "$RUNOUT" == run-ok ]] && ok "fluxctl run: boots, runs a command, exits (builds the warm template)" || bad "fluxctl run output: $RUNOUT"
START=$SECONDS
RUNOUT="$("${FX[@]}" run -- 'ls /var/tmp/leak 2>/dev/null || echo clean' 2>/dev/null </dev/null)" || bad "second fluxctl run failed"
[[ "$RUNOUT" == clean ]] && ok "fluxctl run: the second run restores the warm snapshot, pristine ($((SECONDS-START))s)" || bad "second run saw the first run's file: $RUNOUT"
[[ "$(curl -fs "$B" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d) if isinstance(d,dict) else d;print(sum(1 for v in d if not v["name"].startswith("warm-")),sum(1 for v in d if v["name"].startswith("warm-") and v["status"]!="stopped"))')" == "0 0" ]] && ok "fluxctl run left nothing running (only the stopped warm template)" || bad "a run VM was left behind"
# A stack: two services, one depending on the other. The app reaches the db by name, which only works through the Mac's relay.
mkdir -p "$T/proj" && cp examples/fluxvm.toml "$T/proj/fluxvm.toml" && echo hello > "$T/proj/marker.txt"
( cd "$T/proj" && "${FX[@]}" up >"$T/up1.log" 2>&1 </dev/null ) || { tail -5 "$T/up1.log"; bad "fluxctl up failed"; }
STACKPS="$( cd "$T/proj" && "${FX[@]}" ps 2>/dev/null )"
[[ "$(grep -c running <<<"$STACKPS")" == 2 ]] && ok "stack: up created db and app" || bad "stack ps: $STACKPS"
APPIP="$(awk '$1=="app"{print $4}' <<<"$STACKPS")"
# Stack VMs use your own user name and SSH key (like `fluxctl run`), not this script's throwaway key.
mine() { ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 "$USER@$1" "$2"; }
[[ "$(mine "$APPIP" 'cat /tmp/db-reply' 2>/dev/null)" == db-ok ]] && ok "stack: app reached db by name through the Mac's relay (after_up)" || bad "app could not reach db"
[[ "$(mine "$APPIP" 'cat /srv/app/marker.txt' 2>/dev/null)" == hello ]] && ok "stack: the project directory is shared into app" || bad "stack volume"
START=$SECONDS; ( cd "$T/proj" && "${FX[@]}" up >"$T/up2.log" 2>&1 </dev/null ) && ! grep -qE "creating|recreating" "$T/up2.log" && ok "stack: a second up changes nothing ($((SECONDS-START))s)" || bad "second up was not a no-op: $(cat "$T/up2.log")"
( cd "$T/proj" && "${FX[@]}" down >/dev/null 2>&1 </dev/null )
[[ "$(curl -fs "$B" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d) if isinstance(d,dict) else d;print(sum(1 for v in d if v["name"].startswith("demo-")))')" == 0 ]] && ok "stack: down removed both VMs" || bad "stack VMs left behind"
# Agent sandbox API on a Mac: create with no template (default Debian VM, ready for commands), exec over SSH, a file round trip,
# and the TTL removing the sandbox on its own.
SB="http://127.0.0.1:$PORT/v1/sandboxes"
SBRESP="$(curl -fs -X POST "$SB" -H 'Content-Type: application/json' -d '{"ttl_seconds":40}')" || bad "sandbox create failed"
SBID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$SBRESP")"
SBOUT="$(curl -fs -X POST "$SB/$SBID/process" -H 'Content-Type: application/json' -d '{"command":"echo sandbox-ok; exit 3"}')"
python3 -c 'import sys,json;d=json.loads(sys.argv[1]);assert d["exit_code"]==3 and d["stdout"]=="sandbox-ok\n",d' "$SBOUT" && ok "sandbox: create is ready for commands; exec returns the exit code and output" || bad "sandbox exec: $SBOUT"
curl -fs -X POST "$SB/$SBID/fs/write" -H 'Content-Type: application/json' -d "{\"path\":\"/tmp/a dir/it's.txt\",\"content_base64\":\"$(printf 'x\ny\n' | base64)\",\"mode\":416}" >/dev/null || bad "sandbox fs write"
python3 -c 'import sys,json,base64;d=json.loads(sys.argv[1]);assert base64.b64decode(d["content_base64"])==b"x\ny\n" and d["mode"]==0o640,d' "$(curl -fs -X POST "$SB/$SBID/fs/read" -H 'Content-Type: application/json' -d '{"path":"/tmp/a dir/it'"'"'s.txt"}')" && ok "sandbox: file round trip keeps content and mode (awkward path)" || bad "sandbox fs read"
for _ in $(seq 1 30); do [[ "$(curl -fs "$SB" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d);print(len(d))')" == 0 ]] && break; sleep 3; done
[[ "$(curl -fs "$SB" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d);print(len(d))')" == 0 ]] && ok "sandbox: the TTL removed it" || bad "sandbox still present after its TTL"
# The first sandbox cold-booted and started filling the warm pool. Once two slots are ready, two sandboxes created at the same
# time each restore one (a claimed slot still has its "warm" snapshot; a cold-booted sandbox has none), get their own addresses,
# and do not see each other's files.
for _ in $(seq 1 40); do
  [[ "$(curl -fs "$B" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d);print(sum(1 for v in d if v["name"].startswith("sandbox-slot-") and v["status"]=="stopped"))')" -ge 2 ]] && break; sleep 3
done
WSTART=$SECONDS
for n in 1 2; do curl -fs -X POST "$SB" -H 'Content-Type: application/json' -d '{"ttl_seconds":300}' > "$T/warm$n.json" & eval "WP$n=$!"; done
wait "$WP1" "$WP2" || bad "a warm sandbox create failed"
WID1="$(python3 -c 'import sys,json;print(json.load(open(sys.argv[1]))["id"])' "$T/warm1.json")"; WID2="$(python3 -c 'import sys,json;print(json.load(open(sys.argv[1]))["id"])' "$T/warm2.json")"
for id in "$WID1" "$WID2"; do
  curl -fs "$B/$id/snapshots" | grep -q '"warm"' || bad "sandbox $id was cold-booted, not restored from the warm pool"
done
ok "sandbox: two concurrent creates restored warm slots ($((SECONDS-WSTART))s for both)"
WIP1="$(curl -fs "$B/$WID1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["guest_ip"])')"; WIP2="$(curl -fs "$B/$WID2" | python3 -c 'import sys,json;print(json.load(sys.stdin)["guest_ip"])')"
[[ -n "$WIP1" && -n "$WIP2" && "$WIP1" != "$WIP2" ]] && ok "sandbox: warm sandboxes have different addresses ($WIP1, $WIP2)" || bad "warm sandbox addresses: '$WIP1' '$WIP2'"
curl -fs -X POST "$SB/$WID1/process" -H 'Content-Type: application/json' -d '{"command":"echo one > /tmp/mark"}' >/dev/null
OTHER="$(curl -fs -X POST "$SB/$WID2/process" -H 'Content-Type: application/json' -d '{"command":"cat /tmp/mark 2>/dev/null || echo none"}')"
python3 -c 'import sys,json;assert json.loads(sys.argv[1])["stdout"]=="none\n",sys.argv[1]' "$OTHER" && ok "sandbox: warm sandboxes are isolated from each other" || bad "warm sandboxes share state: $OTHER"
# An offline sandbox has no network card at all: nothing to route through, yet commands and files work (over vsock).
OFF="$(curl -fs -X POST "$SB" -H 'Content-Type: application/json' -d '{"offline":true,"ttl_seconds":300}')" || bad "offline sandbox create failed"
OFFID="$(python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])' <<<"$OFF")"
oexec() { curl -fs -X POST "$SB/$OFFID/process" -H 'Content-Type: application/json' -d "{\"command\":\"$1\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["stdout"],end="")'; }
[[ "$(oexec 'ls /sys/class/net')" == lo ]] && ok "offline sandbox: the guest has no network interface but lo" || bad "offline interfaces: $(oexec 'ls /sys/class/net')"
[[ "$(oexec 'curl -s -m 4 -o /dev/null -w %{http_code} https://example.com; echo')" == 000 ]] && ok "offline sandbox: the internet is unreachable" || bad "offline sandbox reached the network"
curl -fs -X POST "$SB/$OFFID/fs/write" -H 'Content-Type: application/json' -d "{\"path\":\"/tmp/off.txt\",\"content_base64\":\"$(printf 'off\n' | base64)\"}" >/dev/null && ok "offline sandbox: exec and files work over vsock ($(oexec 'whoami'))" || bad "offline sandbox fs write"
[[ -z "$(curl -fs "$B/$OFFID" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("guest_ip") or "")')" ]] && ok "offline sandbox: no address was ever assigned" || bad "offline sandbox got an address"
# The pool refills in the background after the two claims; let it finish so it cannot start a VM while we clean up.
for _ in $(seq 1 40); do
  [[ "$(curl -fs "$B" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d);print(sum(1 for v in d if v["name"].startswith("sandbox-slot-") and v["status"]=="stopped"))')" -ge 2 ]] && break; sleep 3
done
# Remove everything (sandboxes and warm slots) before checking nothing is left running.
for id in $(curl -fs "$B" | python3 -c 'import sys,json;d=json.load(sys.stdin);d=d.get("items",d);print(" ".join(v["id"] for v in d))'); do curl -fs -X DELETE "$B/$id" >/dev/null || true; done
sleep 3
pgrep -f "fluxvm-vz-runner run --config $T" >/dev/null && bad "a sandbox runner is still running" || ok "sandbox: no runner left behind"
echo "PASS"
