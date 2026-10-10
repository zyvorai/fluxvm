#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Live test of container (OCI) sandboxes on vz: one lightweight VM per container (docs/oci-sandboxes.md). Starts a daemon,
# then through the REST API and `fluxctl sandbox run`: exit code propagation, a read-only root with a writable /tmp, the
# default uid 65534, exec with argv in an image without a shell, offline mode, an egress allow-list, TTL expiry, and the
# cold-start time once the image's rootfs is cached.
#   FLUXVM_OCI_BOOT_DIR=dist/oci-boot scripts/oci-live-test.sh
# Needs Apple silicon, the Xcode command line tools, Rust, network access to Docker Hub and gcr.io, and the boot artifacts
# (`oci-kernel`, `oci-initrd`) built by scripts/build-oci-boot.sh on Linux arm64 (the `oci-boot` CI workflow uploads them).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }
BOOT="$(cd "${FLUXVM_OCI_BOOT_DIR:-dist/oci-boot}" 2>/dev/null && pwd)" || { echo "set FLUXVM_OCI_BOOT_DIR to the directory with oci-kernel and oci-initrd" >&2; exit 2; }
[[ -f "$BOOT/oci-kernel" && -f "$BOOT/oci-initrd" ]] || { echo "$BOOT has no oci-kernel / oci-initrd" >&2; exit 2; }
ALPINE="${FLUXVM_OCI_ALPINE:-alpine:3.22}"
DISTROLESS="${FLUXVM_OCI_DISTROLESS:-gcr.io/distroless/python3-debian12}"
T="$(mktemp -d "${TMPDIR:-/tmp}/fluxvm-oci-live.XXXXXX")"; PORT="${FLUXVM_LIVE_PORT:-7798}"
cleanup() { [[ -n "${DPID:-}" ]] && kill "$DPID" 2>/dev/null || true; pkill -f "fluxvm-vz-runner run --config $T" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; [[ -f "$T/daemon.log" ]] && tail -5 "$T/daemon.log"; exit 1; }
json() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

cargo build -p fluxctl -j 4 2>&1 | tail -1
FLUXCTL=./target/debug/fluxctl
cat > "$T/fluxvm.toml" <<EOT
listen = "127.0.0.1:$PORT"
state_dir = "$T/state"
run_dir = "/tmp/fluxvm-run-oci-live"

[apple]
oci_kernel = "$BOOT/oci-kernel"
oci_initrd = "$BOOT/oci-initrd"
EOT
$FLUXCTL --config "$T/fluxvm.toml" serve > "$T/daemon.log" 2>&1 & DPID=$!
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && ok "daemon is up" || bad "daemon did not start"
SERVER="http://127.0.0.1:$PORT"; SB="$SERVER/v1/sandboxes"; B="$SERVER/v1/vms"
create() { curl -fsS -X POST "$SB" -H 'Content-Type: application/json' -d "$1"; }
sexec() { curl -fsS -X POST "$SB/$1/process" -H 'Content-Type: application/json' -d "$(python3 -c 'import sys,json;print(json.dumps({"command":sys.argv[1]}))' "$2")"; }
out() { sexec "$1" "$2" | json 'd["stdout"]' ; }

# Pull and build the rootfs once; the time is reported, not checked (it depends on the network).
START=$SECONDS
curl -fsS -X POST "$SERVER/v1/oci/images" -H 'Content-Type: application/json' -d "{\"image\":\"$ALPINE\"}" > "$T/pull.json" || bad "pull $ALPINE"
ok "pulled $ALPINE and built its rootfs ($((SECONDS-START))s): $(json 'd["manifest_digest"]' < "$T/pull.json")"

# fluxctl sandbox run: the process's output reaches the console, its exit code becomes fluxctl's, and --rm deletes the VM.
set +e
$FLUXCTL --server "$SERVER" sandbox run "$ALPINE" --rm -- sh -c \
  'echo uid=$(id -u); touch /tmp/x && echo tmp=rw; exit 7' \
  > "$T/run.out" 2> "$T/run.err"
CODE=$?
set -e
[[ $CODE == 7 ]] && ok "sandbox run: the container's exit code (7) is fluxctl's" || bad "sandbox run exit code $CODE: $(tail -5 "$T/run.err")"
grep -q '^uid=65534' "$T/run.out" && ok "the process runs as 65534 by default" || bad "uid: $(grep uid= "$T/run.out")"
grep -q '^tmp=rw' "$T/run.out" && ok "/tmp is writable" || bad "/tmp not writable"
sleep 2
[[ "$(curl -fs "$SB" | json 'len(d.get("items",d))')" == 0 ]] && ok "sandbox run --rm deleted the VM" || bad "sandbox left behind after --rm"

# Cold start with the rootfs cached: create returns once the agent answers.
START_MS=$(python3 -c 'import time;print(int(time.time()*1000))')
KEEP="$(create "{\"name\":\"keep\",\"ttl_seconds\":600,\"oci\":{\"image\":\"$ALPINE\",\"command\":[\"sleep\",\"3600\"]}}")" || bad "create a kept sandbox"
COLD_MS=$(( $(python3 -c 'import time;print(int(time.time()*1000))') - START_MS ))
KID="$(json 'd["id"]' <<<"$KEEP")"
ok "cold start with a cached rootfs: ${COLD_MS} ms (target under 2000 ms)"
[[ "$(out "$KID" 'echo exec-ok')" == "exec-ok" ]] && ok "exec through the guest agent (no SSH in the image)" || bad "exec in the kept sandbox"
[[ "$(out "$KID" 'touch /rw-test 2>&1; true')" == *"Read-only file system"* ]] && ok "the root filesystem is read-only, even for root" || bad "root is writable: $(out "$KID" 'touch /rw-test 2>&1; mount | head -3')"
curl -fsS -X POST "$SB/$KID/fs/write" -H 'Content-Type: application/json' -d "{\"path\":\"/tmp/f.txt\",\"content_base64\":\"$(printf 'hi\n' | base64)\"}" >/dev/null || bad "fs write"
[[ "$(out "$KID" 'cat /tmp/f.txt')" == "hi" ]] && ok "file write over vsock lands in the container's /tmp" || bad "fs round trip"
LOGS="$(curl -fsS "$SB/$KID/logs?lines=50")"
[[ "$(json 'd["oci"] and d["exit_code"] is None' <<<"$LOGS")" == True ]] && ok "logs: a running container has no exit code yet" || bad "logs: $LOGS"

# An image with no shell at all: exec with argv.
DL="$(create "{\"name\":\"distroless\",\"ttl_seconds\":600,\"oci\":{\"image\":\"$DISTROLESS\",\"command\":[\"-c\",\"import time; time.sleep(3600)\"]}}")" || bad "create $DISTROLESS"
DID="$(json 'd["id"]' <<<"$DL")"
ARGV="$(curl -fsS -X POST "$SB/$DID/process" -H 'Content-Type: application/json' -d '{"process":{"argv":["python3","-c","print(6*7)"]}}')"
[[ "$(json 'd["exit_code"], d["stdout"].strip()' <<<"$ARGV")" == "(0, '42')" ]] && ok "distroless: exec with argv runs without a shell" || bad "argv exec: $ARGV"
NOSH="$(sexec "$DID" 'true' 2>/dev/null || echo '{}')"
[[ "$(json 'd.get("exit_code")' <<<"$NOSH")" != 0 ]] && ok "distroless: a shell command fails, as there is no /bin/sh" || bad "distroless ran a shell command: $NOSH"

# Offline: no network card at all.
OFF="$(create "{\"name\":\"offline\",\"offline\":true,\"ttl_seconds\":600,\"oci\":{\"image\":\"$ALPINE\",\"command\":[\"sleep\",\"3600\"]}}")" || bad "create offline"
OID="$(json 'd["id"]' <<<"$OFF")"
[[ "$(out "$OID" 'ls /sys/class/net')" == "lo" ]] && ok "offline: only lo" || bad "offline interfaces: $(out "$OID" 'ls /sys/class/net')"
[[ "$(out "$OID" 'wget -q -T 4 -O /dev/null http://example.com && echo reached || echo blocked')" == blocked ]] && ok "offline: the internet is unreachable" || bad "offline sandbox reached the network"

# Allow-list: only example.com, through the host proxy relayed over vsock.
AL="$(create "{\"name\":\"allow\",\"allow_hosts\":[\"example.com\"],\"ttl_seconds\":600,\"oci\":{\"image\":\"$ALPINE\",\"command\":[\"sleep\",\"3600\"]}}")" || bad "create allow-listed"
AID="$(json 'd["id"]' <<<"$AL")"
P='http_proxy=http://127.0.0.1:3128'
[[ "$(out "$AID" "$P wget -q -T 20 -O /dev/null http://example.com && echo reached || echo blocked")" == reached ]] && ok "allow-list: example.com is reachable through the proxy" || bad "allowed host unreachable"
[[ "$(out "$AID" "$P wget -q -T 10 -O /dev/null http://www.debian.org && echo reached || echo blocked")" == blocked ]] && ok "allow-list: another host is refused" || bad "a host not on the list was reachable"
[[ "$(out "$AID" 'wget -q -T 5 -O /dev/null http://example.com && echo reached || echo blocked')" == blocked ]] && ok "allow-list: going around the proxy reaches nothing" || bad "reached the network without the proxy"

# TTL: a short-lived sandbox goes away on its own.
TT="$(create "{\"name\":\"ttl\",\"ttl_seconds\":20,\"oci\":{\"image\":\"$ALPINE\",\"command\":[\"sleep\",\"3600\"]}}")" || bad "create ttl"
TID="$(json 'd["id"]' <<<"$TT")"
for _ in $(seq 1 30); do curl -fs "$B/$TID" >/dev/null 2>&1 || break; sleep 3; done
curl -fs "$B/$TID" >/dev/null 2>&1 && bad "sandbox still present after its TTL" || ok "TTL: the sandbox was removed"

for id in "$KID" "$DID" "$OID" "$AID"; do curl -fs -X DELETE "$B/$id" >/dev/null || true; done
curl -fsS "$SERVER/v1/oci/images" | json 'len(d.get("items",d))' > "$T/n"; ok "cached images: $(cat "$T/n")"
echo "all container sandbox checks passed (cold start ${COLD_MS} ms)"
