#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Guest networking smoke for the in-tree KVM engine's virtio-net (tap -> guest
# RX and guest -> tap TX). Per run, at each vCPU count, in a throwaway network
# namespace: boot the golden agent guest on a tap, check it gets a DHCP lease,
# pings the host both ways, and moves a multi-MiB file in each direction over
# TCP with matching SHA-256.
#
#   FLUXVM_KVM_NET=1 sudo -E scripts/test-kvm-net.sh        # lab host, root
#
# Opt-in and root-only: it needs /dev/kvm, netns/tap, dnsmasq, python3 and the
# golden agent image (scripts/setup-native-agent-template.sh); the hosted CI
# runner has none of the agent image, so this is not part of native-kvm.yml.
# Nothing outside the per-run namespace is touched. After every run and at the
# end it asserts that the namespace and tap are gone, that no dnsmasq /
# hypervisor / server of the run is left, and (at the end) that `ip netns list`
# and the host nft ruleset are unchanged.
#
# Each run also prints which virtio-net datapath the hypervisor reports
# (vhost-net vs userspace pump, with the reason) so a silent fallback is visible.
# FLUXVM_VHOST_NET=0 forces the userspace pump and FLUXVM_NET_QUEUE_PAIRS=N
# (needs vhost-net) builds a multiqueue device; both are inherited by the
# hypervisor, so the same checks run against each datapath. Throughput and CPU
# comparisons live in scripts/bench-kvm-vhost.sh.
#
# Env: RUNS (5), VCPUS_LIST ("1 2"), SIZE_MIB (8), FLUXVM_HYPERVISOR, KERNEL, GOLDEN.
set -uo pipefail

if [ "${FLUXVM_KVM_NET:-0}" != "1" ]; then
  echo "SKIP: opt-in test; set FLUXVM_KVM_NET=1 (needs root, KVM, dnsmasq, the golden agent image)"
  exit 0
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-5}"
VCPUS_LIST="${VCPUS_LIST:-1 2}"
SIZE_MIB="${SIZE_MIB:-8}"
KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux-5.10.225-no-acpi}"
GOLDEN="${GOLDEN:-/var/lib/fluxvm/images/linux-agent.raw}"
HV="${FLUXVM_HYPERVISOR:-${PROJECT_DIR}/target/release/fluxvm-hypervisor}"
HOST_IP=192.168.100.1
TAP=fvnettap0
HTTP_PORT=18080

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
section() { echo ""; echo "=== $1 ==="; }

[ "$(uname -s)" = "Linux" ] && [ -e /dev/kvm ] || { echo "SKIP: needs Linux/KVM"; exit 0; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 2; }
for t in ip nft dnsmasq python3 sha256sum ping; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done
for f in "$KERNEL" "$GOLDEN" "$HV"; do
  [ -e "$f" ] || { echo "missing: $f" >&2; exit 2; }
done

count_procs() { ps -eo comm= | grep -c -E "^$1" || true; }
ns_hash() { ip netns list | sort | sha256sum | cut -c1-16; }
nft_norm() { nft list ruleset 2>/dev/null | sed -E 's/(packets|bytes) [0-9]+/\1 N/g'; }

NS_BEFORE="$(ns_hash)"
NFT_BEFORE="$(nft_norm | sha256sum | cut -c1-16)"
DNSMASQ_BEFORE="$(count_procs dnsmasq)"

ROOT_TMP="$(mktemp -d)"
NS=""; TMP=""; HV_PID=""; HTTP_PID=""
cleanup_run() {
  set +e
  for p in "$HV_PID" "$HTTP_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -n "$TMP" ] && [ -f "$TMP/dnsmasq.pid" ] && kill "$(cat "$TMP/dnsmasq.pid" 2>/dev/null)" 2>/dev/null
  sleep 1
  for p in "$HV_PID" "$HTTP_PID"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  [ -n "$TMP" ] && [ -f "$TMP/dnsmasq.pid" ] && kill -9 "$(cat "$TMP/dnsmasq.pid" 2>/dev/null)" 2>/dev/null
  [ -n "$NS" ] && ip netns delete "$NS" 2>/dev/null
  sleep 1
}

verify_run_teardown() {
  local left="" i
  [ -z "$NS" ] || ! ip netns list | grep -qw "$NS" && pass "namespace ${NS} removed" || fail "namespace ${NS} still exists"
  ! ip link show "$TAP" >/dev/null 2>&1 && pass "tap ${TAP} not in the host namespace" || fail "tap ${TAP} leaked into the host namespace"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    left="$(pgrep -f -- "$TMP/" | tr '\n' ' ')"
    [ -z "$left" ] && break
    kill -9 $left 2>/dev/null
    sleep 1
  done
  [ -z "$left" ] && pass "no leftover hypervisor / dnsmasq / server of this run" || fail "leftover processes: $left"
}

on_exit() {
  local rc=$?
  cleanup_run
  rm -rf "$ROOT_TMP"
  section "global teardown"
  [ "$(ns_hash)" = "$NS_BEFORE" ] && pass "ip netns list unchanged" || fail "ip netns list differs from before"
  local after; after="$(nft_norm | sha256sum | cut -c1-16)"
  [ "$after" = "$NFT_BEFORE" ] && pass "host nft ruleset unchanged (sha256 ${after})" \
    || fail "host nft ruleset changed (${NFT_BEFORE} -> ${after})"
  [ "$(count_procs dnsmasq)" = "$DNSMASQ_BEFORE" ] && pass "dnsmasq process count unchanged" || fail "dnsmasq process count changed"
  echo ""
  echo "kvm net test: ${PASS} passed, ${FAIL} failed"
  [ "$FAIL" -ne 0 ] && exit 1
  [ "$rc" -eq 0 ] && exit 0
  exit 1
}
trap on_exit EXIT
trap "exit 143" INT TERM HUP

cat >"$ROOT_TMP/server.py" <<'PY'
import http.server, sys
down, up = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        data = open(down, "rb").read()
        self.send_response(200); self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        with open(up, "wb") as f:
            left = n
            while left:
                chunk = self.rfile.read(min(65536, left))
                if not chunk: break
                f.write(chunk); left -= len(chunk)
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[3])), H).serve_forever()
PY

agent() {   # agent "<shell command>" [timeout] -> stdout+stderr of the command in the guest
  python3 - "$TMP/vsock.sock" "$1" "${2:-40}" <<'PY'
import json, socket, sys
sock, cmd, t = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_UNIX); s.settimeout(t + 10); s.connect(sock)
f = s.makefile("rwb")
f.write(b"CONNECT 17777\n"); f.flush()
ack = f.readline()
if not ack.upper().startswith(b"OK"): print("AGENT-ERR " + ack.decode()); sys.exit(97)
f.write((json.dumps({"op": "exec", "command": cmd, "timeout_seconds": t}) + "\n").encode()); f.flush()
r = json.loads(f.readline())
sys.stdout.write(r.get("stdout", "") + r.get("stderr", ""))
sys.exit(0 if r.get("exit_code", 1) == 0 else 96)
PY
}

nsx() { ip netns exec "$NS" "$@"; }

api_datapath() {   # datapath the hypervisor reports via Metrics `net_datapath`
  python3 - "$TMP/api.sock" <<'PY'
import json, socket, sys
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
    s.sendall(b'{"action":"metrics"}\n')
    r = json.loads(s.makefile().readline())
    print(r.get("net_datapath") or "unreported")
except Exception as exc:
    print(f"unreported ({type(exc).__name__})")
PY
}

one_run() {  # one_run <vcpus> <index>
  local vcpus="$1" idx="$2"
  NS="fvnet${vcpus}x${idx}"
  TMP="$ROOT_TMP/run-${vcpus}-${idx}"; mkdir -p "$TMP"
  HV_PID=""; HTTP_PID=""
  section "vcpus=${vcpus} run ${idx}/${RUNS}"

  if ip netns list | grep -qw "$NS"; then fail "namespace ${NS} already exists"; return; fi
  ip netns add "$NS" && nsx ip link set lo up

  head -c $((SIZE_MIB * 1024 * 1024)) /dev/urandom >"$TMP/down.bin"
  local down_sha; down_sha="$(sha256sum "$TMP/down.bin" | cut -d' ' -f1)"
  nsx dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --port=0 --bind-dynamic --interface="$TAP" \
    --except-interface=lo --dhcp-range=192.168.100.50,192.168.100.60,12h \
    --dhcp-option=3,${HOST_IP} --dhcp-leasefile="$TMP/leases" --pid-file="$TMP/dnsmasq.pid" \
    --log-facility="$TMP/dnsmasq.log" || { fail "dnsmasq failed to start"; return; }
  nsx python3 "$ROOT_TMP/server.py" "$TMP/down.bin" "$TMP/up.bin" "$HTTP_PORT" >"$TMP/server.log" 2>&1 &
  HTTP_PID=$!

  cp --sparse=always "$GOLDEN" "$TMP/root.raw"; chmod 0600 "$TMP/root.raw"
  cat >"$TMP/boot.json" <<JSON
{
  "kernel": "$KERNEL",
  "rootfs": "$TMP/root.raw",
  "vcpus": ${vcpus},
  "memory_mib": 512,
  "engine": "kvm",
  "tap": "$TAP",
  "mac": "02:fa:ce:00:00:01",
  "vsock_cid": 3,
  "vsock_uds": "$TMP/vsock.sock",
  "kernel_args": "console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw random.trust_cpu=on rdrand=force virtio_mmio.device=0x200@0xfeb00000:5 virtio_mmio.device=0x200@0xfeb00200:6"
}
JSON
  local t0=$SECONDS
  nsx env FLUXVM_KVM_RUN_SECS=600 "$HV" --api-sock "$TMP/api.sock" --boot-config "$TMP/boot.json" >"$TMP/hv.log" 2>&1 &
  HV_PID=$!

  local ready=0 i
  for i in $(seq 1 120); do
    if [ -S "$TMP/vsock.sock" ] && agent "true" 8 >/dev/null 2>&1; then ready=1; break; fi
    kill -0 "$HV_PID" 2>/dev/null || break
    sleep 2
  done
  if [ "$ready" != 1 ]; then
    fail "guest agent never answered"; tail -20 "$TMP/hv.log" >&2
    return
  fi
  pass "guest booted, agent answers ($((SECONDS - t0)) s)"

  nsx ip -4 -o addr show dev "$TAP" | grep -q "inet ${HOST_IP}/24 " \
    && pass "${TAP} is ${HOST_IP}/24" || fail "tap address: $(nsx ip -4 -o addr show dev "$TAP" | tr '\n' ' ')"

  local cpus; cpus="$(agent "grep -c ^processor /proc/cpuinfo" 15 2>&1 | tr -d '[:space:]')"
  [ "$cpus" = "$vcpus" ] && pass "guest sees ${vcpus} vCPU(s)" || fail "guest sees '${cpus}' vCPUs, wanted ${vcpus}"

  local ip="" out
  for i in $(seq 1 15); do
    out="$(agent "ip -4 -o addr show scope global | awk '{print \$4}'" 8 2>&1)"
    if echo "$out" | grep -q "^192\.168\.100\."; then ip="${out%%/*}"; break; fi
    sleep 2
  done
  [ -n "$ip" ] && pass "DHCP lease ${ip} ($(grep -c DHCPACK "$TMP/dnsmasq.log") ACK)" \
    || { fail "no DHCP lease; dnsmasq saw $(grep -c DHCPDISCOVER "$TMP/dnsmasq.log") discovers, $(grep -c DHCPOFFER "$TMP/dnsmasq.log") offers"; return; }

  out="$(agent "ping -c 5 -W 2 ${HOST_IP} 2>&1 | tail -2" 30)"
  echo "$out" | grep -q " 0% packet loss" && pass "guest -> host ping, 0% loss" || fail "guest -> host ping: $out"
  out="$(nsx ping -c 5 -W 2 "$ip" 2>&1 | tail -2)"
  echo "$out" | grep -q " 0% packet loss" && pass "host -> guest ping, 0% loss" || fail "host -> guest ping: $out"

  out="$(agent "curl -sS --max-time 120 -o /tmp/d.bin -w '%{speed_download}' http://${HOST_IP}:${HTTP_PORT}/down.bin 2>&1; echo; sha256sum /tmp/d.bin | cut -d' ' -f1; stat -c %s /tmp/d.bin" 150)"
  local speed got_sha size
  speed="$(echo "$out" | sed -n 1p)"; got_sha="$(echo "$out" | sed -n 2p)"; size="$(echo "$out" | sed -n 3p)"
  if [ "$got_sha" = "$down_sha" ] && [ "$size" = "$((SIZE_MIB * 1024 * 1024))" ]; then
    pass "download ${SIZE_MIB} MiB into the guest, sha256 matches ($(python3 -c "print(round(float('${speed:-0}')/1048576,1))" 2>/dev/null) MiB/s)"
  else
    fail "download mismatch: size=${size} sha=${got_sha} (want ${down_sha}); ${out}"
  fi

  out="$(agent "head -c $((SIZE_MIB * 1024 * 1024)) /dev/urandom > /tmp/u.bin; sha256sum /tmp/u.bin | cut -d' ' -f1; curl -sS --max-time 120 -T /tmp/u.bin -o /dev/null -w '%{http_code} %{speed_upload}' http://${HOST_IP}:${HTTP_PORT}/up.bin 2>&1" 150)"
  local up_sha; up_sha="$(echo "$out" | sed -n 1p)"
  local recv_sha=""; [ -f "$TMP/up.bin" ] && recv_sha="$(sha256sum "$TMP/up.bin" | cut -d' ' -f1)"
  if [ -n "$up_sha" ] && [ "$up_sha" = "$recv_sha" ]; then
    pass "upload ${SIZE_MIB} MiB from the guest, sha256 matches ($(echo "$out" | sed -n 2p))"
  else
    fail "upload mismatch: guest ${up_sha} host ${recv_sha}; ${out}"
  fi

  echo "  net datapath: $(api_datapath)"
  grep -E "^\[net\]" "$TMP/hv.log" | tail -4 | sed 's/^/  hv: /'
  grep -Eq "Kernel panic|panicked at|Oops:|BUG:" "$TMP/hv.log" >/dev/null && fail "hypervisor log contains a panic/oops" || pass "no panic/oops in the hypervisor log"
}

for vcpus in $VCPUS_LIST; do
  for idx in $(seq 1 "$RUNS"); do
    one_run "$vcpus" "$idx"
    cleanup_run
    section "vcpus=${vcpus} run ${idx}: teardown"
    verify_run_teardown
    NS=""; TMP=""
  done
done
