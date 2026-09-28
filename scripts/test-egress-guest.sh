#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Real-traffic test of the egress proxy: HTTPS interception with a client that
# trusts the proxy CA, explicit-proxy and transparent-redirect modes (real nft
# redirect + SO_ORIGINAL_DST), HTTP/2 to the proxy, and ACL bypass attempts.
#
#   stage 1  a real curl in a second throwaway namespace joined by a veth
#   stage 2  the golden native-KVM guest (CA installed by cloud-init `ca_certs`)
#            running the same curl cases through the guest agent
#
# Stage 2 needs a guest that can RECEIVE packets (virtio-net RX, tap -> guest
# queue 0). If the guest gets no DHCP lease it reports BLOCKED (exit 3) after
# proving boot, agent and CA installation.
#
#   FLUXVM_EGRESS_GUEST=1 sudo -E scripts/test-egress-guest.sh     # lab host, root
#
# Everything network-related lives in two throwaway network namespaces ($NS and
# ${NS}c): the tap or veth, a dnsmasq DHCP/DNS server, the egress proxy, an
# HTTPS+HTTP upstream and the nft redirect. The host's default
# namespace, its nftables ruleset and its DNS are never touched. The script
# asserts that `ip netns list` and `nft list ruleset` are unchanged afterwards
# and that no dnsmasq / hypervisor / proxy process was left behind.
#
# Env: FLUXVM_HYPERVISOR, PROXY_BIN (built egress_proxy_ns example), KERNEL,
# GOLDEN (root image built by scripts/setup-native-agent-template.sh), NS.
set -uo pipefail

if [ "${FLUXVM_EGRESS_GUEST:-0}" != "1" ]; then
  echo "SKIP: opt-in test; set FLUXVM_EGRESS_GUEST=1 (needs root, KVM, dnsmasq, the golden guest image)"
  exit 0
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS="${NS:-fvegress}"
TAP=fvtap0
HOST_IP=192.168.100.1   # the hypervisor addresses its tap 192.168.100.1/24
EXPLICIT_PORT=18888
TRANSPARENT_PORT=18889
KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux-5.10.225-no-acpi}"
GOLDEN="${GOLDEN:-/var/lib/fluxvm/images/linux-agent.raw}"
HV="${FLUXVM_HYPERVISOR:-${PROJECT_DIR}/target/release/fluxvm-hypervisor}"
PROXY_BIN="${PROXY_BIN:-${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}/debug/examples/egress_proxy_ns}"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
section() { echo ""; echo "=== $1 ==="; }

[ "$(uname -s)" = "Linux" ] && [ -e /dev/kvm ] || { echo "SKIP: needs Linux/KVM"; exit 0; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 2; }
for t in ip nft dnsmasq curl python3 debugfs openssl; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done
for f in "$KERNEL" "$GOLDEN" "$HV" "$PROXY_BIN"; do
  [ -e "$f" ] || { echo "missing: $f" >&2; exit 2; }
done
if ip netns list | grep -qw "$NS"; then
  echo "namespace $NS already exists; refusing to reuse it" >&2
  exit 2
fi

count_procs() { ps -eo comm= | grep -c -E "^$1" || true; }
ns_hash() { ip netns list | sort | sha256sum | cut -c1-16; }
# Counters change on their own on a live node; everything else must not.
nft_norm() { nft list ruleset 2>/dev/null | sed -E 's/(packets|bytes) [0-9]+/\1 N/g'; }

NS_BEFORE="$(ns_hash)"
NFT_BEFORE="$(nft_norm | sha256sum | cut -c1-16)"
nft_norm >"/tmp/fvegress-nft-before.$$"
DNSMASQ_BEFORE="$(count_procs dnsmasq)"

TMP="$(mktemp -d)"
HV_PID=""; PROXY_PID=""; UP_PID=""; DNS_PID=""
NS_CREATED=0
CNS="${NS}c"
CNS_CREATED=0
BLOCKED=0
REDIRECT_APPLIED=0

teardown() {
  set +e
  [ "$REDIRECT_APPLIED" = 1 ] && "$PROXY_BIN" redirect-remove "$NS" >/dev/null 2>&1
  for p in "$HV_PID" "$PROXY_PID" "$UP_PID"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null
  done
  [ -f "$TMP/dnsmasq.pid" ] && kill "$(cat "$TMP/dnsmasq.pid" 2>/dev/null)" 2>/dev/null
  sleep 1
  for p in "$HV_PID" "$PROXY_PID" "$UP_PID"; do
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null
  done
  [ -f "$TMP/dnsmasq.pid" ] && kill -9 "$(cat "$TMP/dnsmasq.pid" 2>/dev/null)" 2>/dev/null
  [ "$CNS_CREATED" = 1 ] && ip netns delete "$CNS" 2>/dev/null
  [ "$NS_CREATED" = 1 ] && ip netns delete "$NS" 2>/dev/null
  rm -rf "/etc/netns/$NS" "/etc/netns/$CNS"
  sleep 1
}

verify_teardown() {
  section "teardown"
  [ "$(ns_hash)" = "$NS_BEFORE" ] && pass "ip netns list unchanged" || fail "ip netns list differs from before"
  [ ! -e "/etc/netns/$NS" ] && [ ! -e "/etc/netns/$CNS" ] && pass "/etc/netns/$NS and /etc/netns/$CNS removed" || fail "/etc/netns files left behind"
  local after; after="$(nft_norm | sha256sum | cut -c1-16)"
  if [ "$after" = "$NFT_BEFORE" ]; then
    pass "host nft ruleset unchanged (sha256 ${after})"
  else
    nft_norm >"/tmp/fvegress-nft-after.$$"
    if diff "/tmp/fvegress-nft-before.$$" "/tmp/fvegress-nft-after.$$" | grep -E "fluxvm_egress|fvegress|fvtap|192\.168\.100|1888[89]" >/dev/null; then
      fail "host nft ruleset changed and the diff mentions this test's objects"
    else
      pass "host nft ruleset: hash differs only by unrelated live-node churn (no fluxvm_egress/fvegress/192.168.100 lines)"
    fi
    diff "/tmp/fvegress-nft-before.$$" "/tmp/fvegress-nft-after.$$" | head -10
    rm -f "/tmp/fvegress-nft-after.$$"
  fi
  rm -f "/tmp/fvegress-nft-before.$$"
  [ "$(count_procs dnsmasq)" = "$DNSMASQ_BEFORE" ] && pass "no leftover dnsmasq" || fail "dnsmasq process count changed"
  # The live node runs its own hypervisors, so match on this run's private dir.
  local left="" i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    left="$(pgrep -f -- "$TMP/" | tr '\n' ' ')"
    [ -z "$left" ] && break
    kill -9 $left 2>/dev/null
    sleep 1
  done
  if [ -z "$left" ]; then
    pass "no leftover hypervisor / proxy / upstream / dnsmasq of this run"
  else
    fail "leftover processes of this run: $left"
    ps -o pid,stat,args -p ${left// /,} 2>&1 | cut -c1-160 >&2
  fi
  for p in "$HV_PID" "$PROXY_PID" "$UP_PID"; do
    [ -z "$p" ] || ! kill -0 "$p" 2>/dev/null || fail "pid $p still alive"
  done
}

finish() {
  local rc=$?
  teardown
  verify_teardown
  rm -rf "$TMP"
  echo ""
  echo "egress guest test: ${PASS} passed, ${FAIL} failed"
  [ "$FAIL" -ne 0 ] && exit 1
  [ "$rc" -eq 3 ] && exit 3
  [ "$rc" -eq 0 ] && exit 0
  exit 1
}
trap finish EXIT
trap "exit 143" INT TERM HUP

nsx() { ip netns exec "$NS" "$@"; }

# ---------------------------------------------------------------------------
section "certificates and configuration"
# ---------------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fvegress upstream CA" \
  -keyout "$TMP/upca.key" -out "$TMP/upca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=up.test" -keyout "$TMP/up.key" -out "$TMP/up.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:up.test\n' >"$TMP/up.ext"
openssl x509 -req -in "$TMP/up.csr" -CA "$TMP/upca.crt" -CAkey "$TMP/upca.key" -CAcreateserial \
  -days 2 -extfile "$TMP/up.ext" -out "$TMP/up.crt" >/dev/null 2>&1
cat >"$TMP/sandbox.json" <<JSON
{
  "egress_http_rules": ["allow GET up.test/*", "deny * */admin/*"],
  "egress_tls_intercept": true,
  "egress_ca_cert": "$TMP/ca.crt",
  "egress_ca_key": "$TMP/ca.key",
  "egress_tls_ports": [443],
  "egress_tls_allow_private": true,
  "egress_upstream_ca_file": "$TMP/upca.crt",
  "egress_transparent_listen": "0.0.0.0:${TRANSPARENT_PORT}"
}
JSON
"$PROXY_BIN" init-ca "$TMP/sandbox.json" >/dev/null && [ -s "$TMP/ca.crt" ] \
  && pass "proxy CA generated" || { fail "proxy CA generation"; exit 1; }

cat >"$TMP/upstream.py" <<'PY'
import http.server, ssl, sys, threading
log = open(sys.argv[1], "a", buffering=1)
class H(http.server.BaseHTTPRequestHandler):
    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        log.write(f"{self.command} {self.path}\n")
        body = f"upstream:{self.command}:{self.path}".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_GET = do_POST = do_DELETE = do_PUT = _do
    def log_message(self, *a): pass
tls = http.server.ThreadingHTTPServer(("0.0.0.0", 443), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
plain = http.server.ThreadingHTTPServer(("0.0.0.0", 80), H)
threading.Thread(target=plain.serve_forever, daemon=True).start()
tls.serve_forever()
PY

# The disk is a private copy: NoCloud seed + the proxy CA go in via cloud-init.
cp --sparse=always "$GOLDEN" "$TMP/root.raw"
chmod 0600 "$TMP/root.raw"   # the golden image is read-only (0444)
{
  echo '#cloud-config'
  echo 'hostname: egress-test'
  for key in ca_certs ca-certs; do
    echo "${key}:"
    echo '  trusted:'
    echo '    - |'
    sed 's/^/      /' "$TMP/ca.crt"
  done
} >"$TMP/user-data"
printf 'instance-id: fvegress-%s\nlocal-hostname: egress-test\n' "$$" >"$TMP/meta-data"
cat >"$TMP/debugfs.cmds" <<CMDS
mkdir /var/lib/cloud
mkdir /var/lib/cloud/seed
mkdir /var/lib/cloud/seed/nocloud
rm /var/lib/cloud/seed/nocloud/user-data
rm /var/lib/cloud/seed/nocloud/meta-data
write $TMP/user-data /var/lib/cloud/seed/nocloud/user-data
write $TMP/meta-data /var/lib/cloud/seed/nocloud/meta-data
CMDS
debugfs -w -f "$TMP/debugfs.cmds" "$TMP/root.raw" >/dev/null 2>&1
debugfs -R "cat /var/lib/cloud/seed/nocloud/user-data" "$TMP/root.raw" 2>/dev/null | grep -q "BEGIN CERTIFICATE" \
  && pass "NoCloud seed with the proxy CA written into the private disk copy" \
  || { fail "could not seed the private disk copy"; exit 1; }

# ---------------------------------------------------------------------------
section "namespace ${NS}: dnsmasq, proxy, upstream, redirect"
# ---------------------------------------------------------------------------
ip netns add "$NS" && NS_CREATED=1
nsx ip link set lo up
mkdir -p "/etc/netns/$NS"
echo "${HOST_IP} up.test" >"/etc/netns/$NS/hosts"   # name resolution for the proxy's upstream dial

nsx dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --bind-dynamic --interface="$TAP" \
  --except-interface=lo --dhcp-range=192.168.100.50,192.168.100.60,12h \
  --dhcp-option=3,${HOST_IP} --dhcp-option=6,${HOST_IP} --address=/up.test/${HOST_IP} \
  --dhcp-leasefile="$TMP/leases" --pid-file="$TMP/dnsmasq.pid" --log-facility="$TMP/dnsmasq.log" \
  && pass "dnsmasq (DHCP + DNS) running inside ${NS}" || fail "dnsmasq failed to start"

nsx "$PROXY_BIN" serve "$TMP/sandbox.json" "0.0.0.0:${EXPLICIT_PORT}" >"$TMP/proxy.log" 2>&1 &
PROXY_PID=$!
nsx python3 "$TMP/upstream.py" "$TMP/upstream.log" "$TMP/up.crt" "$TMP/up.key" >"$TMP/upstream.out" 2>&1 &
UP_PID=$!
for _ in $(seq 1 50); do
  nsx ss -ltn 2>/dev/null | grep -q ":${EXPLICIT_PORT} " && nsx ss -ltn 2>/dev/null | grep -q ":443 " \
    && nsx ss -ltn 2>/dev/null | grep -q ":${TRANSPARENT_PORT} " && break
  sleep 0.2
done
nsx ss -ltn | grep -q ":${TRANSPARENT_PORT} " && pass "proxy listening (explicit ${EXPLICIT_PORT}, transparent ${TRANSPARENT_PORT}) and upstream on :443/:80" \
  || { fail "proxy/upstream did not start"; cat "$TMP/proxy.log" "$TMP/upstream.out" >&2; exit 1; }

"$PROXY_BIN" redirect-apply "$NS" "$TAP" 80,443 "$TRANSPARENT_PORT" && REDIRECT_APPLIED=1 \
  && pass "nft redirect for tcp 80,443 installed inside ${NS} only" || { fail "redirect apply"; exit 1; }
nsx nft list ruleset | grep -q fluxvm_egress_tp && pass "redirect table visible inside ${NS}" || fail "redirect table missing inside ${NS}"
nft list ruleset 2>/dev/null | grep -q fluxvm_egress_tp && fail "redirect table leaked into the host namespace" || pass "redirect table absent from the host namespace"

# ---------------------------------------------------------------------------
# Shared test cases. CLIENT_RUN <cmd> runs a shell command in the client.
# ---------------------------------------------------------------------------
gcurl() {  # gcurl "<env prefix>" <curl args...> -> "<body> [code version] rc=N"
  local envp="$1"; shift
  CLIENT_RUN "${envp} curl -sS ${CA_FLAG} --max-time 25 -w ' [%{http_code} %{http_version}]' $* 2>&1; echo \" rc=\$?\"" | tr '\n' ' '
}
expect() {  # expect <name> <regex> <actual>
  if echo "$3" | grep -Eq "$2"; then pass "$1"; else fail "$1: wanted /$2/, got: $3"; fi
}
NOPROXY="env -u https_proxy -u http_proxy -u HTTPS_PROXY -u HTTP_PROXY"
PROXYENV="env https_proxy=http://${HOST_IP}:${EXPLICIT_PORT}"

run_cases() {
  : >"$TMP/upstream.log"
  section "[$1] (a) explicit proxy (https_proxy), curl trusts the proxy CA"
  expect "allowed GET"            'upstream:GET:/ok .*\[200 '           "$(gcurl "$PROXYENV" https://up.test/ok)"
  expect "deny */admin/*"         '\[403 '                               "$(gcurl "$PROXYENV" https://up.test/admin/x)"
  expect "bypass /a/../admin"     '\[403 '                               "$(gcurl "$PROXYENV" --path-as-is https://up.test/a/../admin/x)"
  expect "bypass %61dmin"         '\[403 '                               "$(gcurl "$PROXYENV" --path-as-is https://up.test/%61dmin/x)"
  expect "bypass //admin"         '\[403 '                               "$(gcurl "$PROXYENV" --path-as-is https://up.test//admin/x)"
  expect "POST not allowed"       '\[403 '                               "$(gcurl "$PROXYENV" -X POST -d x https://up.test/ok)"
  expect "CONNECT to an unlisted host refused" 'rc=[1-9]|\[000 |\[403 '  "$(gcurl "$PROXYENV" https://blocked.test/)"
  section "[$1] (c) HTTP/2 from curl to the proxy (explicit)"
  expect "curl --http2 negotiates h2" '\[200 2\]'                        "$(gcurl "$PROXYENV" --http2 https://up.test/ok)"
  section "[$1] (b) transparent redirect: no proxy settings in the client"
  expect "transparent https GET"     'upstream:GET:/ok .*\[200 '        "$(gcurl "$NOPROXY" https://up.test/ok)"
  expect "transparent https deny"    '\[403 '                            "$(gcurl "$NOPROXY" https://up.test/admin/x)"
  expect "transparent https bypass"  '\[403 '                            "$(gcurl "$NOPROXY" --path-as-is https://up.test/a/../admin/x)"
  expect "transparent https POST"    '\[403 '                            "$(gcurl "$NOPROXY" -X POST -d x https://up.test/ok)"
  expect "transparent http GET"      'upstream:GET:/ok .*\[200 '        "$(gcurl "$NOPROXY" http://up.test/ok)"
  expect "transparent http deny"     '\[403 '                            "$(gcurl "$NOPROXY" http://up.test/admin/x)"
  section "[$1] (c) HTTP/2 from curl to the proxy (transparent)"
  expect "curl --http2 negotiates h2" '\[200 2\]'                        "$(gcurl "$NOPROXY" --http2 https://up.test/ok)"
  section "[$1] the upstream saw only the allowed requests"
  echo "  upstream log: $(sort "$TMP/upstream.log" | uniq -c | tr '\n' ';')"
  grep -q "admin" "$TMP/upstream.log" && fail "a denied /admin request reached the upstream" || pass "no /admin request reached the upstream"
  grep -q "^POST" "$TMP/upstream.log" && fail "a denied POST reached the upstream" || pass "no POST reached the upstream"
  [ "$(grep -c '^GET /ok$' "$TMP/upstream.log")" -ge 5 ] && pass "allowed GET /ok requests reached the upstream" || fail "expected >=5 allowed GET /ok at the upstream"
}

# ---------------------------------------------------------------------------
section "stage 1: real curl from a client namespace over a veth (${CNS} -> ${NS})"
# ---------------------------------------------------------------------------
ip netns add "$CNS" && CNS_CREATED=1
mkdir -p "/etc/netns/$CNS"; echo "${HOST_IP} up.test" >"/etc/netns/$CNS/hosts"
ip link add fvc0 netns "$NS" type veth peer name fvc1 netns "$CNS" \
  && nsx ip addr add "${HOST_IP}/24" dev fvc0 && nsx ip link set fvc0 up \
  && ip netns exec "$CNS" ip addr add 192.168.100.2/24 dev fvc1 \
  && ip netns exec "$CNS" ip link set fvc1 up && ip netns exec "$CNS" ip link set lo up \
  && pass "veth fvc0 (${NS}) <-> fvc1 (${CNS}) up" || { fail "veth setup"; exit 1; }
"$PROXY_BIN" redirect-apply "$NS" fvc0 80,443 "$TRANSPARENT_PORT" || { fail "redirect apply (veth)"; exit 1; }
CLIENT_RUN() { ip netns exec "$CNS" bash -c "$1" 2>&1; }
CA_FLAG="--cacert $TMP/ca.crt"
curl --version | grep -q HTTP2 || echo "  note: host curl has no HTTP2; the --http2 cases will fail"
run_cases veth

# ---------------------------------------------------------------------------
section "stage 2: the golden guest inside ${NS}"
# ---------------------------------------------------------------------------
nsx ip link del fvc0 2>/dev/null
ip netns delete "$CNS" && CNS_CREATED=0; rm -rf "/etc/netns/$CNS"
"$PROXY_BIN" redirect-apply "$NS" "$TAP" 80,443 "$TRANSPARENT_PORT" || { fail "redirect apply (tap)"; exit 1; }
cat >"$TMP/boot.json" <<JSON
{
  "kernel": "$KERNEL",
  "rootfs": "$TMP/root.raw",
  "vcpus": 1,
  "memory_mib": 512,
  "engine": "kvm",
  "tap": "$TAP",
  "mac": "02:fa:ce:00:00:01",
  "vsock_cid": 3,
  "vsock_uds": "$TMP/vsock.sock",
  "kernel_args": "console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw random.trust_cpu=on rdrand=force virtio_mmio.device=0x200@0xfeb00000:5 virtio_mmio.device=0x200@0xfeb00200:6"
}
JSON
nsx env FLUXVM_KVM_RUN_SECS=900 "$HV" --api-sock "$TMP/api.sock" --boot-config "$TMP/boot.json" >"$TMP/hv.log" 2>&1 &
HV_PID=$!

for _ in $(seq 1 100); do nsx ip link show "$TAP" >/dev/null 2>&1 && break; sleep 0.2; done
nsx ip link show "$TAP" >/dev/null 2>&1 && pass "hypervisor created ${TAP} inside ${NS}" || { fail "tap ${TAP} never appeared"; tail -20 "$TMP/hv.log" >&2; exit 1; }
# The hypervisor addresses the tap itself; its address and mask must arrive in
# network byte order (regression: it used to be 1.100.168.192/8).
nsx ip -4 -o addr show dev "$TAP" | grep -q "inet ${HOST_IP}/24 " \
  && pass "hypervisor configured ${TAP} as ${HOST_IP}/24" \
  || fail "tap address is not ${HOST_IP}/24: $(nsx ip -4 -o addr show dev "$TAP" | tr '\n' ' ')"

agent() {   # agent "<shell command>" [timeout] -> prints stdout+stderr
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

ready=0
for _ in $(seq 1 120); do
  if [ -S "$TMP/vsock.sock" ] && python3 - "$TMP/vsock.sock" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1])
f = s.makefile("rwb"); f.write(b"CONNECT 17777\n"); f.flush()
assert f.readline().upper().startswith(b"OK")
f.write(b'{"op":"ping"}\n'); f.flush()
assert b"pong" in f.readline()
PY
  then ready=1; break; fi
  kill -0 "$HV_PID" 2>/dev/null || break
  sleep 2
done
if [ "$ready" != 1 ]; then
  fail "guest agent never answered"
  tail -30 "$TMP/hv.log" >&2
  exit 1
fi
pass "guest booted and the agent answers over vsock"

agent "cloud-init status --wait" 150 >"$TMP/ci.out" 2>&1; tail -1 "$TMP/ci.out"
ca_files="$(agent "ls -1 /usr/local/share/ca-certificates/" 20 2>&1)"
echo "$ca_files" | grep -q "cloud-init-ca-cert" && pass "cloud-init ca_certs installed the proxy CA in the guest (${ca_files})" \
  || fail "proxy CA not installed in the guest: ${ca_files}"
agent "openssl verify -CApath /etc/ssl/certs $(echo /usr/local/share/ca-certificates/cloud-init-ca-cert-1.crt) 2>&1 | tail -1" 20 | grep -q "OK" \
  && pass "guest system trust store accepts the proxy CA (openssl verify)" || fail "guest openssl verify of the proxy CA"
agent "curl --version | grep -c HTTP2" 20 | grep -q 1 && pass "guest curl 7.58 has HTTP2" || fail "guest curl lacks HTTP2"

got_ip=0
for _ in $(seq 1 10); do
  out="$(agent "ip -4 -o addr show scope global | awk '{print \$4}'" 8 2>&1)"
  if echo "$out" | grep -q "^192\.168\.100\."; then got_ip=1; break; fi
  sleep 3
done
if [ "$got_ip" != 1 ]; then
  offers="$(grep -c DHCPOFFER "$TMP/dnsmasq.log")"
  echo "  BLOCKED: the guest sent DHCPDISCOVER ($(grep -c DHCPDISCOVER "$TMP/dnsmasq.log") seen by dnsmasq in ${NS}, ${offers} offers sent) but never received a reply." >&2
  echo "  Cause: no tap->guest frames reached the guest (virtio-net RX); see the hypervisor log below." >&2
  grep -E "\[net\]" "$TMP/hv.log" | tail -5 >&2
  echo "--- guest link state" >&2
  agent "ip -o link show eth0; networkctl list 2>&1 | tail -4" 15 >&2 2>&1
  BLOCKED=1
  exit 3
fi
pass "guest got a DHCP lease (${out})"
# The golden image ships no resolv.conf (networkd applies the DHCP DNS option
# only when systemd-resolved runs, and it does not), so point the guest at the
# DHCP-advertised server itself, exactly as option 6 says.
agent "rm -f /etc/resolv.conf; printf 'nameserver ${HOST_IP}\\n' > /etc/resolv.conf" 15 >/dev/null 2>&1
res="$(agent "timeout 10 getent hosts up.test" 20 2>&1)"
echo "$res" | grep -q "^${HOST_IP}" && pass "guest resolves up.test -> ${HOST_IP} via dnsmasq" \
  || {
    fail "guest DNS for up.test: ${res}"
    echo "--- guest resolver diagnostics" >&2
    agent "resolvectl status 2>&1 | head -25; echo ---; cat /etc/resolv.conf; echo ---; ip -4 route; echo ---; timeout 8 ping -c2 -W2 ${HOST_IP} 2>&1 | tail -3; echo ---; timeout 8 nslookup up.test ${HOST_IP} 2>&1 | tail -6" 40 >&2 2>&1
    echo "--- dnsmasq log" >&2; tail -15 "$TMP/dnsmasq.log" >&2
    exit 1
  }
CLIENT_RUN() { agent "$1" 45; }
CA_FLAG=""
run_cases guest
