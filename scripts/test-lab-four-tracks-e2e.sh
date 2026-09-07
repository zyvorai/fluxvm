#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Lab e2e for the four-track production merge:
#   mTLS header identity, Hubble-lite CEP views, CH QGA serial socket,
#   KVM FLUXVM_KVM_LOCK_MEM + pause/resume.
#
# Run on a Linux/KVM host with fluxvm serve (auth token in /etc/fluxvm.toml).
#
#   sudo -E ./scripts/test-lab-four-tracks-e2e.sh   # CH/QGA + pause need root tools
#   ./scripts/test-lab-four-tracks-e2e.sh             # most checks as kvm-group user
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_DIR"

API="${FLUXVM_API:-http://127.0.0.1:7788}"
KERN="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
IMG="${IMAGE:-/var/lib/fluxvm/images/ubuntu-22.04.ext4}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
FW="${CLOUDHV_FIRMWARE:-/usr/local/share/cloud-hypervisor/CLOUDHV.fd}"
CFG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
section() { echo; echo "======== $1 ========"; }

fluxvm_token() {
  python3 - "$CFG" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
tok = None
in_auth = False
for line in text.splitlines():
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    if s == "[auth]":
        in_auth = True
        continue
    if in_auth and s.startswith("[") and not s.startswith("[["):
        break
    if in_auth and s.startswith("token"):
        tok = s.split("=", 1)[1].strip().strip('"')
print(tok or "")
PY
}

TOKEN="${FLUXVM_TOKEN:-$(fluxvm_token)}"
[[ -n "$TOKEN" ]] || { echo "no FLUXVM_TOKEN / auth.tokens in $CFG" >&2; exit 2; }
AUTH=(-H "Authorization: Bearer $TOKEN")

section "0) static four-tracks"
python3 scripts/test-four-tracks.py -v
ok "test-four-tracks.py"

section "1) mTLS identity"
TLS="${TMPDIR:-/tmp}/fluxvm-mtls-lab-$$"
mkdir -p "$TLS/state" "$TLS/run"
python3 - "$TLS" <<'PY'
import pathlib, subprocess, sys, textwrap
tls = pathlib.Path(sys.argv[1])
(tls / "openssl.cnf").write_text(
    textwrap.dedent(
        """
        [req]
        distinguished_name=req_dn
        x509_extensions=v3_ca
        prompt=no
        [req_dn]
        CN=fluxvm-test-ca
        [v3_ca]
        basicConstraints=critical,CA:TRUE
        keyUsage=critical,keyCertSign,cRLSign,digitalSignature
        subjectKeyIdentifier=hash
        [v3_server]
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=DNS:localhost,IP:127.0.0.1
        [v3_client]
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature,keyEncipherment
        extendedKeyUsage=clientAuth
        """
    )
)
subprocess.check_call(
    [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(tls / "ca.key"),
        "-out",
        str(tls / "ca.crt"),
        "-days",
        "2",
        "-config",
        str(tls / "openssl.cnf"),
        "-extensions",
        "v3_ca",
    ],
    stderr=subprocess.DEVNULL,
)
subprocess.check_call(
    [
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(tls / "server.key"),
        "-out",
        str(tls / "server.csr"),
        "-subj",
        "/CN=localhost",
    ],
    stderr=subprocess.DEVNULL,
)
subprocess.check_call(
    [
        "openssl",
        "x509",
        "-req",
        "-in",
        str(tls / "server.csr"),
        "-CA",
        str(tls / "ca.crt"),
        "-CAkey",
        str(tls / "ca.key"),
        "-CAcreateserial",
        "-out",
        str(tls / "server.crt"),
        "-days",
        "2",
        "-extfile",
        str(tls / "openssl.cnf"),
        "-extensions",
        "v3_server",
    ],
    stderr=subprocess.DEVNULL,
)
subprocess.check_call(
    [
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(tls / "client.key"),
        "-out",
        str(tls / "client.csr"),
        "-subj",
        "/CN=mtls-lab-client",
    ],
    stderr=subprocess.DEVNULL,
)
subprocess.check_call(
    [
        "openssl",
        "x509",
        "-req",
        "-in",
        str(tls / "client.csr"),
        "-CA",
        str(tls / "ca.crt"),
        "-CAkey",
        str(tls / "ca.key"),
        "-CAcreateserial",
        "-out",
        str(tls / "client.crt"),
        "-days",
        "2",
        "-extfile",
        str(tls / "openssl.cnf"),
        "-extensions",
        "v3_client",
    ],
    stderr=subprocess.DEVNULL,
)
PY
cat >"$TLS/fluxvm.toml" <<EOF
listen = "127.0.0.1:17788"
state_dir = "$TLS/state"
run_dir = "$TLS/run"
qemu_binary = "qemu-system-x86_64"
[auth]
require = true
[[auth.tokens]]
token = "fallback-not-used"
role = "admin"
name = "fallback"
[tls]
cert = "$TLS/server.crt"
key = "$TLS/server.key"
client_ca = "$TLS/ca.crt"
EOF
pkill -f "fluxvm --config $TLS/fluxvm.toml" 2>/dev/null || true
BIN="${FLUXVM_BIN:-$(command -v fluxvm || true)}"
[[ -x "$BIN" ]] || BIN=/usr/local/bin/fluxvm
"$BIN" --config "$TLS/fluxvm.toml" serve >"$TLS/serve.log" 2>&1 &
SPID=$!
UP=0
for _ in $(seq 1 30); do
  if curl -sk --max-time 1 --cert "$TLS/client.crt" --key "$TLS/client.key" --cacert "$TLS/ca.crt" \
    https://127.0.0.1:17788/readyz >/dev/null 2>&1; then
    UP=1
    break
  fi
  kill -0 "$SPID" 2>/dev/null || break
  sleep 0.2
done
if [[ "$UP" != 1 ]]; then
  bad "mTLS serve"
  tail -20 "$TLS/serve.log" || true
else
  ok "mTLS serve"
  C2=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    --cert "$TLS/client.crt" --key "$TLS/client.key" --cacert "$TLS/ca.crt" \
    https://127.0.0.1:17788/v1/network/endpoints || echo 000)
  C3=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    --cert "$TLS/client.crt" --key "$TLS/client.key" --cacert "$TLS/ca.crt" \
    -H "X-Client-Cert-CN: mtls-lab-client" -H "X-Client-Cert-Role: admin" \
    https://127.0.0.1:17788/v1/network/endpoints || echo 000)
  [[ "$C2" == "401" ]] && ok "mTLS nohdr → 401" || bad "mTLS nohdr=$C2"
  [[ "$C3" == "200" ]] && ok "mTLS admin headers → 200" || bad "mTLS admin=$C3"
fi
kill "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
rm -rf "$TLS"

section "2) Hubble-lite"
CREATE=$(curl -sS --max-time 120 "${AUTH[@]}" -H "Content-Type: application/json" -X POST "$API/v1/vms" \
  -d "{\"name\":\"hubble-lab\",\"backend\":\"qemu\",\"image\":\"$IMG\",\"kernel\":\"$KERN\",\"vcpus\":1,\"memory_mib\":512,\"network\":{\"mode\":\"tap\",\"netns\":true,\"mac\":\"52:54:00:12:34:99\"}}")
VID=$(echo "$CREATE" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("id",""))
except: print("")')
if [[ -n "$VID" ]]; then
  sleep 2
  EP=$(curl -sf "${AUTH[@]}" "$API/v1/network/endpoints")
  echo "$EP" | grep -q "$VID" && ok "endpoint for $VID" || bad "no endpoint for $VID"
  curl -sf "${AUTH[@]}" "$API/v1/network/hubble/flows" | grep -q '"items"' && ok "hubble flows" || bad "hubble flows"
  curl -sf "${AUTH[@]}" "$API/v1/network/hubble/ui" | head -c 120 | grep -qiE 'html|hubble|flow' && ok "hubble ui" || bad "hubble ui"
  "$BIN" --config "$CFG" hubble endpoints >/dev/null && ok "cli hubble endpoints" || bad "cli hubble"
  curl -sf "${AUTH[@]}" -X DELETE "$API/v1/vms/$VID" >/dev/null || true
else
  bad "hubble VM create: $(echo "$CREATE" | head -c 200)"
fi

section "3) CH QGA serial"
if [[ ! -f "$FW" ]]; then
  bad "CLOUDHV firmware missing ($FW)"
else
  RAW="${CH_QGA_RAW:-/var/lib/fluxvm/images/ch-qga-lab.raw}"
  if [[ ! -f "$RAW" ]]; then
    sudo qemu-img convert -f raw -O raw "$IMG" "$RAW"
    sudo chmod 644 "$RAW"
  fi
  SPEC=$(mktemp)
  python3 - "$SPEC" "$RAW" "$FW" <<'PY'
import json, sys
json.dump(
    {
        "name": "ch-qga-lab",
        "backend": "cloud-hypervisor",
        "image": sys.argv[2],
        "firmware": sys.argv[3],
        "qga": {"enabled": True},
        "vcpus": 1,
        "memory_mib": 512,
        "network": {"mode": "none"},
        "hyperv": True,
    },
    open(sys.argv[1], "w"),
)
PY
  CHOUT=$(curl -sS --max-time 90 "${AUTH[@]}" -H "Content-Type: application/json" \
    -X POST "$API/v1/vms" --data @"$SPEC")
  rm -f "$SPEC"
  CHID=$(echo "$CHOUT" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("id",""))
except: print("")')
  if [[ -n "$CHID" ]]; then
    sleep 2
    SOCK="/var/lib/fluxvm/instances/$CHID/qga.sock"
    if [[ -S "$SOCK" ]] || sudo test -S "$SOCK"; then
      ok "qga.sock present"
    else
      bad "no qga.sock for $CHID"
    fi
    curl -sf "${AUTH[@]}" -X DELETE "$API/v1/vms/$CHID" >/dev/null || true
  else
    bad "CH create: $(echo "$CHOUT" | head -c 250)"
  fi
fi

section "4) KVM lock-mem + pause"
chmod +x scripts/test-kvm-pause-smoke.sh
if FLUXVM_KVM_LOCK_MEM=1 ./scripts/test-kvm-pause-smoke.sh; then
  ok "pause smoke under LOCK_MEM"
else
  bad "pause smoke"
fi
TMP=$(mktemp -d)
BOOT="$TMP/boot.json"
cat >"$BOOT" <<JSON
{"kernel":"$KERN","rootfs":"$ROOTFS","vcpus":1,"memory_mib":256,"engine":"kvm","kernel_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/bin/sleep"}
JSON
HV="${FLUXVM_HYPERVISOR:-/usr/local/bin/fluxvm-hypervisor}"
FLUXVM_KVM_LOCK_MEM=1 "$HV" --api-sock "$TMP/api.sock" --boot-config "$BOOT" >"$TMP/hv.log" 2>&1 &
HPID=$!
sleep 2
VMLCK=$(awk '/VmLck:/{print $2}' /proc/$HPID/status 2>/dev/null || echo 0)
[[ "${VMLCK:-0}" != "0" ]] && ok "VmLck=$VMLCK kB" || bad "VmLck=$VMLCK"
kill "$HPID" 2>/dev/null || true
wait "$HPID" 2>/dev/null || true
rm -rf "$TMP"

echo
echo "four-tracks-e2e PASS=$PASS FAIL=$FAIL"
exit $((FAIL > 0 ? 1 : 0))
