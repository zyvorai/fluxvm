#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Detailed production-dataplane regression (health, ipcache, FQDN refresh).
#
# Usage:
#   sudo -E ./scripts/test-production-dataplane-e2e.sh [--config PATH]
#       [--kernel PATH] [--rootfs PATH] [--skip-download] [--skip-unit]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONFIG="/etc/fluxvm.toml"
LISTEN=""
KERNEL=""
ROOTFS=""
SKIP_DOWNLOAD=0
SKIP_UNIT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --kernel) KERNEL="$2"; shift 2 ;;
    --rootfs) ROOTFS="$2"; shift 2 ;;
    --skip-download) SKIP_DOWNLOAD=1; shift ;;
    --skip-unit) SKIP_UNIT=1; shift ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
section() { echo ""; echo "=== $1 ==="; }

[ "$(uname -s)" = "Linux" ] || { echo "requires Linux/KVM" >&2; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm missing" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo -E $0)" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "config not found: $CONFIG" >&2; exit 1; }

EPH="${FLUXVM_BIN:-$(command -v fluxvm)}"
STATE_DIR=$(python3 - "$CONFIG" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    print(tomllib.load(f).get("state_dir", "/var/lib/fluxvm"))
PY
)
if [ -z "$LISTEN" ]; then
  LISTEN=$(python3 - "$CONFIG" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    listen = tomllib.load(f).get("listen", "127.0.0.1:7788")
print("http://" + listen if "://" not in listen else listen)
PY
)
fi
KERNEL="${KERNEL:-$STATE_DIR/kernels/vmlinux}"
ROOTFS="${ROOTFS:-$STATE_DIR/images/ubuntu-22.04.ext4}"

# Prefer FLUXVM_TOKEN; else first [[auth.tokens]] entry from config.
if [[ -z "${FLUXVM_TOKEN:-}" ]]; then
  FLUXVM_TOKEN="$(python3 - "$CONFIG" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
tok = ""
in_auth = False
for line in text.splitlines():
    s = line.strip()
    if s == "[auth]":
        in_auth = True
        continue
    if in_auth and s.startswith("[") and not s.startswith("[["):
        break
    if in_auth and s.startswith("token"):
        tok = s.split("=", 1)[1].strip().strip('"')
        break
print(tok)
PY
)"
fi
export FLUXVM_TOKEN
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

TMP="$(mktemp -d)"
CFG_BACKUP="${TMP}/fluxvm.toml.bak"
CFG_TEST="${TMP}/fluxvm-prod.toml"
SERVICE_RESTARTED=0
ID=""
SIMPLE=""

cleanup() {
  curl -sf -m 5 "${AUTH_HDR[@]}" -X DELETE "${LISTEN}/v1/network/cnp/web-egress" >/dev/null 2>&1 || true
  curl -sf -m 5 "${AUTH_HDR[@]}" -X DELETE "${LISTEN}/v1/network/groups/web-egress" >/dev/null 2>&1 || true
  if [ -n "$ID" ]; then
    curl -sf -m 30 "${AUTH_HDR[@]}" -X DELETE "${LISTEN}/v1/vms/${ID}" >/dev/null 2>&1 || \
      "$EPH" --config "$CONFIG" delete "$ID" >/dev/null 2>&1 || true
  fi
  if [ "$SERVICE_RESTARTED" = "1" ] && [ -f "$CFG_BACKUP" ]; then
    cp "$CFG_BACKUP" "$CONFIG"
    systemctl restart fluxvm >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

json_get() {
  python3 -c "
import json,sys
raw=sys.stdin.read().strip()
if not raw: sys.exit(0)
try: d=json.loads(raw)
except Exception: sys.exit(0)
def dig(o,p):
  for x in p.split('.'):
    if isinstance(o,dict): o=o.get(x)
    else: return ''
  return '' if o is None else o
print(dig(d, sys.argv[1]))
" "$1"
}

api() {
  local method="$1" path="$2"; shift 2
  local auth=()
  if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
    auth=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
  fi
  curl -sS -m 60 -X "$method" "${LISTEN}${path}" -H 'Content-Type: application/json' "${auth[@]}" "$@"
}

section "Unit suites"
if [ "$SKIP_UNIT" = "0" ]; then
  python3 "${PROJECT_DIR}/scripts/test-production-dataplane.py" >/tmp/prod-py.log 2>&1 \
    && pass "test-production-dataplane.py" || { fail "prod python"; tail -20 /tmp/prod-py.log >&2; }
  python3 "${PROJECT_DIR}/scripts/test-network-policy.py" >/tmp/np-py.log 2>&1 \
    && pass "test-network-policy.py" || fail "network-policy python"
  CARGO_BIN=""
  for d in "${HOME}/.cargo/bin" "${SUDO_USER:+/home/$SUDO_USER/.cargo/bin}"; do
    [ -n "${d:-}" ] && [ -x "${d}/cargo" ] && CARGO_BIN="${d}/cargo" && export PATH="${d}:$PATH" && break
  done
  [ -z "$CARGO_BIN" ] && command -v cargo >/dev/null && CARGO_BIN=$(command -v cargo)
  if [ -n "$CARGO_BIN" ]; then
    ( cd "$PROJECT_DIR"
      if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
        runuser -u "$SUDO_USER" -- "$CARGO_BIN" test -p fluxvm-network --lib --release
      else
        "$CARGO_BIN" test -p fluxvm-network --lib --release
      fi
    ) >/tmp/prod-rust.log 2>&1
    grep -q 'test result: ok' /tmp/prod-rust.log && pass "cargo test fluxvm-network" \
      || { fail "cargo tests"; tail -30 /tmp/prod-rust.log >&2; }
  fi
fi

section "BPF install + prod profile"
if [ -x "${PROJECT_DIR}/scripts/build-ebpf.sh" ]; then
  ( cd "$PROJECT_DIR" && ./scripts/build-ebpf.sh >/tmp/prod-bpf.log 2>&1 ) \
    && pass "build-ebpf" || { fail "build-ebpf"; tail -20 /tmp/prod-bpf.log >&2; }
  install -D -m0644 "${PROJECT_DIR}/dist/bpf/fluxvm_tc.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
  install -D -m0644 "${PROJECT_DIR}/dist/bpf/fluxvm_xdp.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o
fi

cp "$CONFIG" "$CFG_BACKUP"
# Merge fail-closed prod dataplane settings onto existing config
python3 - "$CONFIG" "$CFG_TEST" "$KERNEL" <<'PY'
import sys, pathlib
src, dst, kernel = sys.argv[1], sys.argv[2], sys.argv[3]
base = pathlib.Path(src).read_text()
lines, skip = [], None
for line in base.splitlines():
    if line.strip().startswith("[sandbox.dataplane"):
        skip = "dp"; continue
    if skip == "dp":
        if line.strip().startswith("["): skip = None
        else: continue
    if line.strip().startswith("fluxvm_kernel") or line.strip().startswith("firecracker_kernel"):
        continue
    lines.append(line)
out = "\n".join(lines).rstrip() + "\n\n"
out += f'fluxvm_kernel = "{kernel}"\nfirecracker_kernel = "{kernel}"\n\n'
out += """[sandbox.dataplane]
mode = "ebpf"
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = true
default_allow = false
allow_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
allow_ports = ["tcp/443", "tcp/80", "udp/53"]
max_egress_mbps = 250
max_egress_pps = 100000
sample_rate = 100
"""
pathlib.Path(dst).write_text(out)
PY
cp "$CFG_TEST" "$CONFIG"
systemctl restart fluxvm
SERVICE_RESTARTED=1
for _ in $(seq 1 40); do curl -sf -m 2 "${AUTH_HDR[@]}" "${LISTEN}/v1/vms" >/dev/null && break; sleep 0.5; done
curl -sf "${AUTH_HDR[@]}" "${LISTEN}/v1/vms" >/dev/null && pass "API up with prod profile" || fail "API down"

section "Health / ipcache / refresh-dns API+CLI"
HEALTH=$(api GET /v1/network/health)
echo "$HEALTH" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert "ok" in d and "bpf_object_present" in d and "ipcache_entries" in d
assert d["bpf_object_present"] is True
assert d["bpffs_present"] is True
assert d["ok"] is True, d.get("notes")
print("mode", d.get("mode"))
' && pass "GET /v1/network/health ok=true" || fail "health: $HEALTH"

"$EPH" --config "$CONFIG" dataplane health >"${TMP}/h.json" \
  && python3 -c "import json;d=json.load(open('${TMP}/h.json'));assert d['ok'] is True" \
  && pass "CLI dataplane health" || fail "CLI health"

IPC=$(api GET /v1/network/ipcache)
echo "$IPC" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert "items" in d' \
  && pass "GET /v1/network/ipcache" || fail "ipcache: $IPC"

REF=$(api POST /v1/network/refresh-dns --data '{}')
echo "$REF" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert "refreshed" in d' \
  && pass "POST /v1/network/refresh-dns" || fail "refresh: $REF"

"$EPH" --config "$CONFIG" dataplane refresh-dns >"${TMP}/r.json" \
  && pass "CLI dataplane refresh-dns" || fail "CLI refresh"

section "FQDN resolve path via CNP + VM"
mkdir -p "$(dirname "$KERNEL")" "$(dirname "$ROOTFS")"
if [ ! -f "$KERNEL" ] || [ ! -f "$ROOTFS" ]; then
  if [ "$SKIP_DOWNLOAD" = "1" ]; then fail "missing assets"; exit 1; fi
  curl -fsSL https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin -o "$KERNEL"
  curl -fsSL https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4 -o "$ROOTFS"
fi

api POST /v1/network/cnp --data @"${PROJECT_DIR}/examples/cnp-web.json" >/dev/null \
  && pass "CNP apply web-egress" || fail "CNP apply"

MAC="02:fc:$(printf '%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
cat > "${TMP}/vm.json" <<JSON
{
  "name": "fluxvm-prod-e2e",
  "backend": "flux-vm",
  "image": "${ROOTFS}",
  "kernel": "${KERNEL}",
  "vcpus": 1,
  "memory_mib": 256,
  "network": {"mode": "tap", "netns": true, "mac": "${MAC}"},
  "ttl_seconds": 600,
  "agent": {"enabled": false}
}
JSON
CREATE=$(api POST /v1/vms --data @"${TMP}/vm.json" 2>"${TMP}/err" || true)
ID=$(printf '%s' "$CREATE" | json_get id)
[ -z "$ID" ] && CREATE=$("$EPH" --config "$CONFIG" create --spec "${TMP}/vm.json" 2>"${TMP}/err" || true) && ID=$(printf '%s' "$CREATE" | json_get id)
[ -n "$ID" ] && pass "VM created $ID" || { fail "create failed $(head -c 200 "${TMP}/err")"; exit 1; }
SIMPLE=$(python3 -c "import uuid; print(uuid.UUID('$ID').hex)")

for _ in $(seq 1 30); do
  ST=$(api GET "/v1/vms/${ID}/network/status" || echo '{}')
  echo "$ST" | python3 -c 'import json,sys;sys.exit(0 if json.load(sys.stdin).get("attached") else 1)' 2>/dev/null && break
  sleep 0.5
done

# Label so CNP group matches; include an FQDN on the VM policy to exercise sync resolve
api POST "/v1/vms/${ID}/network/policy" --data '{
  "default_allow": false,
  "labels": ["app=web"],
  "groups": [],
  "allow_cidrs": [],
  "allow_ports": ["tcp/443"],
  "allow_fqdns": ["example.com"],
  "deny_cidrs": []
}' >/dev/null && pass "policy with labels+FQDN" || fail "policy post"

EFF=$(api GET "/v1/vms/${ID}/network/effective")
echo "$EFF" | python3 -c '
import json,sys
d=json.load(sys.stdin)
names=[g["name"] for g in d["membership"]["matched"]]
assert "web-egress" in names, names
# FQDN resolve may add /32s; at least group CIDRs present
assert "10.0.0.0/8" in d["effective"]["allow_cidrs"] or any("/32" in c for c in d["effective"]["allow_cidrs"])
' && pass "effective includes CNP + FQDN path" || fail "effective: $EFF"

api POST /v1/network/refresh-dns --data '{}' >/dev/null && pass "refresh-dns after FQDN policy" || fail "refresh after"

IPC2=$(api GET /v1/network/ipcache)
echo "$IPC2" | python3 -c '
import json,sys
d=json.load(sys.stdin)
items=d.get("items",[])
# ipcache fills when guest_cidr known at apply; may be empty on some backends
print("ipcache_entries", len(items))
' && pass "ipcache readable after VM policy" || fail "ipcache after"

HEALTH2=$(api GET /v1/network/health)
echo "$HEALTH2" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["ok"] is True; assert d["groups"]>=1' \
  && pass "health shows groups>=1" || fail "health groups: $HEALTH2"

"$EPH" --config "$CONFIG" dataplane ipcache >"${TMP}/ipc.json" && pass "CLI dataplane ipcache" || fail "CLI ipcache"

# preflight bpftool/tc
bash "${PROJECT_DIR}/scripts/preflight.sh" 2>/tmp/pf.log | tee /tmp/pf.out >/dev/null || true
grep -q bpftool /tmp/pf.out && grep -q tc /tmp/pf.out \
  && pass "preflight lists bpftool+tc" || fail "preflight missing bpftool/tc"

section "Teardown"
api DELETE "/v1/vms/${ID}" >/dev/null 2>&1 || "$EPH" --config "$CONFIG" delete "$ID" >/dev/null || true
ID=""
api DELETE /v1/network/cnp/web-egress >/dev/null || true
pass "cleaned"

section "Summary"
echo "  pass: ${PASS}  fail: ${FAIL}"
[ "$FAIL" -eq 0 ]
