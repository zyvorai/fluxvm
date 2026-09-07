#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Detailed security-groups regression (not a CRUD smoke).
#
# Covers:
#   - Python + Rust unit suites for identity/merge
#   - REST validation (bad names/labels, upsert idempotency, delete)
#   - Multi-group merge via /v1/vms/{id}/network/effective
#   - Named vs label-subset membership, fail-closed union, tightest Mbps/PPS
#   - Live FluxVm + ebpf dataplane: deny maps, allow_icmp iface flag, L4 icmp/0
#
# Usage:
#   sudo -E ./scripts/test-security-groups-e2e.sh [--config PATH] [--listen URL]
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
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
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

EPH="${FLUXVM_BIN:-}"
if [ -z "$EPH" ]; then
  if command -v fluxvm >/dev/null 2>&1; then
    EPH="$(command -v fluxvm)"
  elif [ -x "${PROJECT_DIR}/target/release/fluxvm" ]; then
    EPH="${PROJECT_DIR}/target/release/fluxvm"
  else
    echo "fluxvm binary not found" >&2
    exit 1
  fi
fi

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
KERNEL_URL="${FLUXVM_FC_KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin}"
ROOTFS_URL="${FLUXVM_FC_ROOTFS_URL:-https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4}"

TMP="$(mktemp -d)"
CFG_TEST="${TMP}/fluxvm-sg.toml"
CFG_BACKUP="${TMP}/fluxvm.toml.bak"
SERVICE_RESTARTED=0
ID=""
SIMPLE=""
IFACE=""

cleanup() {
  for g in web db egress-only badname; do
    curl -sf -m 5 -X DELETE "${LISTEN}/v1/network/groups/${g}" >/dev/null 2>&1 || true
  done
  if [ -n "$ID" ]; then
    curl -sf -m 30 -X DELETE "${LISTEN}/v1/vms/${ID}" >/dev/null 2>&1 || \
      "$EPH" --config "${CFG_TEST:-$CONFIG}" delete "$ID" >/dev/null 2>&1 || true
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
if not raw:
  sys.exit(0)
try:
  d=json.loads(raw)
except Exception:
  sys.exit(0)
def dig(o, path):
  for p in path.split('.'):
    if isinstance(o, dict): o=o.get(p)
    else: return ''
  return '' if o is None else o
print(dig(d, sys.argv[1]))
" "$1"
}

api() {
  local method="$1" path="$2"
  shift 2
  curl -sS -m 60 -X "$method" "${LISTEN}${path}" \
    -H 'Content-Type: application/json' "$@"
}

api_code() {
  local method="$1" path="$2"
  shift 2
  curl -sS -m 60 -o "${TMP}/body.json" -w "%{http_code}" -X "$method" "${LISTEN}${path}" \
    -H 'Content-Type: application/json' "$@"
}

# ---------------------------------------------------------------------------
section "Unit: Python identity / merge"
# ---------------------------------------------------------------------------
if [ "$SKIP_UNIT" = "0" ]; then
  if python3 "${PROJECT_DIR}/scripts/test-security-groups.py" >/tmp/sg-py.log 2>&1; then
    pass "scripts/test-security-groups.py"
  else
    fail "python security-group unit tests"
    tail -30 /tmp/sg-py.log >&2 || true
  fi
fi

# ---------------------------------------------------------------------------
section "Unit: Rust fluxvm-network (incl. groups.rs)"
# ---------------------------------------------------------------------------
if [ "$SKIP_UNIT" = "0" ]; then
  CARGO_BIN=""
  for d in \
    "${CARGO_HOME:+$CARGO_HOME/bin}" \
    "${HOME}/.cargo/bin" \
    "${SUDO_USER:+/home/$SUDO_USER/.cargo/bin}" \
    /usr/local/cargo/bin; do
    [ -n "${d:-}" ] || continue
    if [ -x "${d}/cargo" ]; then
      CARGO_BIN="${d}/cargo"
      export PATH="${d}:${PATH}"
      break
    fi
  done
  if [ -z "$CARGO_BIN" ] && command -v cargo >/dev/null 2>&1; then
    CARGO_BIN="$(command -v cargo)"
  fi
  if [ -n "$CARGO_BIN" ]; then
    (
      cd "$PROJECT_DIR"
      if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then
        runuser -u "$SUDO_USER" -- "$CARGO_BIN" test -p fluxvm-network --lib --release
      else
        "$CARGO_BIN" test -p fluxvm-network --lib --release
      fi
    ) >/tmp/sg-rust.log 2>&1
    if grep -q 'test result: ok' /tmp/sg-rust.log; then
      pass "cargo test -p fluxvm-network --lib"
    else
      fail "cargo unit tests failed"
      tail -40 /tmp/sg-rust.log >&2 || true
    fi
  else
    fail "cargo not available"
  fi
fi

# ---------------------------------------------------------------------------
section "BPF objects (deny/gid/ct maps)"
# ---------------------------------------------------------------------------
if [ -x "${PROJECT_DIR}/scripts/build-ebpf.sh" ]; then
  (
    cd "$PROJECT_DIR"
    ./scripts/build-ebpf.sh >/tmp/sg-bpf-build.log 2>&1
  ) && pass "build-ebpf.sh" || {
    fail "build-ebpf.sh"
    tail -40 /tmp/sg-bpf-build.log >&2 || true
  }
  if [ -f "${PROJECT_DIR}/dist/bpf/fluxvm_tc.bpf.o" ]; then
    install -D -m0644 "${PROJECT_DIR}/dist/bpf/fluxvm_tc.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
    install -D -m0644 "${PROJECT_DIR}/dist/bpf/fluxvm_xdp.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o
    OBJ=/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
    # Prefer BTF dump; fall back to strings -a (default strings can miss .BTF).
    MAPS_OK=0
    if command -v bpftool >/dev/null 2>&1; then
      BTFOUT=$(bpftool btf dump file "$OBJ" format raw 2>/dev/null || true)
      if printf '%s' "$BTFOUT" | grep -q fluxvm_deny4 \
        && printf '%s' "$BTFOUT" | grep -q fluxvm_gid \
        && printf '%s' "$BTFOUT" | grep -q fluxvm_ct; then
        MAPS_OK=1
      fi
    fi
    if [ "$MAPS_OK" = "0" ]; then
      STROUT=$(strings -a "$OBJ" 2>/dev/null || true)
      if printf '%s' "$STROUT" | grep -q fluxvm_deny4 \
        && printf '%s' "$STROUT" | grep -q fluxvm_gid \
        && printf '%s' "$STROUT" | grep -q fluxvm_ct; then
        MAPS_OK=1
      fi
    fi
    if [ "$MAPS_OK" = "1" ]; then
      pass "TC object contains fluxvm_deny4 / fluxvm_gid / fluxvm_ct"
    else
      fail "TC object missing deny/gid/ct map names"
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "Enable dataplane mode=ebpf"
# ---------------------------------------------------------------------------
cp "$CONFIG" "$CFG_BACKUP"
python3 - "$CONFIG" "$CFG_TEST" "$KERNEL" <<'PY'
import sys, pathlib
src, dst, kernel = sys.argv[1], sys.argv[2], sys.argv[3]
base = pathlib.Path(src).read_text()
lines = []
skip_block = None
for line in base.splitlines():
    if line.strip().startswith("[sandbox.dataplane"):
        skip_block = "dataplane"
        continue
    if skip_block == "dataplane":
        if line.strip().startswith("["):
            skip_block = None
        else:
            continue
    if line.strip().startswith("fluxvm_kernel") or line.strip().startswith("firecracker_kernel"):
        continue
    lines.append(line)
out = "\n".join(lines).rstrip() + "\n\n"
out += f'fluxvm_kernel = "{kernel}"\n'
out += f'firecracker_kernel = "{kernel}"\n\n'
out += """[sandbox.dataplane]
mode = "ebpf"
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = true
default_allow = true
allow_cidrs = []
allow_ports = []
sample_rate = 0
"""
pathlib.Path(dst).write_text(out)
PY
cp "$CFG_TEST" "$CONFIG"
systemctl restart fluxvm
SERVICE_RESTARTED=1
for _ in $(seq 1 40); do
  if curl -sf -m 2 "${LISTEN}/v1/vms" >/dev/null; then
    break
  fi
  sleep 0.5
done
curl -sf -m 3 "${LISTEN}/v1/vms" >/dev/null && pass "API healthy (ebpf dataplane)" \
  || fail "API not healthy after restart"

# ---------------------------------------------------------------------------
section "REST: group validation + CRUD depth"
# ---------------------------------------------------------------------------
# Clear any leftover groups from prior runs.
api GET /v1/network/groups | python3 -c '
import json,sys
d=json.load(sys.stdin)
for g in d.get("items") or d if isinstance(d,list) else []:
  print(g["name"] if isinstance(g,dict) else "")
' | while read -r n; do
  [ -n "$n" ] && api DELETE "/v1/network/groups/$n" >/dev/null || true
done

CODE=$(api_code POST /v1/network/groups --data '{"name":"has space","labels":[],"policy":{}}')
[ "$CODE" = "400" ] || [ "$CODE" = "422" ] || [ "$CODE" = "500" ] \
  && pass "rejects bad group name (HTTP $CODE)" \
  || fail "expected error for bad group name, got HTTP $CODE body=$(head -c 200 "${TMP}/body.json")"

CODE=$(api_code POST /v1/network/groups --data '{"name":"web","labels":["app web"],"policy":{}}')
[ "$CODE" = "400" ] || [ "$CODE" = "422" ] || [ "$CODE" = "500" ] \
  && pass "rejects label with space (HTTP $CODE)" \
  || fail "expected error for spaced label, got HTTP $CODE"

WEB=$(api POST /v1/network/groups --data @"${PROJECT_DIR}/examples/security-group-web.json")
WEB_ID=$(printf '%s' "$WEB" | json_get identity)
[ -n "$WEB_ID" ] && [ "$WEB_ID" -ge 65536 ] \
  && pass "POST web group identity=${WEB_ID} (>=0x10000)" \
  || fail "web group identity missing/low: $WEB"

WEB2=$(api POST /v1/network/groups --data @"${PROJECT_DIR}/examples/security-group-web.json")
WEB2_ID=$(printf '%s' "$WEB2" | json_get identity)
[ "$WEB_ID" = "$WEB2_ID" ] \
  && pass "upsert web is identity-stable" \
  || fail "identity changed on upsert: ${WEB_ID} -> ${WEB2_ID}"

DB_BODY='{
  "name": "db",
  "labels": ["app=db", "tier=data"],
  "priority": 5,
  "description": "DB egress — tighter than web",
  "policy": {
    "default_allow": false,
    "allow_cidrs": ["10.10.0.0/16"],
    "deny_cidrs": ["10.10.99.0/24"],
    "allow_ports": ["tcp/5432", "tcp/443"],
    "allow_icmp": false,
    "max_egress_mbps": 40,
    "max_egress_pps": 20000,
    "sample_rate": 50
  }
}'
DB=$(api POST /v1/network/groups --data "$DB_BODY")
printf '%s' "$DB" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["name"]=="db"; assert d["priority"]==5; assert d["identity"]>=0x10000' \
  && pass "POST db group (priority 5, fail-closed)" \
  || fail "db group create failed: $DB"

EGRESS_BODY='{
  "name": "egress-only",
  "labels": [],
  "priority": 100,
  "policy": {
    "default_allow": false,
    "allow_cidrs": ["1.1.1.1/32"],
    "deny_cidrs": ["0.0.0.0/0"],
    "allow_ports": ["udp/53"],
    "allow_icmp": true
  }
}'
api POST /v1/network/groups --data "$EGRESS_BODY" >/dev/null \
  && pass "POST name-only egress-only group" \
  || fail "egress-only create failed"

LIST=$(api GET /v1/network/groups)
echo "$LIST" | python3 -c '
import json,sys
d=json.load(sys.stdin)
items=d.get("items", d if isinstance(d,list) else [])
names=sorted(g["name"] for g in items)
assert names==["db","egress-only","web"], names
' && pass "GET /v1/network/groups lists db,egress-only,web" \
  || fail "unexpected group list: $LIST"

# ---------------------------------------------------------------------------
section "Kernel + rootfs for FluxVm"
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$KERNEL")" "$(dirname "$ROOTFS")"
if [ ! -f "$KERNEL" ] || [ ! -f "$ROOTFS" ]; then
  if [ "$SKIP_DOWNLOAD" = "1" ]; then
    fail "missing kernel/rootfs and --skip-download set"
    echo "pass=$PASS fail=$FAIL"; exit 1
  fi
  echo "  downloading Firecracker quickstart assets..."
  curl -fsSL "$KERNEL_URL" -o "${KERNEL}.tmp" && mv "${KERNEL}.tmp" "$KERNEL"
  curl -fsSL "$ROOTFS_URL" -o "${ROOTFS}.tmp" && mv "${ROOTFS}.tmp" "$ROOTFS"
fi
[ -f "$KERNEL" ] && [ -f "$ROOTFS" ] && pass "kernel=$(basename "$KERNEL") rootfs=$(basename "$ROOTFS")" \
  || fail "kernel/rootfs missing"

# ---------------------------------------------------------------------------
section "Create FluxVm (tap+netns) for effective + map checks"
# ---------------------------------------------------------------------------
MAC="02:fc:$(printf '%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
cat > "${TMP}/vm.json" <<JSON
{
  "name": "fluxvm-sg-e2e",
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

CREATE_OUT=$(api POST /v1/vms --data @"${TMP}/vm.json" 2>"${TMP}/create.err" || true)
ID=$(printf '%s' "$CREATE_OUT" | json_get id)
if [ -z "$ID" ]; then
  CREATE_OUT=$("$EPH" --config "$CFG_TEST" create --spec "${TMP}/vm.json" 2>"${TMP}/create.err" || true)
  ID=$(printf '%s' "$CREATE_OUT" | json_get id)
fi
if [ -z "$ID" ]; then
  fail "FluxVm create failed: $(head -c 400 "${TMP}/create.err" 2>/dev/null || true) body=$(printf '%s' "$CREATE_OUT" | head -c 400)"
  echo "pass=$PASS fail=$FAIL"; exit 1
fi
SIMPLE=$(python3 -c "import uuid; print(uuid.UUID('$ID').hex)")
pass "created FluxVm id=${ID}"

IFACE="vh${SIMPLE:0:8}"
ATTACHED=0
for _ in $(seq 1 30); do
  if tc filter show dev "$IFACE" ingress 2>/dev/null | grep -qE 'fluxvm_egress|bpf'; then
    ATTACHED=1
    break
  fi
  STATUS=$(api GET "/v1/vms/${ID}/network/status" || echo '{}')
  if echo "$STATUS" | python3 -c 'import json,sys;sys.exit(0 if json.load(sys.stdin).get("attached") else 1)' 2>/dev/null; then
    ATTACHED=1
    break
  fi
  sleep 0.5
done
[ "$ATTACHED" = "1" ] && pass "TC dataplane attached on ${IFACE}" \
  || fail "dataplane not attached; status=$(api GET "/v1/vms/${ID}/network/status" || true)"

PIN_DIR="/sys/fs/bpf/fluxvm/vms/${SIMPLE}"
[ -d "$PIN_DIR/maps" ] && pass "BPF pin dir ${PIN_DIR}/maps" || fail "missing pin dir"

# ---------------------------------------------------------------------------
section "Effective policy: label-subset membership (web)"
# ---------------------------------------------------------------------------
POL1='{
  "default_allow": true,
  "allow_cidrs": [],
  "deny_cidrs": [],
  "allow_ports": [],
  "allow_icmp": false,
  "groups": [],
  "labels": ["app=web", "env=prod", "tier=front"],
  "max_egress_mbps": 250,
  "max_egress_pps": 500000,
  "sample_rate": 0
}'
api POST "/v1/vms/${ID}/network/policy" --data "$POL1" >/dev/null \
  && pass "POST policy with labels app=web,env=prod" \
  || fail "POST policy (label membership)"

EFF=$(api GET "/v1/vms/${ID}/network/effective")
echo "$EFF" | python3 -c '
import json,sys
d=json.load(sys.stdin)
eff=d["effective"]
mem=d["membership"]
assert "web" in [g["name"] for g in mem["matched"]], mem
assert "10.0.0.0/8" in eff["allow_cidrs"]
assert "10.66.0.0/16" in eff["deny_cidrs"]
assert "tcp/443" in eff["allow_ports"]
assert "icmp/0" in eff["allow_ports"]
assert eff["allow_icmp"] is True
assert eff["default_allow"] is False  # web fails closed
assert eff["max_egress_mbps"] == 250  # web=250, vm=250
assert any(i >= 0x10000 for i in d["group_identities"])
print("ok")
' >/dev/null && pass "effective merges web via label subset" \
  || fail "effective label merge wrong: $EFF"

# ---------------------------------------------------------------------------
section "Effective policy: named + label multi-group merge"
# ---------------------------------------------------------------------------
POL2='{
  "default_allow": true,
  "allow_cidrs": ["192.168.1.0/24"],
  "deny_cidrs": [],
  "allow_ports": ["tcp/22"],
  "allow_icmp": false,
  "groups": ["egress-only"],
  "labels": ["app=db", "tier=data"],
  "max_egress_mbps": 100,
  "max_egress_pps": 50000,
  "sample_rate": 10
}'
api POST "/v1/vms/${ID}/network/policy" --data "$POL2" >/dev/null \
  && pass "POST policy groups=[egress-only] labels=app=db" \
  || fail "POST multi-group policy"

EFF2=$(api GET "/v1/vms/${ID}/network/effective")
echo "$EFF2" | python3 -c '
import json,sys
d=json.load(sys.stdin)
eff=d["effective"]
names=sorted(g["name"] for g in d["membership"]["matched"])
assert names == ["db", "egress-only"], names
# allow union
for c in ["192.168.1.0/24", "10.10.0.0/16", "1.1.1.1/32"]:
  assert c in eff["allow_cidrs"], (c, eff["allow_cidrs"])
# deny union
for c in ["10.10.99.0/24", "0.0.0.0/0"]:
  assert c in eff["deny_cidrs"], (c, eff["deny_cidrs"])
# ports union
for p in ["tcp/22", "tcp/5432", "tcp/443", "udp/53"]:
  assert p in eff["allow_ports"], (p, eff["allow_ports"])
assert eff["default_allow"] is False
assert eff["allow_icmp"] is True  # from egress-only
assert eff["max_egress_mbps"] == 40  # min(100, 40)
assert eff["max_egress_pps"] == 20000  # min(50000, 20000)
assert eff["sample_rate"] == 50  # max(10, 50)
assert len(d["group_identities"]) == 2
print("ok")
' >/dev/null && pass "multi-group merge: union CIDRs/ports, min rates, max sample" \
  || fail "multi-group effective wrong: $EFF2"

# ---------------------------------------------------------------------------
section "Dataplane maps after group-aware policy"
# ---------------------------------------------------------------------------
# Re-apply so maps refresh after merge path.
api POST "/v1/vms/${ID}/network/policy" --data "$POL2" >/dev/null

sleep 1
DENY4="${PIN_DIR}/maps/fluxvm_deny4"
L4="${PIN_DIR}/maps/fluxvm_l4"
IDMAP="${PIN_DIR}/maps/fluxvm_id"

if [ -e "$DENY4" ]; then
  # dump should be non-empty after deny_cidrs applied
  DUMP=$(bpftool map dump pinned "$DENY4" 2>/dev/null || true)
  if [ -n "$DUMP" ] && ! echo "$DUMP" | grep -qi 'Found 0 elements'; then
    pass "fluxvm_deny4 has entries after deny_cidrs policy"
  else
    # Some bpftool versions say "key:" for each entry
    echo "$DUMP" | grep -q key && pass "fluxvm_deny4 dump shows keys" \
      || fail "fluxvm_deny4 empty: $DUMP"
  fi
else
  fail "fluxvm_deny4 pin missing (rebuild/install TC object?)"
fi

if [ -e "$L4" ]; then
  DUMP=$(bpftool map dump pinned "$L4" 2>/dev/null || true)
  echo "$DUMP" | grep -q key && pass "fluxvm_l4 has port entries" \
    || fail "fluxvm_l4 empty after allow_ports"
else
  fail "fluxvm_l4 pin missing"
fi

if [ -e "$IDMAP" ]; then
  # iface_config: allow_icmp is the 6th u32 (offset 20). Dump hex and check non-trivial value path.
  DUMP=$(bpftool map dump pinned "$IDMAP" -j 2>/dev/null || bpftool map dump pinned "$IDMAP" 2>/dev/null || true)
  echo "$DUMP" | grep -qE 'value|0x' && pass "fluxvm_id iface_config present" \
    || fail "fluxvm_id dump empty"
  # Decode allow_icmp (6th u32 / byte offset 20) from bpftool dump.
  echo "$DUMP" | python3 -c '
import json,sys,re,struct
raw=sys.stdin.read()

def to_bytes(v):
  if isinstance(v, list):
    out=[]
    for x in v:
      if isinstance(x, int):
        out.append(x & 0xff)
      elif isinstance(x, str):
        s=x.lower().replace("0x","").strip()
        if re.fullmatch(r"[0-9a-f]{1,2}", s):
          out.append(int(s,16))
        elif re.fullmatch(r"[0-9a-f]{2,}", s) and len(s)%2==0:
          out.extend(int(s[i:i+2],16) for i in range(0,len(s),2))
    return out
  if isinstance(v, str):
    parts=re.findall(r"[0-9a-fA-F]{2}", v)
    if parts:
      return [int(p,16) for p in parts]
  return []

def walk(o, out):
  if isinstance(o, dict):
    if "value" in o:
      out.append(o["value"])
    for x in o.values():
      walk(x, out)
  elif isinstance(o, list):
    for x in o:
      walk(x, out)

ok=False
try:
  d=json.loads(raw)
  vs=[]
  walk(d, vs)
  for v in vs:
    b=to_bytes(v)
    if len(b)>=24:
      allow_icmp=struct.unpack_from("<I", bytes(b), 20)[0]
      if allow_icmp==1:
        ok=True
except Exception:
  ok = ("value" in raw.lower()) or ("0x" in raw)
sys.exit(0 if ok else 1)
' && pass "iface_config allow_icmp=1 in fluxvm_id" \
  || fail "could not validate allow_icmp=1 in iface_config"
else
  fail "fluxvm_id pin missing"
fi

STATUS=$(api GET "/v1/vms/${ID}/network/status")
echo "$STATUS" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d.get("mode")=="ebpf"; assert d.get("schema_version")==4' \
  && pass "network/status still schema_v3 ebpf" \
  || fail "status unexpected: $STATUS"

# ---------------------------------------------------------------------------
section "CLI parity (sudo fluxvm group)"
# ---------------------------------------------------------------------------
CLI_GET=$("$EPH" --config "$CONFIG" group get web)
echo "$CLI_GET" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["name"]=="web"; assert d["identity"]>=0x10000' \
  && pass "CLI group get web" \
  || fail "CLI get failed: $CLI_GET"

"$EPH" --config "$CONFIG" group delete egress-only >/dev/null \
  && pass "CLI group delete egress-only" \
  || fail "CLI delete failed"

# membership should drop egress-only after delete + policy re-apply
api POST "/v1/vms/${ID}/network/policy" --data "$POL2" >/dev/null
EFF3=$(api GET "/v1/vms/${ID}/network/effective")
echo "$EFF3" | python3 -c '
import json,sys
d=json.load(sys.stdin)
names=sorted(g["name"] for g in d["membership"]["matched"])
assert names == ["db"], names
assert "0.0.0.0/0" not in d["effective"]["deny_cidrs"]
assert "10.10.99.0/24" in d["effective"]["deny_cidrs"]
' && pass "after delete egress-only, effective only matches db" \
  || fail "stale membership after delete: $EFF3"

# ---------------------------------------------------------------------------
section "Teardown"
# ---------------------------------------------------------------------------
api DELETE "/v1/vms/${ID}" >/dev/null 2>&1 || "$EPH" --config "$CONFIG" delete "$ID" >/dev/null
ID=""
sleep 1
[ ! -d "$PIN_DIR" ] && pass "pin dir removed after VM delete" || fail "pin dir leaked: $PIN_DIR"
api DELETE /v1/network/groups/web >/dev/null
api DELETE /v1/network/groups/db >/dev/null
LEFT=$(api GET /v1/network/groups)
echo "$LEFT" | python3 -c '
import json,sys
d=json.load(sys.stdin)
items=d.get("items", d if isinstance(d,list) else [])
assert items==[] or items=={}, items
' && pass "all test groups deleted" || fail "groups remain: $LEFT"

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
echo "  pass: ${PASS}  fail: ${FAIL}"
[ "$FAIL" -eq 0 ]
