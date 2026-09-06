#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# End-to-end Network Fabric regression: kernel TC/XDP smoke + FluxVm dataplane
# attach + REST policy/status/stats/flows (including live reconfigure and rate
# limits).
#
# Usage:
#   sudo -E ./scripts/test-network-fabric.sh [--config PATH] [--listen URL]
#       [--kernel PATH] [--rootfs PATH] [--skip-download]
#
# Env:
#   FLUXVM_BIN           fluxvm binary
#   FLUXVM_FABRIC_LISTEN override API base (default: parsed from config listen)
#
# The script temporarily enables sandbox.dataplane.mode=ebpf in a working copy
# of the config, restarts the fluxvm service, runs the suite, then restores
# the previous unit config and restarts again.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONFIG="/etc/fluxvm.toml"
LISTEN=""
KERNEL=""
ROOTFS=""
SKIP_DOWNLOAD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --kernel) KERNEL="$2"; shift 2 ;;
    --rootfs) ROOTFS="$2"; shift 2 ;;
    --skip-download) SKIP_DOWNLOAD=1; shift ;;
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

KERNEL="${KERNEL:-$STATE_DIR/kernels/vmlinux-fabric-test}"
ROOTFS="${ROOTFS:-$STATE_DIR/images/bionic-fabric-rootfs.ext4}"
KERNEL_URL="${FLUXVM_FC_KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin}"
ROOTFS_URL="${FLUXVM_FC_ROOTFS_URL:-https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4}"

TMP="$(mktemp -d)"
CFG_TEST="${TMP}/fluxvm-fabric.toml"
CFG_BACKUP="${TMP}/fluxvm.toml.bak"
SERVICE_RESTARTED=0
ID=""
SIMPLE=""
IFACE=""

cleanup() {
  if [ -n "$ID" ]; then
    "$EPH" --config "$CFG_TEST" delete "$ID" >/dev/null 2>&1 || \
      curl -sf -X DELETE "${LISTEN}/v1/vms/${ID}" >/dev/null 2>&1 || true
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

# ---------------------------------------------------------------------------
section "Unit tests (fluxvm-core / fluxvm-network)"
# ---------------------------------------------------------------------------
# Under `sudo`, HOME is often /root — prefer the invoking user's cargo install.
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
      runuser -u "$SUDO_USER" -- "$CARGO_BIN" test -p fluxvm-core -p fluxvm-network --lib --release
    else
      "$CARGO_BIN" test -p fluxvm-core -p fluxvm-network --lib --release
    fi
  ) >/tmp/fabric-unit.log 2>&1
  if /usr/bin/grep -q 'test result: ok' /tmp/fabric-unit.log; then
    pass "cargo test -p fluxvm-core -p fluxvm-network"
  else
    fail "cargo unit tests failed (see /tmp/fabric-unit.log)"
    tail -40 /tmp/fabric-unit.log >&2 || true
  fi
else
  fail "cargo not available"
fi

# ---------------------------------------------------------------------------
section "Kernel TC / rate-limit / XDP smoke"
# ---------------------------------------------------------------------------
if [ -x "${PROJECT_DIR}/scripts/build-ebpf.sh" ]; then
  (
    cd "$PROJECT_DIR"
    ./scripts/build-ebpf.sh >/tmp/fabric-bpf-build.log 2>&1
  )
  install -D -m0644 "${PROJECT_DIR}/dist/bpf/fluxvm_tc.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
  install -D -m0644 "${PROJECT_DIR}/dist/bpf/fluxvm_xdp.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o
  pass "BPF objects built and installed"
fi
if "${PROJECT_DIR}/scripts/test-ebpf-smoke.sh" /usr/lib/fluxvm/bpf >/tmp/fabric-smoke.log 2>&1; then
  pass "test-ebpf-smoke.sh (allow/deny/LPM/PPS/XDP)"
else
  fail "test-ebpf-smoke.sh failed"
  tail -30 /tmp/fabric-smoke.log >&2 || true
fi

# ---------------------------------------------------------------------------
section "Firecracker kernel + rootfs for FluxVm"
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$KERNEL")" "$(dirname "$ROOTFS")"
if [ ! -f "$KERNEL" ] || [ ! -f "$ROOTFS" ]; then
  if [ "$SKIP_DOWNLOAD" = "1" ]; then
    echo "missing kernel/rootfs and --skip-download set" >&2
    exit 2
  fi
  echo "  downloading Firecracker quickstart assets..."
  curl -fsSL "$KERNEL_URL" -o "${KERNEL}.tmp"
  mv "${KERNEL}.tmp" "$KERNEL"
  curl -fsSL "$ROOTFS_URL" -o "${ROOTFS}.tmp"
  mv "${ROOTFS}.tmp" "$ROOTFS"
fi
[ -f "$KERNEL" ] && [ -f "$ROOTFS" ] && pass "kernel=$(basename "$KERNEL") rootfs=$(basename "$ROOTFS")" \
  || fail "kernel/rootfs missing"

# ---------------------------------------------------------------------------
section "Enable dataplane mode=ebpf (temp config + service restart)"
# ---------------------------------------------------------------------------
cp "$CONFIG" "$CFG_BACKUP"
python3 - "$CONFIG" "$CFG_TEST" "$KERNEL" <<'PY'
import sys, tomllib, pathlib
src, dst, kernel = sys.argv[1], sys.argv[2], sys.argv[3]
data = tomllib.loads(pathlib.Path(src).read_text())
data["fluxvm_kernel"] = kernel
data["firecracker_kernel"] = kernel
sandbox = data.setdefault("sandbox", {})
dp = sandbox.setdefault("dataplane", {})
dp.update({
    "mode": "ebpf",
    "bpf_object": "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o",
    "pin_root": "/sys/fs/bpf/fluxvm",
    "required": True,
    "default_allow": True,
    "allow_cidrs": [],
    "allow_ports": [],
    "sample_rate": 0,
})
# tomllib is read-only; emit TOML manually for the fields we care about.
base = pathlib.Path(src).read_text()
# Strip any prior dataplane / kernel assignments we will re-append.
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
for _ in $(seq 1 30); do
  if curl -sf -m 2 "${LISTEN}/v1/vms" >/dev/null; then
    break
  fi
  sleep 1
done
curl -sf -m 3 "${LISTEN}/v1/vms" >/dev/null && pass "API healthy with ebpf dataplane config" \
  || fail "API not healthy after restart"

# ---------------------------------------------------------------------------
section "Create FluxVm sandbox (tap + netns) — dataplane attach"
# ---------------------------------------------------------------------------
MAC="02:fc:fa:$(printf '%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
cat > "${TMP}/vm.json" <<JSON
{
  "name": "fluxvm-fabric-e2e",
  "backend": "flux-vm",
  "image": "${ROOTFS}",
  "kernel": "${KERNEL}",
  "vcpus": 1,
  "memory_mib": 256,
  "network": {"mode": "tap", "netns": true, "mac": "${MAC}"},
  "ttl_seconds": 300,
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
  fail "FluxVm create failed: body=$(printf '%s' "$CREATE_OUT" | head -c 500) err=$(head -c 500 "${TMP}/create.err" 2>/dev/null || true)"
  echo ""; echo "=== Summary ==="; echo "  pass: ${PASS}  fail: ${FAIL}"
  exit 1
fi
SIMPLE=$(python3 -c "import uuid; print(uuid.UUID('$ID').hex)")
pass "created FluxVm id=${ID}"

# Host veth name for namespaced TAP.
IFACE="vh${SIMPLE:0:8}"
# Wait briefly for TC attach.
ATTACHED=0
for _ in $(seq 1 20); do
  if tc filter show dev "$IFACE" ingress 2>/dev/null | grep -q fluxvm_egress; then
    ATTACHED=1
    break
  fi
  # Interface may appear slightly after create returns.
  if ip link show "$IFACE" >/dev/null 2>&1; then
    if tc filter show dev "$IFACE" ingress 2>/dev/null | grep -q bpf; then
      ATTACHED=1
      break
    fi
  fi
  sleep 0.5
done
if [ "$ATTACHED" = "1" ]; then
  pass "TC filter attached on ${IFACE}"
else
  # Status API may still report pin/iface even if tc show raced.
  STATUS=$(api GET "/v1/vms/${ID}/network/status" || echo '{}')
  echo "$STATUS" | python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("attached") else 1)' \
    && pass "network/status.attached=true (iface=$(echo "$STATUS" | json_get interface))" \
    || fail "TC dataplane not attached on ${IFACE}; status=${STATUS}"
fi

PIN_DIR="/sys/fs/bpf/fluxvm/vms/${SIMPLE}"
META="/run/fluxvm/ebpf/vms/${SIMPLE}/iface"
[ -d "$PIN_DIR/maps" ] && pass "BPF pins under ${PIN_DIR}" || fail "missing pin dir ${PIN_DIR}"
[ -f "$META" ] && pass "iface meta $(cat "$META")" || fail "missing iface meta ${META}"

# ---------------------------------------------------------------------------
section "REST status / policy / stats / flows"
# ---------------------------------------------------------------------------
STATUS=$(api GET "/v1/vms/${ID}/network/status")
echo "$STATUS" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d.get("mode")=="ebpf"; assert d.get("identity"); assert d.get("schema_compatible") is True; assert d.get("schema_version")==3; print("ok")' >/dev/null \
  && pass "GET network/status mode=ebpf schema_v3" \
  || fail "GET network/status unexpected: $STATUS"

POLICY=$(api GET "/v1/vms/${ID}/network/policy")
echo "$POLICY" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert "default_allow" in d; print("ok")' >/dev/null \
  && pass "GET network/policy" \
  || fail "GET network/policy failed: $POLICY"

STATS=$(api GET "/v1/vms/${ID}/network/stats" || echo '{}')
echo "$STATS" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert "allowed_packets" in d or "dropped_packets" in d; print("ok")' >/dev/null \
  && pass "GET network/stats" \
  || fail "GET network/stats failed: $STATS"

FLOWS=$(api GET "/v1/vms/${ID}/network/flows?limit=10" || echo '{}')
echo "$FLOWS" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert "items" in d; print("ok")' >/dev/null \
  && pass "GET network/flows" \
  || fail "GET network/flows failed: $FLOWS"

# ---------------------------------------------------------------------------
section "Live policy reconfigure (deny-all + rate limits)"
# ---------------------------------------------------------------------------
POST_BODY='{"default_allow":false,"allow_cidrs":[],"allow_ports":[],"max_egress_pps":1000,"max_egress_mbps":50,"sample_rate":10}'
POST_OUT=$(api POST "/v1/vms/${ID}/network/policy" --data "$POST_BODY")
echo "$POST_OUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d.get("default_allow") is False; assert d.get("max_egress_pps")==1000; assert d.get("max_egress_mbps")==50; print("ok")' >/dev/null \
  && pass "POST network/policy (deny + Mbps/PPS)" \
  || fail "POST network/policy failed: $POST_OUT"

# Filter must still be attached after in-place reconfigure.
if tc filter show dev "$IFACE" ingress 2>/dev/null | grep -q bpf \
  || api GET "/v1/vms/${ID}/network/status" | python3 -c 'import json,sys;sys.exit(0 if json.load(sys.stdin).get("attached") else 1)'; then
  pass "TC still attached after live reconfigure"
else
  fail "TC detached during reconfigure"
fi

# Rate map should exist after policy with limits.
if bpftool map show pinned "${PIN_DIR}/maps/fluxvm_rate" >/dev/null 2>&1; then
  pass "fluxvm_rate map present after rate-limit policy"
else
  fail "fluxvm_rate map missing"
fi

# Restore permissive policy for cleanup traffic.
api POST "/v1/vms/${ID}/network/policy" --data '{"default_allow":true,"allow_cidrs":[],"allow_ports":[],"sample_rate":0}' >/dev/null \
  && pass "POST network/policy restore permissive" \
  || fail "failed to restore permissive policy"

# ---------------------------------------------------------------------------
section "Teardown cleans pins + TC"
# ---------------------------------------------------------------------------
api DELETE "/v1/vms/${ID}" >/dev/null 2>&1 \
  || "$EPH" --config "$CFG_TEST" delete "$ID" >/dev/null
ID=""
sleep 1
if [ -d "$PIN_DIR" ]; then
  fail "pin dir still present after delete: ${PIN_DIR}"
else
  pass "pin dir removed"
fi
if [ -f "$META" ]; then
  fail "iface meta still present: ${META}"
else
  pass "iface meta removed"
fi
if ip link show "$IFACE" >/dev/null 2>&1 && tc filter show dev "$IFACE" ingress 2>/dev/null | grep -q bpf; then
  fail "TC filter still on ${IFACE}"
else
  pass "host veth/TC cleaned up"
fi

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
echo "  pass: ${PASS}  fail: ${FAIL}"
[ "$FAIL" -eq 0 ]
