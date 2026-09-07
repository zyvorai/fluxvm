#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Post-deploy regression gate for FluxVM on a lab host (does not replace
# full e2e matrix). Checks prior production paths still work after new merges.
#
#   ./scripts/test-lab-regression.sh
#   sudo -E ./scripts/test-lab-regression.sh   # for boot + ebpf smokes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_DIR"

API="${FLUXVM_API:-http://127.0.0.1:7788}"
KERN="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
IMG="${IMAGE:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
CFG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
BIN="${FLUXVM_BIN:-$(command -v fluxvm || echo /usr/local/bin/fluxvm)}"

PASS=0
FAIL=0
SKIP=0
ok() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
skip() { SKIP=$((SKIP + 1)); echo "  [SKIP] $1"; }
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

section "1) readyz + auth"
RZ=$(curl -sf "${AUTH[@]}" "$API/readyz")
echo "$RZ" | grep -q '"ok":true' && ok "readyz ok" || bad "readyz"
C401=$(curl -sS -o /dev/null -w "%{http_code}" \
  -H "X-Client-Cert-CN: x" -H "X-Client-Cert-Role: admin" \
  "$API/v1/network/endpoints" || echo 000)
[[ "$C401" == "401" ]] && ok "HTTP ignores cert headers" || bad "cert-header leak=$C401"
if grep -qE '^[[:space:]]*fluxvm_engine[[:space:]]*=[[:space:]]*"kvm"' "$CFG" 2>/dev/null; then
  bad "fluxvm_engine forced to kvm (lab prod density should stay firecracker)"
else
  ok "engine not forced kvm"
fi

section "2) KVM linux boot smoke"
if [[ "$(id -u)" -eq 0 ]]; then
  chmod +x scripts/test-kvm-linux-boot-smoke.sh
  if TIMEOUT_SECS="${TIMEOUT_SECS:-35}" \
    FLUXVM_HYPERVISOR="${FLUXVM_HYPERVISOR:-/usr/local/bin/fluxvm-hypervisor}" \
    ./scripts/test-kvm-linux-boot-smoke.sh 2>&1 | tee /tmp/fluxvm-boot-smoke.out | tail -20; then
    if grep -qE 'fail: 0|FAIL=0' /tmp/fluxvm-boot-smoke.out || grep -qi 'stdin round-trip\|USERSPACE_OK' /tmp/fluxvm-boot-smoke.out; then
      ok "kvm linux boot smoke"
    else
      bad "kvm boot smoke unclear"
    fi
  else
    bad "kvm boot smoke"
  fi
else
  skip "kvm boot smoke (needs root)"
fi

section "3) flux-vm sandbox create/delete"
SB=$(curl -sS --max-time 90 "${AUTH[@]}" -H "Content-Type: application/json" -X POST "$API/v1/sandboxes" \
  -d "{\"name\":\"lab-reg-sb\",\"spec\":{\"name\":\"b\",\"backend\":\"flux-vm\",\"image\":\"$IMG\",\"kernel\":\"$KERN\",\"vcpus\":1,\"memory_mib\":512,\"network\":{\"mode\":\"none\"}}}")
SID=$(echo "$SB" | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("id",""))
except: print("")')
if [[ -n "$SID" ]]; then
  ok "flux-vm sandbox create"
  curl -sf "${AUTH[@]}" -X DELETE "$API/v1/vms/$SID" >/dev/null && ok "sandbox delete" || bad "sandbox delete"
else
  bad "sandbox create: $(echo "$SB" | head -c 200)"
fi

section "4) eBPF smoke"
OBJ=""
for cand in \
  "${EBPF_OBJ_DIR:-}" \
  "$PROJECT_DIR/dist/bpf" \
  /usr/lib/fluxvm/bpf; do
  [[ -n "$cand" && -f "$cand/fluxvm_tc.bpf.o" && -f "$cand/fluxvm_xdp.bpf.o" ]] || continue
  OBJ="$cand"
  break
done
if [[ -z "$OBJ" ]]; then
  if [[ -x scripts/build-ebpf.sh ]]; then
    ./scripts/build-ebpf.sh && OBJ="$PROJECT_DIR/dist/bpf"
  fi
fi
if [[ "$(id -u)" -ne 0 ]]; then
  skip "ebpf smoke (needs root)"
elif [[ -z "$OBJ" ]]; then
  skip "ebpf objs missing (dist/bpf or /usr/lib/fluxvm/bpf)"
else
  chmod +x scripts/test-ebpf-smoke.sh
  if timeout 180 ./scripts/test-ebpf-smoke.sh "$OBJ" 2>&1 | tee /tmp/fluxvm-ebpf-smoke.out | tail -15; then
    grep -qi 'passed' /tmp/fluxvm-ebpf-smoke.out && ok "ebpf smoke ($OBJ)" || bad "ebpf smoke"
  else
    bad "ebpf smoke"
    tail -20 /tmp/fluxvm-ebpf-smoke.out || true
  fi
fi

echo
echo "lab-regression PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit $((FAIL > 0 ? 1 : 0))
