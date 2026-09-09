#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Production readiness gate for FluxVM (dataplane + Service Fabric).
# Read-only by default — asserts control plane, Network Fabric health,
# Service Fabric schema/pins, and optional VIP SLO when VIP= is set.
#
# Env:
#   FLUXVM_URL=http://127.0.0.1:7788
#   FABRIC_URL=…              optional; also probe Fabric health/readyz
#   TOKEN=…                   optional Bearer for FluxVM auth
#   FABRIC_TOKEN=…            optional for Fabric probes / SLO HA delta
#   SECTIONS=all|control,network_fabric,service_fabric,pressure,slo,affinity,dataplane_e2e
#   VIP= VIP_PORT= SERVICE=   optional SLO / affinity
#   RUN_HEAVY=1               enable dataplane_e2e (root VM spin; off by default)
#   EXPECT_SCHEMA=4
#   EXPECT_PROGRAM_GENERATION=8
#
# Exit: 0 PASS; 1 FAIL; 2 misconfig
#
#   FLUXVM_URL=http://127.0.0.1:7788 ./scripts/test-production-readiness.sh
#   VIP=10.96.0.10 VIP_PORT=80 ./scripts/test-production-readiness.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec </dev/null

FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
FABRIC_URL="${FABRIC_URL:-}"
SECTIONS_RAW="${SECTIONS:-all}"
EXPECT_SCHEMA="${EXPECT_SCHEMA:-4}"
EXPECT_GEN="${EXPECT_PROGRAM_GENERATION:-8}"
RUN_HEAVY="${RUN_HEAVY:-0}"
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT

PASS_N=0
FAIL_N=0
SKIP_N=0
declare -a SUMMARY=()

pass() { PASS_N=$((PASS_N + 1)); SUMMARY+=("PASS|$1|${2:-}"); echo "  [PASS] $1${2:+ — $2}"; }
fail() { FAIL_N=$((FAIL_N + 1)); SUMMARY+=("FAIL|$1|${2:-}"); echo "  [FAIL] $1${2:+ — $2}" >&2; }
skip() { SKIP_N=$((SKIP_N + 1)); SUMMARY+=("SKIP|$1|${2:-}"); echo "  [SKIP] $1${2:+ — $2}"; }

truthy() {
  case "${1:-}" in 1|true|yes|TRUE|YES) return 0 ;; *) return 1 ;; esac
}

want_section() {
  local name="$1"
  if [[ "$SECTIONS_RAW" == "all" ]]; then
    case "$name" in
      dataplane_e2e)
        truthy "$RUN_HEAVY" && return 0
        return 1
        ;;
      *) return 0 ;;
    esac
  fi
  [[ ",${SECTIONS_RAW}," == *",$name,"* ]]
}

auth=()
if [[ -n "${TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer $TOKEN")
fi

curl_code() {
  local url="$1"
  curl -sk -m 10 "${auth[@]}" -o "$BODY" -w '%{http_code}' "$url" 2>/dev/null || echo 000
}

echo "########## FluxVM production readiness ##########"
echo "  FLUXVM_URL=$FLUXVM_URL FABRIC_URL=${FABRIC_URL:-none}"
echo "  SECTIONS=$SECTIONS_RAW VIP=${VIP:-unset}"
echo ""

# ── control ─────────────────────────────────────────────────────────
if want_section control; then
  echo "=== control ==="
  hz="$(curl_code "$FLUXVM_URL/healthz")"
  rz="$(curl_code "$FLUXVM_URL/readyz")"
  ctrl_ok=1
  if [[ "$hz" != "200" ]]; then
    fail "control" "/healthz HTTP $hz"
    ctrl_ok=0
  elif [[ "$rz" != "200" ]]; then
    fail "control" "/readyz HTTP $rz"
    ctrl_ok=0
  else
    ok="$(BODY="$BODY" python3 - <<'PY'
import json, os
doc = json.load(open(os.environ["BODY"]))
print("1" if doc.get("ok") is True else "0")
PY
)"
    if [[ "$ok" != "1" ]]; then
      fail "control" "/readyz ok!=true"
      ctrl_ok=0
    fi
  fi
  if [[ "$ctrl_ok" -eq 1 ]]; then
    if [[ -n "$FABRIC_URL" ]]; then
      fh="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "$FABRIC_URL/health" || echo 000)"
      fr="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "$FABRIC_URL/readyz" || echo 000)"
      if [[ "$fh" == "200" && "$fr" == "200" ]]; then
        pass "control" "fluxvm+fabric health/readyz"
      else
        fail "control" "fabric health=$fh readyz=$fr"
      fi
    else
      pass "control" "fluxvm healthz+readyz"
    fi
  fi
fi

# ── network_fabric ──────────────────────────────────────────────────
if want_section network_fabric; then
  echo "=== network_fabric ==="
  code="$(curl_code "$FLUXVM_URL/v1/network/health")"
  if [[ "$code" != "200" ]]; then
    fail "network_fabric" "GET /v1/network/health HTTP $code"
  else
    set +e
    detail="$(BODY="$BODY" python3 - <<'PY'
import json, os, sys
doc = json.load(open(os.environ["BODY"]))
errs = []
if doc.get("ok") is not True:
    errs.append("ok=%r" % (doc.get("ok"),))
for k in ("bpf_object_present", "bpffs_present"):
    if k in doc and doc.get(k) is not True:
        errs.append("%s=%r" % (k, doc.get(k)))
if "pin_root_present" in doc and doc.get("pin_root_present") is not True:
    errs.append("pin_root_present=%r" % (doc.get("pin_root_present"),))
if errs:
    print("; ".join(errs))
    sys.exit(1)
print("mode=%s" % (doc.get("mode", ""),))
sys.exit(0)
PY
)"
    dc=$?
    set -e
    if [[ $dc -eq 0 ]]; then
      pass "network_fabric" "$detail"
    else
      fail "network_fabric" "$detail"
    fi
  fi
fi

# ── service_fabric ──────────────────────────────────────────────────
if want_section service_fabric; then
  echo "=== service_fabric ==="
  code="$(curl_code "$FLUXVM_URL/v1/network/services/status")"
  if [[ "$code" != "200" ]]; then
    fail "service_fabric" "GET /v1/network/services/status HTTP $code"
  else
    set +e
    detail="$(BODY="$BODY" EXPECT_SCHEMA="$EXPECT_SCHEMA" EXPECT_GEN="$EXPECT_GEN" python3 - <<'PY'
import json, os, sys
doc = json.load(open(os.environ["BODY"]))
want_s = int(os.environ["EXPECT_SCHEMA"])
want_g = int(os.environ["EXPECT_GEN"])
errs = []
sv = doc.get("schema_version")
pg = doc.get("program_generation")
mt = doc.get("map_tier")
if sv != want_s:
    errs.append("schema_version=%r want %s" % (sv, want_s))
if pg != want_g:
    errs.append("program_generation=%r want %s" % (pg, want_g))
if not isinstance(mt, str) or not mt:
    errs.append("map_tier=%r" % (mt,))
ns = doc.get("north_south_interfaces") or []
ifaces = doc.get("interfaces") or []
by = {row.get("interface"): row for row in ifaces if isinstance(row, dict)}
for name in ns:
    row = by.get(name) or {}
    if not row.get("tc_program_pinned"):
        errs.append("%s: tc_program_pinned=false" % name)
    if doc.get("xdp_acceleration") and row.get("xdp_requested") and not row.get("xdp_program_pinned"):
        errs.append("%s: xdp_program_pinned=false" % name)
if doc.get("cgroup_connect") and not doc.get("cgroup_connect_attached"):
    errs.append("cgroup_connect_attached=false")
if errs:
    print("; ".join(errs))
    sys.exit(1)
print("schema=%s gen=%s tier=%s ns=%s" % (sv, pg, mt, ns))
sys.exit(0)
PY
)"
    dc=$?
    set -e
    if [[ $dc -eq 0 ]]; then
      pass "service_fabric" "$detail"
    else
      fail "service_fabric" "$detail"
    fi
  fi
fi

# ── pressure ────────────────────────────────────────────────────────
if want_section pressure; then
  echo "=== pressure ==="
  code="$(curl -sk -m 10 "${auth[@]}" -X POST -o "$BODY" -w '%{http_code}' \
    "$FLUXVM_URL/v1/network/services/pressure/reconcile" 2>/dev/null || echo 000)"
  if [[ "$code" != "200" ]]; then
    fail "pressure" "POST pressure/reconcile HTTP $code"
  else
    set +e
    detail="$(BODY="$BODY" python3 - <<'PY'
import json, os, sys
doc = json.load(open(os.environ["BODY"]))
errs = []
for k in ("action", "pressure_percent", "map_tier", "program_generation", "gc"):
    if k not in doc:
        errs.append("missing %s" % k)
if not isinstance(doc.get("gc"), dict):
    errs.append("gc must be object")
if doc.get("action") == "hard_reload":
    errs.append("action=hard_reload under idle readiness")
if errs:
    print("; ".join(errs))
    sys.exit(1)
print("action=%s pressure=%s" % (doc.get("action"), doc.get("pressure_percent")))
sys.exit(0)
PY
)"
    dc=$?
    set -e
    if [[ $dc -eq 0 ]]; then
      pass "pressure" "$detail"
    else
      fail "pressure" "$detail"
    fi
  fi
fi

# ── slo (optional VIP) ──────────────────────────────────────────────
if want_section slo; then
  echo "=== slo ==="
  if [[ -z "${VIP:-}" ]]; then
    skip "slo" "set VIP= (and VIP_PORT=) for latency/Mpps gates"
  else
    chmod +x "$ROOT/scripts/test-service-fabric-slo.sh" 2>/dev/null || true
    set +e
    FLUXVM_URL="$FLUXVM_URL" TOKEN="${TOKEN:-}" \
      FABRIC_URL="${FABRIC_URL:-}" FABRIC_TOKEN="${FABRIC_TOKEN:-${TOKEN:-}}" \
      VIP="$VIP" VIP_PORT="${VIP_PORT:-80}" SERVICE="${SERVICE:-}" \
      SLO_CI=1 \
      "$ROOT/scripts/test-service-fabric-slo.sh" >/tmp/fluxvm-slo.out 2>&1
    dc=$?
    set -e
    if [[ $dc -eq 0 ]]; then
      pass "slo" "VIP=$VIP"
    else
      fail "slo" "test-service-fabric-slo exit $dc"
      tail -40 /tmp/fluxvm-slo.out >&2 || true
    fi
  fi
fi

# ── affinity ────────────────────────────────────────────────────────
if want_section affinity; then
  echo "=== affinity ==="
  if [[ -z "${VIP:-}" ]]; then
    skip "affinity" "set VIP= for multi-queue affinity proof"
  else
    chmod +x "$ROOT/scripts/test-service-fabric-rss-affinity.sh" 2>/dev/null || true
    set +e
    FLUXVM_URL="$FLUXVM_URL" TOKEN="${TOKEN:-}" \
      VIP="$VIP" VIP_PORT="${VIP_PORT:-80}" RSS_IFACE="${RSS_IFACE:-}" \
      SLO_CI=1 \
      "$ROOT/scripts/test-service-fabric-rss-affinity.sh" >/tmp/fluxvm-aff.out 2>&1
    dc=$?
    set -e
    if [[ $dc -eq 0 ]]; then
      if grep -q '^SKIP:' /tmp/fluxvm-aff.out 2>/dev/null; then
        skip "affinity" "$(grep '^SKIP:' /tmp/fluxvm-aff.out | tail -1 | sed 's/^SKIP: //')"
      else
        pass "affinity" "multi-queue proof"
      fi
    else
      fail "affinity" "exit $dc"
      tail -30 /tmp/fluxvm-aff.out >&2 || true
    fi
  fi
fi

# ── dataplane_e2e (heavy) ───────────────────────────────────────────
if want_section dataplane_e2e; then
  echo "=== dataplane_e2e (heavy) ==="
  chmod +x "$ROOT/scripts/test-production-dataplane-e2e.sh" 2>/dev/null || true
  set +e
  sudo -E "$ROOT/scripts/test-production-dataplane-e2e.sh" --skip-download >/tmp/fluxvm-dpe2e.out 2>&1
  dc=$?
  set -e
  if [[ $dc -eq 0 ]]; then
    pass "dataplane_e2e" "production dataplane e2e"
  else
    fail "dataplane_e2e" "exit $dc"
    tail -40 /tmp/fluxvm-dpe2e.out >&2 || true
  fi
elif [[ "$SECTIONS_RAW" == "all" ]]; then
  skip "dataplane_e2e" "read-only default (RUN_HEAVY=0)"
fi

echo ""
echo "########## Summary ##########"
for row in "${SUMMARY[@]}"; do
  IFS='|' read -r st name detail <<<"$row"
  printf '  %-4s  %-16s  %s\n' "$st" "$name" "$detail"
done
echo "pass=$PASS_N fail=$FAIL_N skip=$SKIP_N"

if [[ "$FAIL_N" -gt 0 ]]; then
  echo "########## FluxVM production readiness: FAIL ##########" >&2
  exit 1
fi
echo "########## FluxVM production readiness: PASS ##########"
exit 0
