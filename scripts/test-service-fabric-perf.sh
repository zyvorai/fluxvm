#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Service Fabric performance / qualification lab (black-box).
# Measures VIP RTT p50/p99, optional PPS sample, host-routing counters,
# EDT presence, and HA delta lag when a peer is configured.
#
# Env:
#   FLUXVM_URL=http://127.0.0.1:7788
#   TOKEN=...                 # optional bearer
#   VIP=10.96.0.10
#   VIP_PORT=80
#   SAMPLES=50
#   FABRIC_URL=              # optional; enables HA lag probe
#   FABRIC_TOKEN=
#   SERVICE=payments
#
# Optional SLO gates (fail the script when set and violated):
#   SLO_VIP_P99_MS=5          require VIP connect p99 ≤ N ms (needs VIP=)
#   SLO_PRESSURE_IDLE=1       pressure action must not be hard_reload
#   SLO_REQUIRE_CHANNELS=1    when north_south_interfaces present, require
#                             combined_channels or rx_channels in status
#   SLO_CI_SHAPE=1            assert status program_generation + pressure JSON
#                             shape even when VIP is unset (CI-friendly)
set -euo pipefail

FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
SAMPLES="${SAMPLES:-50}"
VIP="${VIP:-}"
VIP_PORT="${VIP_PORT:-80}"
SERVICE="${SERVICE:-}"

auth=()
if [[ -n "${TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer $TOKEN")
fi

STATUS_JSON="$(mktemp)"
PRESSURE_JSON="$(mktemp)"
trap 'rm -f "$STATUS_JSON" "$PRESSURE_JSON"' EXIT

echo "== Service Fabric status =="
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/status" | tee "$STATUS_JSON" | python3 -m json.tool

echo "== Pressure reconcile =="
curl -sf -X POST "${auth[@]}" "$FLUXVM_URL/v1/network/services/pressure/reconcile" \
  | tee "$PRESSURE_JSON" | python3 -m json.tool || true

VIP_P99=""
if [[ -z "$VIP" ]]; then
  echo "Set VIP=... to run latency samples (skipped)."
else
  echo "== VIP RTT samples ($SAMPLES) via curl --connect-timeout =="
  VIP_P99="$(
  VIP="$VIP" VIP_PORT="$VIP_PORT" SAMPLES="$SAMPLES" python3 - <<'PY'
import os, subprocess, sys, time
vip=os.environ["VIP"]
port=int(os.environ.get("VIP_PORT","80"))
n=int(os.environ.get("SAMPLES","50"))
samples=[]
for i in range(n):
    t0=time.perf_counter()
    # TCP connect timing only (no HTTP required)
    r=subprocess.run(["bash","-lc", f"echo >/dev/tcp/{vip}/{port}"], capture_output=True)
    dt=(time.perf_counter()-t0)*1000
    if r.returncode==0:
        samples.append(dt)
samples.sort()
if not samples:
    print("FAIL: no successful connects", file=sys.stderr)
    raise SystemExit(2)
def pct(p):
    idx=min(len(samples)-1, int(round((p/100)*(len(samples)-1))))
    return samples[idx]
p99=pct(99)
print(f"ok={len(samples)}/{n} p50_ms={pct(50):.3f} p99_ms={p99:.3f} max_ms={samples[-1]:.3f}", file=sys.stderr)
print(f"{p99:.6f}")
PY
  )"
fi

echo "== Stats snapshot =="
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/stats" | python3 -m json.tool | head -80

if [[ -n "${FABRIC_URL:-}" && -n "${SERVICE}" ]]; then
  echo "== HA delta lag probe =="
  fauth=(-H "Authorization: Bearer ${FABRIC_TOKEN:-$TOKEN}")
  before=$(date +%s%3N)
  curl -sk "${fauth[@]}" "$FABRIC_URL/api/dataplane/services/$SERVICE/conntrack/delta?after_seq=0" >/tmp/sf-delta.json || true
  after=$(date +%s%3N)
  echo "delta_fetch_ms=$((after-before))"
  python3 - <<'PY'
import json
try:
  d=json.load(open("/tmp/sf-delta.json"))
  print("delta_keys", list(d)[:12] if isinstance(d, dict) else type(d))
except Exception as e:
  print("delta parse:", e)
PY
fi

echo "== SLO / CI shape gates =="
STATUS_JSON="$STATUS_JSON" PRESSURE_JSON="$PRESSURE_JSON" \
VIP_P99="${VIP_P99:-}" SLO_VIP_P99_MS="${SLO_VIP_P99_MS:-}" \
SLO_PRESSURE_IDLE="${SLO_PRESSURE_IDLE:-}" \
SLO_REQUIRE_CHANNELS="${SLO_REQUIRE_CHANNELS:-}" \
SLO_CI_SHAPE="${SLO_CI_SHAPE:-}" \
python3 - <<'PY'
import json, os, sys

status_path = os.environ["STATUS_JSON"]
pressure_path = os.environ["PRESSURE_JSON"]
fail = []

try:
    status = json.load(open(status_path))
except Exception as e:
    print(f"FAIL: status JSON: {e}")
    sys.exit(2)

pressure = None
try:
    pressure = json.load(open(pressure_path))
except Exception:
    pressure = None

ci = os.environ.get("SLO_CI_SHAPE", "").strip() in ("1", "true", "yes")
if ci:
    gen = status.get("program_generation")
    if not isinstance(gen, int) or gen < 1:
        fail.append(f"status.program_generation missing/invalid: {gen!r}")
    if not isinstance(status.get("map_tier"), str):
        fail.append("status.map_tier missing")
    if pressure is None:
        fail.append("pressure reconcile JSON missing (required for SLO_CI_SHAPE)")
    else:
        for key in ("action", "pressure_percent", "map_tier", "program_generation", "gc"):
            if key not in pressure:
                fail.append(f"pressure missing key {key}")
        if "gc" in pressure and not isinstance(pressure["gc"], dict):
            fail.append("pressure.gc must be object")

if os.environ.get("SLO_PRESSURE_IDLE", "").strip() in ("1", "true", "yes"):
    if pressure is None:
        fail.append("SLO_PRESSURE_IDLE set but pressure JSON unavailable")
    else:
        action = pressure.get("action")
        if action == "hard_reload":
            fail.append(
                f"pressure action is hard_reload under idle gate "
                f"(pressure_percent={pressure.get('pressure_percent')})"
            )

if os.environ.get("SLO_REQUIRE_CHANNELS", "").strip() in ("1", "true", "yes"):
    ifaces = status.get("north_south_interfaces") or []
    interfaces = status.get("interfaces") or []
    if ifaces:
        ok = False
        for iface in interfaces:
            off = iface.get("offload") or {}
            if off.get("combined_channels") or off.get("rx_channels"):
                ok = True
                break
        if not ok:
            fail.append(
                "SLO_REQUIRE_CHANNELS: no combined_channels/rx_channels in "
                "status.interfaces[].offload (NS iface configured)"
            )

thr = os.environ.get("SLO_VIP_P99_MS", "").strip()
p99_raw = os.environ.get("VIP_P99", "").strip()
if thr:
    if not p99_raw:
        fail.append("SLO_VIP_P99_MS set but VIP samples skipped/unavailable (set VIP=)")
    else:
        try:
            p99 = float(p99_raw)
            limit = float(thr)
            if p99 > limit:
                fail.append(f"VIP p99 {p99:.3f}ms > SLO_VIP_P99_MS {limit}")
            else:
                print(f"VIP p99 OK: {p99:.3f}ms <= {limit}ms")
        except ValueError:
            fail.append(f"bad VIP_P99/SLO_VIP_P99_MS: {p99_raw!r} / {thr!r}")

if fail:
    for f in fail:
        print(f"FAIL: {f}")
    sys.exit(2)
print("SLO gates: PASS")
PY

echo "PASS: service fabric perf lab completed (see numbers above)"
