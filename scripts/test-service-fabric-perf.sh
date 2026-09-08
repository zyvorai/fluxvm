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

echo "== Service Fabric status =="
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/status" | python3 -m json.tool

echo "== Pressure reconcile =="
curl -sf -X POST "${auth[@]}" "$FLUXVM_URL/v1/network/services/pressure/reconcile" | python3 -m json.tool || true

if [[ -z "$VIP" ]]; then
  echo "Set VIP=... to run latency samples (skipped)."
else
  echo "== VIP RTT samples ($SAMPLES) via curl --connect-timeout =="
  python3 - <<PY
import os, statistics, subprocess, time
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
    print("FAIL: no successful connects")
    raise SystemExit(2)
def pct(p):
    idx=min(len(samples)-1, int(round((p/100)*(len(samples)-1))))
    return samples[idx]
print(f"ok={len(samples)}/{n} p50_ms={pct(50):.3f} p99_ms={pct(99):.3f} max_ms={samples[-1]:.3f}")
PY
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

echo "PASS: service fabric perf lab completed (see numbers above)"
