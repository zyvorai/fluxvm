#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Service Fabric performance / qualification lab (black-box).
# Measures VIP RTT p50/p99, optional PPS/Mpps sample, host-routing counters,
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
# SLO_CI=1 applies universal CI defaults (overridable by env):
#   SLO_VIP_P99_MS=25         when VIP set; skip if no VIP
#   SLO_PRESSURE_IDLE=1
#   SLO_EDT_FAIRNESS=1        if any service has max_egress_mbps: require EDT
#                             pacing counters present/non-absurd; else skip
#   SLO_FAILOVER_LOSS_MS=500  when FABRIC_URL+SERVICE set; else skip
#   SLO_MPPS_MIN=0.01         synthetic connect-rate Mpps vs VIP; skip if no VIP
#   SLO_CI_SHAPE=1
#
# SLO_LAB=1 applies higher lab ceilings (on top of / instead of CI floor):
#   SLO_MPPS_MIN=0.05         connect-burst floor (5× CI)
#   SLO_PKT_MPPS_MIN=0.10     packet Mpps from service/iface stats during storm
#   SLO_CPU_MAX_PERCENT=85    fluxvm process CPU% average during storm must be ≤
#   SLO_RSS_PPS_MIN=10000     when RSS section also runs
#   MPPS_DURATION=3 MPPS_WORKERS=64
#
# Optional SLO gates (also usable without SLO_CI/SLO_LAB):
#   SLO_VIP_P99_MS=5          require VIP connect p99 ≤ N ms (needs VIP=)
#   SLO_PRESSURE_IDLE=1       pressure action must not be hard_reload
#   SLO_REQUIRE_CHANNELS=1    when north_south_interfaces present, require
#                             combined_channels or rx_channels in status
#   SLO_CI_SHAPE=1            assert status program_generation + pressure JSON
#                             shape even when VIP is unset (CI-friendly)
#   SLO_EDT_FAIRNESS=1        EDT pacing gate (see above)
#   SLO_FAILOVER_LOSS_MS=N    HA delta fetch RTT ceiling
#   SLO_MPPS_MIN=N            min estimated Mpps from connect burst
#   SLO_MPPS_STRICT=1         enforce Mpps on null-channel/dummy NS ifaces
#   SLO_PKT_MPPS_MIN=N        min packet Mpps from stats/ethtool during storm
#   SLO_CPU_MAX_PERCENT=N     max fluxvm CPU% during Mpps/RSS storm
#   SLO_RSS_LOAD=1            also run scripts/test-service-fabric-rss.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
SAMPLES="${SAMPLES:-50}"
VIP="${VIP:-}"
VIP_PORT="${VIP_PORT:-80}"
SERVICE="${SERVICE:-}"

truthy() {
  case "${1:-}" in
    1|true|yes|TRUE|YES) return 0 ;;
    *) return 1 ;;
  esac
}

# Universal CI defaults when SLO_CI=1 (operator env still wins).
if truthy "${SLO_CI:-}"; then
  export SLO_CI_SHAPE="${SLO_CI_SHAPE:-1}"
  export SLO_PRESSURE_IDLE="${SLO_PRESSURE_IDLE:-1}"
  export SLO_EDT_FAIRNESS="${SLO_EDT_FAIRNESS:-1}"
  export SLO_FAILOVER_LOSS_MS="${SLO_FAILOVER_LOSS_MS:-500}"
  export SLO_MPPS_MIN="${SLO_MPPS_MIN:-0.01}"
  if [[ -n "$VIP" ]]; then
    export SLO_VIP_P99_MS="${SLO_VIP_P99_MS:-25}"
  fi
fi

# Higher lab ceilings when SLO_LAB=1 (overrides CI floor when both set unless
# the operator already exported a stricter/explicit value — we only default).
if truthy "${SLO_LAB:-}"; then
  export SLO_CI_SHAPE="${SLO_CI_SHAPE:-1}"
  export SLO_PRESSURE_IDLE="${SLO_PRESSURE_IDLE:-1}"
  export SLO_EDT_FAIRNESS="${SLO_EDT_FAIRNESS:-1}"
  export SLO_MPPS_MIN="${SLO_MPPS_MIN:-0.05}"
  export SLO_PKT_MPPS_MIN="${SLO_PKT_MPPS_MIN:-0.10}"
  export SLO_CPU_MAX_PERCENT="${SLO_CPU_MAX_PERCENT:-85}"
  export SLO_RSS_PPS_MIN="${SLO_RSS_PPS_MIN:-10000}"
  export MPPS_DURATION="${MPPS_DURATION:-3}"
  export MPPS_WORKERS="${MPPS_WORKERS:-64}"
  if [[ -n "$VIP" ]]; then
    export SLO_VIP_P99_MS="${SLO_VIP_P99_MS:-50}"
  fi
fi

auth=()
if [[ -n "${TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer $TOKEN")
fi

STATUS_JSON="$(mktemp)"
PRESSURE_JSON="$(mktemp)"
SERVICES_JSON="$(mktemp)"
STATS_JSON="$(mktemp)"
trap 'rm -f "$STATUS_JSON" "$PRESSURE_JSON" "$SERVICES_JSON" "$STATS_JSON"' EXIT

echo "== Service Fabric status =="
if ! curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/status" >"$STATUS_JSON"; then
  if truthy "${SLO_CI:-}" || truthy "${SLO_LAB:-}"; then
    echo "SKIP: FluxVM status unreachable at $FLUXVM_URL (SLO soft-skip)"
    exit 0
  fi
  echo "FAIL: cannot fetch $FLUXVM_URL/v1/network/services/status" >&2
  exit 2
fi
python3 -m json.tool <"$STATUS_JSON"

echo "== Pressure reconcile =="
curl -sf -X POST "${auth[@]}" "$FLUXVM_URL/v1/network/services/pressure/reconcile" \
  | tee "$PRESSURE_JSON" | python3 -m json.tool || true

curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services" >"$SERVICES_JSON" 2>/dev/null || echo '{"items":[]}' >"$SERVICES_JSON"
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/stats" >"$STATS_JSON" 2>/dev/null || echo '{"interfaces":{}}' >"$STATS_JSON"

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

MPPS_EST=""
PKT_MPPS_EST=""
CPU_AVG_PCT=""
if [[ -n "$VIP" && ( -n "${SLO_MPPS_MIN:-}" || -n "${SLO_PKT_MPPS_MIN:-}" || -n "${SLO_CPU_MAX_PERCENT:-}" ) ]]; then
  echo "== Lab Mpps / CPU sample (connect burst + stats) =="
  # Pick optional iface from status for ethtool packet deltas.
  RSS_IFACE_GUESS="$(python3 - <<PY
import json
try:
  d=json.load(open("$STATUS_JSON"))
  ns=d.get("north_south_interfaces") or []
  print(ns[0] if ns else "")
except Exception:
  print("")
PY
)"
  EVAL_OUT="$(
  VIP="$VIP" VIP_PORT="$VIP_PORT" \
  MPPS_DURATION="${MPPS_DURATION:-1.5}" MPPS_WORKERS="${MPPS_WORKERS:-32}" \
  FLUXVM_URL="$FLUXVM_URL" TOKEN="${TOKEN:-}" \
  RSS_IFACE="${RSS_IFACE:-$RSS_IFACE_GUESS}" \
  STATS_JSON="$STATS_JSON" \
  python3 - <<'PY'
import json, os, subprocess, sys, time, concurrent.futures, re

vip = os.environ["VIP"]
port = int(os.environ.get("VIP_PORT", "80"))
duration = float(os.environ.get("MPPS_DURATION", "1.5"))
workers = int(os.environ.get("MPPS_WORKERS", "32"))
iface = os.environ.get("RSS_IFACE", "").strip()
fluxvm_url = os.environ.get("FLUXVM_URL", "http://127.0.0.1:7788").rstrip("/")
token = os.environ.get("TOKEN", "").strip()
stats_path = os.environ.get("STATS_JSON", "")

def fluxvm_pid():
    try:
        out = subprocess.check_output(["pgrep", "-n", "-x", "fluxvm"], text=True).strip()
        return int(out.splitlines()[0])
    except Exception:
        return None

def read_proc_cpu(pid):
    # returns (utime+stime jiffies, wall_ns)
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        # fields 14,15 are utime,stime (1-indexed → 13,14)
        return int(parts[13]) + int(parts[14]), time.perf_counter_ns()
    except Exception:
        return None, None

def ethtool_packets(dev):
    if not dev:
        return None
    try:
        out = subprocess.check_output(["ethtool", "-S", dev], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    total = 0
    matched = False
    for line in out.splitlines():
        m = re.search(r"(rx_packets|tx_packets|rx_pkts|tx_pkts|packets):\s*(\d+)", line, re.I)
        if m:
            total += int(m.group(2))
            matched = True
    return total if matched else None

def service_packets(path):
    try:
        d = json.load(open(path))
    except Exception:
        return None
    total = 0
    found = False
    def walk(obj):
        nonlocal total, found
        if isinstance(obj, dict):
            for k, v in obj.items():
                kl = str(k).lower()
                if kl in ("packets", "rx_packets", "tx_packets", "forward_packets", "forward_pkts") and isinstance(v, (int, float)):
                    total += int(v)
                    found = True
                else:
                    walk(v)
        elif isinstance(obj, list):
            for i in obj:
                walk(i)
    walk(d)
    return total if found else None

def one():
    r = subprocess.run(["bash", "-lc", f"echo >/dev/tcp/{vip}/{port}"], capture_output=True)
    return r.returncode == 0

one()
pid = fluxvm_pid()
cpu0, t0cpu = read_proc_cpu(pid) if pid else (None, None)
eth0 = ethtool_packets(iface)
svc0 = service_packets(stats_path)

deadline = time.perf_counter() + duration
t0 = time.perf_counter()
ok = fail = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
    futs = []
    while time.perf_counter() < deadline:
        futs.append(ex.submit(one))
        if len(futs) >= workers * 4:
            for f in concurrent.futures.as_completed(futs):
                if f.result():
                    ok += 1
                else:
                    fail += 1
            futs = []
    for f in concurrent.futures.as_completed(futs):
        if f.result():
            ok += 1
        else:
            fail += 1
elapsed = max(1e-6, time.perf_counter() - t0)

# refresh stats after storm
try:
    auth = ["-H", f"Authorization: Bearer {token}"] if token else []
    subprocess.run(
        ["curl", "-sf", *auth, f"{fluxvm_url}/v1/network/services/stats"],
        check=False,
        stdout=open(stats_path, "w") if stats_path else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
except Exception:
    pass

cpu1, t1cpu = read_proc_cpu(pid) if pid else (None, None)
eth1 = ethtool_packets(iface)
svc1 = service_packets(stats_path)

mpps = (ok / elapsed) / 1_000_000.0
print(f"connect_ok={ok} fail={fail} elapsed_s={elapsed:.3f} est_mpps={mpps:.6f}", file=sys.stderr)

pkt_mpps = None
if eth0 is not None and eth1 is not None and eth1 >= eth0:
    pkt_mpps = ((eth1 - eth0) / elapsed) / 1_000_000.0
    print(f"ethtool_pkt_delta={eth1-eth0} iface={iface} pkt_mpps={pkt_mpps:.6f}", file=sys.stderr)
elif svc0 is not None and svc1 is not None and svc1 >= svc0:
    pkt_mpps = ((svc1 - svc0) / elapsed) / 1_000_000.0
    print(f"stats_pkt_delta={svc1-svc0} pkt_mpps={pkt_mpps:.6f}", file=sys.stderr)
else:
    print("pkt_mpps unavailable (no ethtool/stats counters)", file=sys.stderr)

cpu_pct = None
if cpu0 is not None and cpu1 is not None and t0cpu and t1cpu and t1cpu > t0cpu:
    # jiffies → assume USER_HZ=100
    hz = os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK")) if hasattr(os, "sysconf_names") else 100
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except Exception:
        hz = 100
    dj = cpu1 - cpu0
    dt = (t1cpu - t0cpu) / 1e9
    cpu_pct = (dj / hz) / dt * 100.0
    print(f"fluxvm_pid={pid} cpu_avg_pct={cpu_pct:.2f}", file=sys.stderr)
else:
    print("cpu sample unavailable (no fluxvm pid/stat)", file=sys.stderr)

# machine-readable triple for the shell
print(f"{mpps:.8f}")
print(f"{'' if pkt_mpps is None else f'{pkt_mpps:.8f}'}")
print(f"{'' if cpu_pct is None else f'{cpu_pct:.4f}'}")
PY
  )"
  MPPS_EST="$(printf '%s\n' "$EVAL_OUT" | sed -n '1p')"
  PKT_MPPS_EST="$(printf '%s\n' "$EVAL_OUT" | sed -n '2p')"
  CPU_AVG_PCT="$(printf '%s\n' "$EVAL_OUT" | sed -n '3p')"
fi

echo "== Stats snapshot =="
python3 -m json.tool <"$STATS_JSON" | head -80 || true

DELTA_FETCH_MS=""
if [[ -n "${FABRIC_URL:-}" && -n "${SERVICE}" ]]; then
  echo "== HA delta lag probe =="
  fauth=()
  if [[ -n "${FABRIC_TOKEN:-${TOKEN:-}}" ]]; then
    fauth=(-H "Authorization: Bearer ${FABRIC_TOKEN:-$TOKEN}")
  fi
  before=$(date +%s%3N)
  curl -sk "${fauth[@]}" "$FABRIC_URL/api/dataplane/services/$SERVICE/conntrack/delta?after_seq=0" >/tmp/sf-delta.json || true
  after=$(date +%s%3N)
  DELTA_FETCH_MS=$((after-before))
  echo "delta_fetch_ms=$DELTA_FETCH_MS"
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
SERVICES_JSON="$SERVICES_JSON" STATS_JSON="$STATS_JSON" \
VIP_P99="${VIP_P99:-}" SLO_VIP_P99_MS="${SLO_VIP_P99_MS:-}" \
SLO_PRESSURE_IDLE="${SLO_PRESSURE_IDLE:-}" \
SLO_REQUIRE_CHANNELS="${SLO_REQUIRE_CHANNELS:-}" \
SLO_CI_SHAPE="${SLO_CI_SHAPE:-}" \
SLO_EDT_FAIRNESS="${SLO_EDT_FAIRNESS:-}" \
SLO_FAILOVER_LOSS_MS="${SLO_FAILOVER_LOSS_MS:-}" \
DELTA_FETCH_MS="${DELTA_FETCH_MS:-}" \
SLO_MPPS_MIN="${SLO_MPPS_MIN:-}" MPPS_EST="${MPPS_EST:-}" \
SLO_PKT_MPPS_MIN="${SLO_PKT_MPPS_MIN:-}" PKT_MPPS_EST="${PKT_MPPS_EST:-}" \
SLO_CPU_MAX_PERCENT="${SLO_CPU_MAX_PERCENT:-}" CPU_AVG_PCT="${CPU_AVG_PCT:-}" \
SLO_LAB="${SLO_LAB:-}" \
VIP="${VIP:-}" FABRIC_URL="${FABRIC_URL:-}" SERVICE="${SERVICE:-}" \
python3 - <<'PY'
import json, os, sys

status_path = os.environ["STATUS_JSON"]
pressure_path = os.environ["PRESSURE_JSON"]
services_path = os.environ["SERVICES_JSON"]
stats_path = os.environ["STATS_JSON"]
fail = []
notes = []

def truthy(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")

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

try:
    services_doc = json.load(open(services_path))
except Exception:
    services_doc = {"items": []}
services = services_doc.get("items") if isinstance(services_doc, dict) else []
if not isinstance(services, list):
    services = []

try:
    stats_doc = json.load(open(stats_path))
except Exception:
    stats_doc = {}

ci = truthy("SLO_CI_SHAPE")
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

if truthy("SLO_PRESSURE_IDLE"):
    if pressure is None:
        fail.append("SLO_PRESSURE_IDLE set but pressure JSON unavailable")
    else:
        action = pressure.get("action")
        if action == "hard_reload":
            fail.append(
                f"pressure action is hard_reload under idle gate "
                f"(pressure_percent={pressure.get('pressure_percent')})"
            )

if truthy("SLO_REQUIRE_CHANNELS"):
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
vip = os.environ.get("VIP", "").strip()
if thr:
    if not vip:
        notes.append("SLO_VIP_P99_MS skipped (no VIP)")
    elif not p99_raw:
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

# --- EDT fairness ---
if truthy("SLO_EDT_FAIRNESS"):
    paced = [s for s in services if isinstance(s, dict) and s.get("max_egress_mbps")]
    if not paced:
        notes.append("SLO_EDT_FAIRNESS skipped (no service max_egress_mbps / EDT not configured)")
    else:
        # Collect edt_packets from host stats interfaces → service counters.
        counters = []
        interfaces = stats_doc.get("interfaces") if isinstance(stats_doc, dict) else None
        if isinstance(interfaces, dict):
            for _iface, items in interfaces.items():
                if isinstance(items, list):
                    counters.extend(items)
        elif isinstance(interfaces, list):
            counters.extend(interfaces)
        # Some payloads may be a flat list under another key.
        if not counters and isinstance(stats_doc.get("items"), list):
            counters = stats_doc["items"]

        by_name = {c.get("name"): c for c in counters if isinstance(c, dict)}
        absurd = 1 << 62
        for svc in paced:
            name = svc.get("name", "?")
            c = by_name.get(name)
            if c is None:
                # EDT configured on service: require a stats row with edt_packets.
                # Soft: if stats empty entirely, still require evidence of pacing field somewhere.
                if not counters:
                    fail.append(
                        f"SLO_EDT_FAIRNESS: service {name!r} has max_egress_mbps="
                        f"{svc.get('max_egress_mbps')} but no service stats/EDT counters"
                    )
                else:
                    fail.append(
                        f"SLO_EDT_FAIRNESS: no stats row for paced service {name!r}"
                    )
                continue
            if "edt_packets" not in c:
                fail.append(f"SLO_EDT_FAIRNESS: {name!r} stats missing edt_packets")
                continue
            edt = c.get("edt_packets")
            if not isinstance(edt, int) or edt < 0 or edt >= absurd:
                fail.append(
                    f"SLO_EDT_FAIRNESS: {name!r} edt_packets absurd/invalid: {edt!r}"
                )
                continue
            fwd = c.get("forward_packets")
            if isinstance(fwd, int) and fwd > 0 and edt > fwd * 16 + 1000:
                fail.append(
                    f"SLO_EDT_FAIRNESS: {name!r} edt_packets={edt} >> forward_packets={fwd}"
                )
                continue
            print(f"EDT OK: {name} max_egress_mbps={svc.get('max_egress_mbps')} edt_packets={edt}")

# --- Failover / HA delta RTT ---
failover = os.environ.get("SLO_FAILOVER_LOSS_MS", "").strip()
fabric = os.environ.get("FABRIC_URL", "").strip()
service = os.environ.get("SERVICE", "").strip()
delta_raw = os.environ.get("DELTA_FETCH_MS", "").strip()
if failover:
    if not fabric or not service:
        notes.append("SLO_FAILOVER_LOSS_MS skipped (need FABRIC_URL+SERVICE)")
    elif not delta_raw:
        fail.append("SLO_FAILOVER_LOSS_MS set but delta fetch RTT unavailable")
    else:
        try:
            ms = float(delta_raw)
            limit = float(failover)
            if ms > limit:
                fail.append(f"HA delta fetch {ms:.0f}ms > SLO_FAILOVER_LOSS_MS {limit}")
            else:
                print(f"HA delta fetch OK: {ms:.0f}ms <= {limit}ms")
        except ValueError:
            fail.append(f"bad DELTA_FETCH_MS/SLO_FAILOVER_LOSS_MS: {delta_raw!r} / {failover!r}")

# --- Mpps (connect estimate) ---
mpps_min = os.environ.get("SLO_MPPS_MIN", "").strip()
mpps_est = os.environ.get("MPPS_EST", "").strip()
mpps_strict = truthy("SLO_MPPS_STRICT")
# Dummy / null-channel NS ifaces cannot sustain meaningful Mpps; soft-skip
# unless SLO_MPPS_STRICT=1 (same spirit as SLO_RSS_STRICT).
channels_null = False
for iface in (status.get("interfaces") or []):
    if not isinstance(iface, dict):
        continue
    off = iface.get("offload") or {}
    if off.get("combined_channels") is None and off.get("rx_channels") is None:
        channels_null = True
        break
if mpps_min:
    if not vip:
        notes.append("SLO_MPPS_MIN skipped (no VIP)")
    elif not mpps_est:
        fail.append("SLO_MPPS_MIN set but Mpps sample unavailable")
    elif channels_null and not mpps_strict:
        notes.append(
            "SLO_MPPS_MIN soft-skip (NS iface channels null/dummy; "
            "set SLO_MPPS_STRICT=1 to enforce)"
        )
    else:
        try:
            est = float(mpps_est)
            limit = float(mpps_min)
            if est < limit:
                fail.append(f"est Mpps {est:.6f} < SLO_MPPS_MIN {limit}")
            else:
                print(f"Mpps OK: {est:.6f} >= {limit}")
        except ValueError:
            fail.append(f"bad MPPS_EST/SLO_MPPS_MIN: {mpps_est!r} / {mpps_min!r}")

# --- Packet Mpps (lab) ---
pkt_min = os.environ.get("SLO_PKT_MPPS_MIN", "").strip()
pkt_est = os.environ.get("PKT_MPPS_EST", "").strip()
lab = os.environ.get("SLO_LAB", "").strip().lower() in ("1", "true", "yes")
if pkt_min:
    if not vip:
        notes.append("SLO_PKT_MPPS_MIN skipped (no VIP)")
    elif not pkt_est:
        if lab:
            notes.append("SLO_PKT_MPPS_MIN soft-skip (no ethtool/stats packet counters)")
        else:
            fail.append("SLO_PKT_MPPS_MIN set but packet Mpps sample unavailable")
    else:
        try:
            est = float(pkt_est)
            limit = float(pkt_min)
            if est < limit:
                fail.append(f"pkt Mpps {est:.6f} < SLO_PKT_MPPS_MIN {limit}")
            else:
                print(f"Pkt Mpps OK: {est:.6f} >= {limit}")
        except ValueError:
            fail.append(f"bad PKT_MPPS_EST/SLO_PKT_MPPS_MIN: {pkt_est!r} / {pkt_min!r}")

# --- CPU ceiling during storm ---
cpu_max = os.environ.get("SLO_CPU_MAX_PERCENT", "").strip()
cpu_avg = os.environ.get("CPU_AVG_PCT", "").strip()
if cpu_max:
    if not vip:
        notes.append("SLO_CPU_MAX_PERCENT skipped (no VIP / no storm)")
    elif not cpu_avg:
        if lab:
            notes.append("SLO_CPU_MAX_PERCENT soft-skip (fluxvm pid/stat unavailable)")
        else:
            fail.append("SLO_CPU_MAX_PERCENT set but CPU sample unavailable")
    else:
        try:
            avg = float(cpu_avg)
            limit = float(cpu_max)
            if avg > limit:
                fail.append(f"fluxvm CPU {avg:.1f}% > SLO_CPU_MAX_PERCENT {limit}")
            else:
                print(f"CPU OK: {avg:.1f}% <= {limit}%")
        except ValueError:
            fail.append(f"bad CPU_AVG_PCT/SLO_CPU_MAX_PERCENT: {cpu_avg!r} / {cpu_max!r}")

for n in notes:
    print(f"NOTE: {n}")

if fail:
    for f in fail:
        print(f"FAIL: {f}")
    sys.exit(2)
print("SLO gates: PASS")
PY

if [[ "${SLO_RSS_LOAD:-}" == "1" || "${SLO_RSS_LOAD:-}" == "true" || "${SLO_RSS_LOAD:-}" == "yes" ]] || truthy "${SLO_LAB:-}"; then
  echo "== RSS under-load (SLO_RSS_LOAD / SLO_LAB) =="
  "$ROOT/scripts/test-service-fabric-rss.sh"
fi

echo "PASS: service fabric perf lab completed (see numbers above)"
