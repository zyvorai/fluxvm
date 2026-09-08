#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Service Fabric RSS under-load PPS gate.
# Storms the VIP briefly, samples iface PPS (ethtool -S preferred), and
# optionally checks multi-queue RX activity.
#
# Env:
#   FLUXVM_URL=http://127.0.0.1:7788
#   TOKEN=...
#   VIP= / VIP_PORT=80
#   RSS_IFACE=                override NS iface (else from status)
#   SLO_RSS_PPS_MIN=1000      lab default; fail if measured PPS below
#   SLO_REQUIRE_CHANNELS=1    fail if channels missing when NS iface present
#   SLO_RSS_STRICT=1          fail (not soft-skip) when channels null on dummy
#   LOAD_SECONDS=4            connect/iperf storm duration
#   SLO_CI=1                  soft-skip when API/VIP/iface unavailable
set -euo pipefail

FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
VIP="${VIP:-}"
VIP_PORT="${VIP_PORT:-80}"
SLO_RSS_PPS_MIN="${SLO_RSS_PPS_MIN:-1000}"
LOAD_SECONDS="${LOAD_SECONDS:-4}"
RSS_IFACE="${RSS_IFACE:-}"

auth=()
if [[ -n "${TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer $TOKEN")
fi

truthy() {
  case "${1:-}" in
    1|true|yes|TRUE|YES) return 0 ;;
    *) return 1 ;;
  esac
}

skip() {
  echo "NOTE: $1"
  echo "SKIP: RSS under-load PPS gate"
  exit 0
}

fail() {
  echo "FAIL: $1" >&2
  exit 2
}

STATUS_JSON="$(mktemp)"
STATS_JSON="$(mktemp)"
ETH_BEFORE="$(mktemp)"
ETH_AFTER="$(mktemp)"
trap 'rm -f "$STATUS_JSON" "$STATS_JSON" "$ETH_BEFORE" "$ETH_AFTER"' EXIT

echo "== RSS under-load: status =="
if ! curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/status" >"$STATUS_JSON"; then
  if truthy "${SLO_CI:-}"; then
    skip "FluxVM status unreachable (SLO_CI soft-skip)"
  fi
  fail "cannot fetch $FLUXVM_URL/v1/network/services/status"
fi
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/stats" >"$STATS_JSON" 2>/dev/null || echo '{"interfaces":{}}' >"$STATS_JSON"

eval "$(
STATUS_JSON="$STATUS_JSON" RSS_IFACE="$RSS_IFACE" \
SLO_REQUIRE_CHANNELS="${SLO_REQUIRE_CHANNELS:-}" \
SLO_RSS_STRICT="${SLO_RSS_STRICT:-}" \
python3 - <<'PY'
import json, os, shlex

status = json.load(open(os.environ["STATUS_JSON"]))
override = os.environ.get("RSS_IFACE", "").strip()
ns = status.get("north_south_interfaces") or []
interfaces = status.get("interfaces") or []

iface = override
if not iface and ns:
    iface = ns[0]
if not iface and interfaces:
    iface = (interfaces[0] or {}).get("interface") or ""

channels = None
for row in interfaces:
    if not isinstance(row, dict):
        continue
    if iface and row.get("interface") != iface:
        continue
    off = row.get("offload") or {}
    channels = off.get("combined_channels") or off.get("rx_channels")
    if not iface:
        iface = row.get("interface") or iface
    break

req = os.environ.get("SLO_REQUIRE_CHANNELS", "").strip().lower() in ("1", "true", "yes")
strict = os.environ.get("SLO_RSS_STRICT", "").strip().lower() in ("1", "true", "yes")

print(f"IFACE={shlex.quote(iface or '')}")
print(f"CHANNELS={channels if channels is not None else ''}")

if not iface:
    print("DECISION=skip_no_iface")
elif channels is None:
    if req:
        print("DECISION=fail_channels")
    elif strict:
        print("DECISION=fail_channels_null")
    else:
        print("DECISION=soft_skip_channels")
else:
    print("DECISION=ok")
PY
)"

case "${DECISION:-}" in
  skip_no_iface)
    if truthy "${SLO_CI:-}" || [[ -z "$VIP" ]]; then
      skip "no NS iface in status (set RSS_IFACE=)"
    fi
    fail "no NS iface in status (set RSS_IFACE=)"
    ;;
  fail_channels)
    fail "SLO_REQUIRE_CHANNELS: no combined_channels/rx_channels for $IFACE"
    ;;
  fail_channels_null)
    fail "SLO_RSS_STRICT: channels null for $IFACE (dummy/unsupported)"
    ;;
  soft_skip_channels)
    skip "channels null on $IFACE (dummy/unsupported); set SLO_RSS_STRICT=1 to fail"
    ;;
esac

echo "RSS iface=$IFACE channels=${CHANNELS:-unknown}"

if [[ -z "$VIP" ]]; then
  skip "no VIP set (RSS PPS gate needs VIP= for under-load storm)"
fi

dump_ethtool() {
  local iface="$1" out="$2"
  if ! command -v ethtool >/dev/null 2>&1; then
    : >"$out"
    return 0
  fi
  ethtool -S "$iface" >"$out" 2>/dev/null || : >"$out"
}

service_pkt_total() {
  STATS_JSON="$STATS_JSON" python3 - <<'PY'
import json, os
doc=json.load(open(os.environ["STATS_JSON"]))
total=0
interfaces=doc.get("interfaces")
rows=[]
if isinstance(interfaces, dict):
    for items in interfaces.values():
        if isinstance(items, list):
            rows.extend(items)
elif isinstance(interfaces, list):
    rows=interfaces
for c in rows:
    if not isinstance(c, dict):
        continue
    for k in ("forward_packets","reverse_packets","xdp_packets","dsr_packets","snat_packets"):
        v=c.get(k)
        if isinstance(v, int):
            total += v
print(total)
PY
}

echo "== RSS under-load: capture before =="
dump_ethtool "$IFACE" "$ETH_BEFORE"
# Refresh stats snapshot before storm.
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/stats" >"$STATS_JSON" 2>/dev/null || true
BEFORE_SVC="$(service_pkt_total)"

echo "== RSS under-load: ${LOAD_SECONDS}s storm → $VIP:$VIP_PORT =="
if command -v iperf3 >/dev/null 2>&1 && [[ "${RSS_USE_IPERF:-}" == "1" ]]; then
  iperf3 -u -c "$VIP" -p "$VIP_PORT" -t "$LOAD_SECONDS" -b 100M -P 4 >/tmp/sf-rss-iperf.txt 2>&1 &
  storm_pid=$!
  sleep "$LOAD_SECONDS"
  wait "$storm_pid" 2>/dev/null || true
else
  VIP="$VIP" VIP_PORT="$VIP_PORT" LOAD_SECONDS="$LOAD_SECONDS" python3 - <<'PY'
import os, subprocess, time, concurrent.futures
vip=os.environ["VIP"]
port=int(os.environ["VIP_PORT"])
deadline=time.perf_counter()+float(os.environ["LOAD_SECONDS"])
workers=64

def one():
    subprocess.run(["bash","-lc", f"echo >/dev/tcp/{vip}/{port}"], capture_output=True)

with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
    futs=[]
    while time.perf_counter() < deadline:
        futs.append(ex.submit(one))
        if len(futs) > workers * 4:
            concurrent.futures.wait(futs[:workers])
            futs=futs[workers:]
    concurrent.futures.wait(futs)
PY
fi

echo "== RSS under-load: capture after =="
dump_ethtool "$IFACE" "$ETH_AFTER"
curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/stats" >"$STATS_JSON" 2>/dev/null || true
AFTER_SVC="$(service_pkt_total)"

EVAL_OUT="$(
ETH_BEFORE="$ETH_BEFORE" ETH_AFTER="$ETH_AFTER" \
BEFORE_SVC="$BEFORE_SVC" AFTER_SVC="$AFTER_SVC" \
LOAD_SECONDS="$LOAD_SECONDS" CHANNELS="${CHANNELS:-}" \
SLO_RSS_PPS_MIN="$SLO_RSS_PPS_MIN" \
python3 - <<'PY'
import os, re, sys

def parse_ethtool(path):
    rx = tx = None
    rx_q = {}
    try:
        text = open(path).read()
    except OSError:
        return None, None, {}
    for line in text.splitlines():
        line = line.strip()
        low = line.lower().replace(" ", "")
        if rx is None and ("rx_packets:" in low or low.startswith("rxpackets:")):
            try:
                rx = int(line.split(":")[-1].strip())
            except ValueError:
                pass
        if tx is None and ("tx_packets:" in low or low.startswith("txpackets:")):
            try:
                tx = int(line.split(":")[-1].strip())
            except ValueError:
                pass
        m = re.match(r"^rx[_-]?(\d+)[_-]?(?:packets|pkts)\s*:\s*(\d+)$", line, re.I)
        if m:
            rx_q[int(m.group(1))] = int(m.group(2))
    if rx is None and rx_q:
        rx = sum(rx_q.values())
    return rx, tx, rx_q

secs = max(1e-6, float(os.environ.get("LOAD_SECONDS", "4")))
brx, btx, bq = parse_ethtool(os.environ["ETH_BEFORE"])
arx, atx, aq = parse_ethtool(os.environ["ETH_AFTER"])
pps = None
source = "none"
if brx is not None and arx is not None:
    delta = max(0, (arx - brx))
    if btx is not None and atx is not None:
        delta += max(0, atx - btx)
    pps = delta / secs
    source = "ethtool"
else:
    try:
        b = int(os.environ.get("BEFORE_SVC") or "0")
        a = int(os.environ.get("AFTER_SVC") or "0")
        if a >= b:
            pps = max(0, a - b) / secs
            source = "service_stats"
    except ValueError:
        pass

if pps is None:
    print("SOURCE=none")
    print("PPS=")
    print("QUEUE_NOTE=skip")
    sys.exit(0)

print(f"SOURCE={source}")
print(f"PPS={pps:.3f}")

active = 0
for q, after in aq.items():
    before = bq.get(q, 0)
    if after > before:
        active += 1
try:
    ch = int(os.environ.get("CHANNELS") or "0")
except ValueError:
    ch = 0
print(f"ACTIVE_RX_QUEUES={active}")
if ch >= 2 and aq:
    print(f"QUEUE_NOTE={'ok' if active >= 2 else 'underutilized'}")
elif ch >= 2:
    print("QUEUE_NOTE=no_per_queue_stats")
else:
    print("QUEUE_NOTE=skip")

limit = float(os.environ["SLO_RSS_PPS_MIN"])
if pps < limit:
    print(f"GATE=fail")
    print(f"GATE_MSG=measured PPS {pps:.1f} < SLO_RSS_PPS_MIN {limit}")
else:
    print("GATE=ok")
    print(f"GATE_MSG=RSS PPS OK: {pps:.1f} >= {limit}")
PY
)"

SOURCE="$(printf '%s\n' "$EVAL_OUT" | sed -n 's/^SOURCE=//p' | head -1)"
PPS="$(printf '%s\n' "$EVAL_OUT" | sed -n 's/^PPS=//p' | head -1)"
ACTIVE_RX_QUEUES="$(printf '%s\n' "$EVAL_OUT" | sed -n 's/^ACTIVE_RX_QUEUES=//p' | head -1)"
QUEUE_NOTE="$(printf '%s\n' "$EVAL_OUT" | sed -n 's/^QUEUE_NOTE=//p' | head -1)"
GATE="$(printf '%s\n' "$EVAL_OUT" | sed -n 's/^GATE=//p' | head -1)"
GATE_MSG="$(printf '%s\n' "$EVAL_OUT" | sed -n 's/^GATE_MSG=//p' | head -1)"

echo "measured_pps=${PPS:-n/a} source=${SOURCE:-none} active_rx_queues=${ACTIVE_RX_QUEUES:-0} queue_note=${QUEUE_NOTE:-}"

if [[ -z "${PPS:-}" ]]; then
  if truthy "${SLO_CI:-}"; then
    skip "could not sample PPS (no ethtool -S / service stats deltas)"
  fi
  fail "could not sample PPS"
fi

if [[ "${GATE:-}" == "fail" ]]; then
  fail "${GATE_MSG:-PPS below SLO_RSS_PPS_MIN}"
fi
echo "${GATE_MSG:-RSS PPS OK}"

case "${QUEUE_NOTE:-}" in
  underutilized)
    echo "NOTE: channels>=2 but fewer than 2 queues showed RX delta (best-effort)"
    ;;
  ok)
    echo "RSS multi-queue RX: at least 2 queues active"
    ;;
  no_per_queue_stats)
    echo "NOTE: per-queue RX stats unavailable; multi-queue check skipped"
    ;;
esac

echo "PASS: RSS under-load PPS gate"
