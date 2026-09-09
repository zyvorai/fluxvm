#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Stricter multi-queue RSS affinity proof for Service Fabric.
#
# Generates many 5-tuple flows (varying ephemeral source ports) against VIP,
# samples ethtool per-queue RX counters, and asserts:
#   - ≥2 RX queues show nonzero delta when combined/rx channels ≥2
#   - flow distribution is not collapsed onto a single queue (affinity spread)
#
# Soft-skips on dummy/null-channel ifaces unless SLO_RSS_STRICT=1.
#
# Env:
#   FLUXVM_URL=http://127.0.0.1:7788
#   TOKEN=…
#   VIP= / VIP_PORT=80
#   RSS_IFACE=              override NS iface
#   FLOWS=64                distinct source-port connects
#   LOAD_SECONDS=3
#   SLO_RSS_STRICT=1        fail when channels null
#   SLO_CI=1                soft-skip when VIP/iface unavailable
#
#   ./scripts/test-service-fabric-rss-affinity.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
VIP="${VIP:-}"
VIP_PORT="${VIP_PORT:-80}"
FLOWS="${FLOWS:-64}"
LOAD_SECONDS="${LOAD_SECONDS:-3}"
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
  echo "SKIP: RSS affinity proof"
  exit 0
}

fail() {
  echo "FAIL: $1" >&2
  exit 2
}

STATUS_JSON="$(mktemp)"
ETH_BEFORE="$(mktemp)"
ETH_AFTER="$(mktemp)"
trap 'rm -f "$STATUS_JSON" "$ETH_BEFORE" "$ETH_AFTER"' EXIT

echo "== RSS affinity: status =="
if ! curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/status" >"$STATUS_JSON"; then
  if truthy "${SLO_CI:-}"; then
    skip "FluxVM status unreachable (SLO_CI soft-skip)"
  fi
  fail "cannot fetch services/status"
fi

eval "$(
STATUS_JSON="$STATUS_JSON" RSS_IFACE="$RSS_IFACE" \
SLO_RSS_STRICT="${SLO_RSS_STRICT:-}" \
python3 - <<'PY'
import json, os, shlex
status = json.load(open(os.environ["STATUS_JSON"]))
override = os.environ.get("RSS_IFACE", "").strip()
ns = status.get("north_south_interfaces") or []
interfaces = status.get("interfaces") or []
iface = override or (ns[0] if ns else "")
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
strict = os.environ.get("SLO_RSS_STRICT", "").strip().lower() in ("1", "true", "yes")
print(f"IFACE={shlex.quote(iface or '')}")
print(f"CHANNELS={channels if channels is not None else ''}")
if not iface:
    print("DECISION=skip_no_iface")
elif channels is None:
    print("DECISION=fail_channels_null" if strict else "DECISION=soft_skip_channels")
elif int(channels) < 2:
    print("DECISION=soft_skip_single")
else:
    print("DECISION=ok")
PY
)"

case "${DECISION:-}" in
  skip_no_iface)
    if truthy "${SLO_CI:-}" || [[ -z "$VIP" ]]; then
      skip "no NS iface (set RSS_IFACE=)"
    fi
    fail "no NS iface"
    ;;
  fail_channels_null)
    fail "SLO_RSS_STRICT: channels null for $IFACE"
    ;;
  soft_skip_channels)
    skip "channels null on $IFACE (dummy); set SLO_RSS_STRICT=1 to fail"
    ;;
  soft_skip_single)
    skip "channels=$CHANNELS < 2 — cannot prove multi-queue affinity"
    ;;
esac

[[ -n "$VIP" ]] || skip "VIP unset (affinity proof needs VIP=)"

echo "RSS affinity iface=$IFACE channels=$CHANNELS flows=$FLOWS"

dump_queues() {
  local iface="$1" out="$2"
  if ! command -v ethtool >/dev/null 2>&1; then
    : >"$out"
    return 0
  fi
  ethtool -S "$iface" >"$out" 2>/dev/null || : >"$out"
}

echo "== capture before =="
dump_queues "$IFACE" "$ETH_BEFORE"

echo "== $FLOWS-flow storm ${LOAD_SECONDS}s → $VIP:$VIP_PORT =="
VIP="$VIP" VIP_PORT="$VIP_PORT" FLOWS="$FLOWS" LOAD_SECONDS="$LOAD_SECONDS" python3 - <<'PY'
import os, socket, time, concurrent.futures
vip = os.environ["VIP"]
port = int(os.environ["VIP_PORT"])
n = int(os.environ["FLOWS"])
deadline = time.perf_counter() + float(os.environ["LOAD_SECONDS"])

def one(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Pin distinct local ports when possible so RSS 5-tuple varies.
        local_port = 20000 + (i % 20000)
        try:
            s.bind(("0.0.0.0", local_port))
        except OSError:
            pass
        s.settimeout(0.5)
        s.connect((vip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()

ok = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, n)) as ex:
    while time.perf_counter() < deadline:
        futs = [ex.submit(one, i) for i in range(n)]
        ok += sum(1 for f in concurrent.futures.as_completed(futs) if f.result())
print(f"connect_attempts_ok≈{ok}", flush=True)
PY

echo "== capture after =="
dump_queues "$IFACE" "$ETH_AFTER"

ETH_BEFORE="$ETH_BEFORE" ETH_AFTER="$ETH_AFTER" CHANNELS="$CHANNELS" python3 - <<'PY'
import os, re, sys
before = open(os.environ["ETH_BEFORE"]).read().splitlines()
after = open(os.environ["ETH_AFTER"]).read().splitlines()
channels = int(os.environ.get("CHANNELS") or "0")

def queue_rx(lines):
    # Common ethtool spellings: rx_queue_N_packets, rx-N.packets, queue_N_rx_packets
    pats = [
        re.compile(r"rx[_-]queue[_-]?(\d+)[_-]packets[:\s]+(\d+)", re.I),
        re.compile(r"rx-(\d+)\.packets[:\s]+(\d+)", re.I),
        re.compile(r"queue[_-]?(\d+)[_-]rx[_-]packets[:\s]+(\d+)", re.I),
    ]
    out = {}
    for line in lines:
        s = line.strip()
        for pat in pats:
            m = pat.search(s)
            if m:
                out[int(m.group(1))] = int(m.group(2))
                break
    return out

b = queue_rx(before)
a = queue_rx(after)
if not a:
    print("NOTE: no per-queue RX counters in ethtool -S")
    print("SKIP: RSS affinity proof (counters unavailable)")
    sys.exit(0)

deltas = {q: a.get(q, 0) - b.get(q, 0) for q in set(b) | set(a)}
active = sorted(q for q, d in deltas.items() if d > 0)
total = sum(max(0, d) for d in deltas.values())
print(f"queue_deltas={dict(sorted(deltas.items()))}")
print(f"active_rx_queues={len(active)} queues={active} total_delta={total}")

if total <= 0:
    print("FAIL: no RX queue packet delta under multi-flow storm", file=sys.stderr)
    sys.exit(2)
if len(active) < 2:
    print(
        f"FAIL: affinity collapsed — only {len(active)} queue(s) active "
        f"(need ≥2 for channels={channels})",
        file=sys.stderr,
    )
    sys.exit(2)

# Soft check: top queue should not take >95% when ≥2 active (skew OK, monopoly not).
top = max(deltas.values())
if total > 0 and top / total > 0.95 and len(active) >= 2:
    print(f"NOTE: high skew top_share={top/total:.2%} (still multi-queue)")
print(f"PASS: RSS affinity — {len(active)} queues carried RX under pinned flows")
PY

echo "PASS: RSS affinity proof"
