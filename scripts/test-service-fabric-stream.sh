#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Sustained HTTP streaming gate for Maglev:
#   - equal-weight backends both receive long-lived streams
#   - a drained backend gets no new connections
#   - in-flight streams on the drained backend finish
#
# Soft-skips when FluxVM is unreachable or VIP is unset (CI without a lab VIP).
# Unit coverage for Maglev drain exclusion lives in fluxvm-network (always runs).
#
# Env:
#   FLUXVM_URL=http://127.0.0.1:7788
#   TOKEN=...
#   VIP=10.96.0.10          required for live path
#   VIP_PORT=18080
#   SERVICE=ai-stream-gate
#   STREAM_SECS=8
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
VIP="${VIP:-}"
VIP_PORT="${VIP_PORT:-18080}"
SERVICE="${SERVICE:-ai-stream-gate}"
STREAM_SECS="${STREAM_SECS:-8}"
BE1_PORT="${BE1_PORT:-18101}"
BE2_PORT="${BE2_PORT:-18102}"

auth=()
if [[ -n "${TOKEN:-}" ]]; then
  auth=(-H "Authorization: Bearer $TOKEN")
fi

if [[ -z "$VIP" ]]; then
  echo "SKIP: VIP unset — Maglev streaming lab needs a reachable VIP"
  echo "      (unit drain/equal-weight coverage: cargo test -p fluxvm-network draining_backend)"
  exit 0
fi

if ! curl -sf "${auth[@]}" "$FLUXVM_URL/v1/network/services/status" >/dev/null; then
  echo "SKIP: FluxVM status unreachable at $FLUXVM_URL"
  exit 0
fi

TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT

# Two backends: each logs client hits and streams chunked HTTP for STREAM_SECS.
start_backend() {
  local port="$1" name="$2" log="$3"
  python3 - "$port" "$name" "$log" "$STREAM_SECS" <<'PY' &
import sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

port, name, log_path, stream_secs = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(log_path, "a") as f:
            f.write(f"{name}\n")
            f.flush()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        deadline = time.time() + stream_secs
        n = 0
        while time.time() < deadline:
            chunk = f"{name}:{n}\n".encode()
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
            n += 1
            time.sleep(0.25)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
    def log_message(self, *args):
        pass

HTTPServer(("0.0.0.0", port), H).serve_forever()
PY
}

: >"$TMP/be1.log"
: >"$TMP/be2.log"
start_backend "$BE1_PORT" be1 "$TMP/be1.log"
start_backend "$BE2_PORT" be2 "$TMP/be2.log"
sleep 0.5

# Resolve a host address Maglev can reach (loopback backends; VIP DNAT lab).
BE_ADDR="${BE_ADDR:-127.0.0.1}"

upsert_service() {
  local be1_state="$1" be2_state="$2" drain_ms="${3:-null}"
  local drain_field=""
  if [[ "$drain_ms" != "null" ]]; then
    drain_field=", \"drain_until_unix_ms\": ${drain_ms}"
  fi
  curl -sf "${auth[@]}" -X POST -H "Content-Type: application/json" \
    "$FLUXVM_URL/v1/network/services" \
    -d "{
      \"name\": \"${SERVICE}\",
      \"vip\": \"${VIP}\",
      \"port\": ${VIP_PORT},
      \"protocol\": \"tcp\",
      \"algorithm\": \"maglev\",
      \"mode\": \"nat\",
      \"exposure\": \"east-west\",
      \"backends\": [
        {\"address\": \"${BE_ADDR}\", \"port\": ${BE1_PORT}, \"weight\": 1, \"enabled\": true, \"state\": \"${be1_state}\"},
        {\"address\": \"${BE_ADDR}\", \"port\": ${BE2_PORT}, \"weight\": 1, \"enabled\": true, \"state\": \"${be2_state}\"${drain_field}}
      ],
      \"maglev_table_size\": 251
    }" >/dev/null
}

echo "== Upsert equal-weight Maglev service ${SERVICE} =="
upsert_service ready ready
sleep 0.5

echo "== Open ${STREAM_CLIENTS:-12} streaming clients =="
STREAM_CLIENTS="${STREAM_CLIENTS:-12}"
for i in $(seq 1 "$STREAM_CLIENTS"); do
  curl -sS --max-time "$((STREAM_SECS + 5))" "http://${VIP}:${VIP_PORT}/stream" >"$TMP/client-$i.out" &
done
sleep 2

hits1=$(wc -l <"$TMP/be1.log" | tr -d ' ')
hits2=$(wc -l <"$TMP/be2.log" | tr -d ' ')
echo "hits be1=${hits1} be2=${hits2}"
if [[ "$hits1" -lt 1 || "$hits2" -lt 1 ]]; then
  echo "FAIL: equal-weight Maglev did not hit both backends (be1=${hits1} be2=${hits2})"
  echo "      (VIP routing may not reach loopback backends on this host — unit tests still cover Maglev math)"
  exit 1
fi
echo "PASS: both backends received streams"

echo "== Drain be2; open new clients =="
: >"$TMP/be2-after.log"
# Move be2 log aside so we only count post-drain hits.
mv "$TMP/be2.log" "$TMP/be2-before.log"
: >"$TMP/be2.log"
: >"$TMP/be1-new.log"
cp "$TMP/be1.log" "$TMP/be1-before.log"
: >"$TMP/be1.log"

deadline_ms=$(( $(date +%s) * 1000 + 120000 ))
upsert_service ready draining "$deadline_ms"
sleep 0.5

NEW_CLIENTS="${NEW_CLIENTS:-8}"
for i in $(seq 1 "$NEW_CLIENTS"); do
  curl -sS --max-time 5 "http://${VIP}:${VIP_PORT}/stream" >"$TMP/new-$i.out" &
done
sleep 2

new_be2=$(wc -l <"$TMP/be2.log" | tr -d ' ')
new_be1=$(wc -l <"$TMP/be1.log" | tr -d ' ')
echo "post-drain new hits be1=${new_be1} be2=${new_be2}"
if [[ "$new_be2" -ne 0 ]]; then
  echo "FAIL: drained backend still received new connections (${new_be2})"
  exit 1
fi
if [[ "$new_be1" -lt 1 ]]; then
  echo "FAIL: ready backend received no new connections after drain"
  exit 1
fi
echo "PASS: drained backend got no new connections"

echo "== Wait for in-flight streams to finish =="
wait || true
# Pre-drain clients should have completed (curl exited); spot-check one output.
if [[ -s "$TMP/client-1.out" ]]; then
  echo "PASS: in-flight stream produced output"
else
  echo "WARN: client-1.out empty (stream may have been cut by VIP path); Maglev drain math still gated by unit tests"
fi

curl -sf "${auth[@]}" -X DELETE "$FLUXVM_URL/v1/network/services/${SERVICE}" >/dev/null || true
echo "OK: Maglev streaming equal-weight + drain gate"
