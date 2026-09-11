#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
OUT="${1:-/tmp/fluxvm-network-measurements.json}"
DURATION="${FLUXVM_BENCH_SECONDS:-5}"
command -v iperf3 >/dev/null || { echo "iperf3 required" >&2; exit 2; }
command -v ping >/dev/null || { echo "ping required" >&2; exit 2; }
SERVER="${FLUXVM_BENCH_SERVER:-127.0.0.1}"
PORT="${FLUXVM_BENCH_PORT:-5201}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
iperf3 -c "$SERVER" -p "$PORT" -t "$DURATION" -J > "$TMP/iperf.json"
ping -n -c 50 -i 0.02 "$SERVER" > "$TMP/ping.txt"
python3 - "$TMP/iperf.json" "$TMP/ping.txt" "$OUT" <<'PY'
import json, re, sys, pathlib
iperf=json.load(open(sys.argv[1]))
ping=pathlib.Path(sys.argv[2]).read_text()
bps=float(iperf.get('end',{}).get('sum_received',{}).get('bits_per_second',0.0))
loss=0.0
m=re.search(r'(\d+(?:\.\d+)?)% packet loss', ping)
if m: loss=float(m.group(1))
rtts=[]
for line in ping.splitlines():
    m=re.search(r'time[=<]([0-9.]+) ms', line)
    if m: rtts.append(float(m.group(1)))
rtts.sort()
def pct(xs,p):
    if not xs: return None
    i=min(len(xs)-1, max(0, int((len(xs)-1)*p)))
    return xs[i]
out={"schema_version":1,"metadata":{"source":"sentinel-ga-benchmark-network"},"metrics":{
    "throughput_gbps":bps/1e9,"packet_loss_pct":loss}}
p99=pct(rtts,.99)
if p99 is not None: out['metrics']['network_rtt_p99_ms']=p99
pathlib.Path(sys.argv[3]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
PY
cat "$OUT"
