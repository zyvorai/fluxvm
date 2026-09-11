#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
OUT="${1:-/tmp/fluxvm-storage-measurements.json}"
DIR="${FLUXVM_BENCH_STORAGE_DIR:-/var/tmp}"
SIZE="${FLUXVM_BENCH_STORAGE_SIZE:-256m}"
RUNTIME="${FLUXVM_BENCH_SECONDS:-10}"
command -v fio >/dev/null || { echo "Flexible I/O Tester (fio) required" >&2; exit 2; }
FIO_VERSION="$(fio --version 2>/dev/null || true)"
[[ "$FIO_VERSION" == fio-* ]] || { echo "Flexible I/O Tester required; found incompatible fio executable: $FIO_VERSION" >&2; exit 2; }
TMP=$(mktemp -d "$DIR/fluxvm-fio.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
fio --name=fluxvm-ga --filename="$TMP/io.bin" --size="$SIZE" --runtime="$RUNTIME" --time_based=1 \
  --rw=randrw --rwmixread=70 --bs=4k --iodepth=32 --direct=1 --ioengine=libaio --group_reporting=1 \
  --output-format=json > "$TMP/fio.json"
python3 - "$TMP/fio.json" "$OUT" <<'PY'
import json, pathlib, sys
j=json.load(open(sys.argv[1])); job=j['jobs'][0]
# fio clat_ns percentiles use string percentile keys.
vals=[]
for side in ('read','write'):
    pct=job.get(side,{}).get('clat_ns',{}).get('percentile',{})
    for key in ('99.000000','99.000000%'):
        if key in pct: vals.append(float(pct[key])/1e6)
out={"schema_version":1,"metadata":{"source":"sentinel-ga-benchmark-storage"},"metrics":{}}
if vals: out['metrics']['block_io_p99_ms']=max(vals)
pathlib.Path(sys.argv[2]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
PY
cat "$OUT"
