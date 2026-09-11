#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m py_compile "$ROOT/tools/fluxvm-sentinel-certify.py" "$ROOT/tools/tests/test_fluxvm_sentinel_certify.py" "$ROOT/scripts/sentinel-ga-merge-measurements.py"
python3 -m unittest "$ROOT/tools/tests/test_fluxvm_sentinel_certify.py"
python3 -m json.tool "$ROOT/benchmarks/sentinel-ga-budgets.json" >/dev/null
for f in "$ROOT/scripts"/sentinel-ga-*.sh "$ROOT/scripts/test-sentinel-ga-host.sh"; do bash -n "$f"; done
python3 "$ROOT/tools/fluxvm-sentinel-certify.py" probe >/tmp/fluxvm-sentinel-probe.json
python3 -m json.tool /tmp/fluxvm-sentinel-probe.json >/dev/null
if command -v shellcheck >/dev/null; then
  shellcheck "$ROOT/scripts"/sentinel-ga-*.sh "$ROOT/scripts/test-sentinel-ga-host.sh"
fi
echo "Sentinel Set 12E static gates passed"
