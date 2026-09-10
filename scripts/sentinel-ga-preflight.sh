#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${1:-baseline}"
OUT="${2:-/tmp/fluxvm-sentinel-preflight.json}"
BUDGETS="${FLUXVM_SENTINEL_BUDGETS:-$ROOT/benchmarks/sentinel-ga-budgets.json}"
PY="${PYTHON:-python3}"
"$PY" "$ROOT/tools/fluxvm-sentinel-certify.py" gate \
  --profile "$PROFILE" \
  --budgets "$BUDGETS" \
  --json-out "$OUT"
cat "$OUT"
