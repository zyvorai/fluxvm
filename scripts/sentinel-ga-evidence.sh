#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${1:-/var/tmp/fluxvm-sentinel-evidence-$STAMP}"
python3 "$ROOT/tools/fluxvm-sentinel-certify.py" evidence "$OUT"
printf '%s\n' "$OUT"
