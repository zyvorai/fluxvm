#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-/usr}"
install -Dm0755 "$ROOT/tools/fluxvm-sentinel-certify.py" "$PREFIX/libexec/fluxvm/fluxvm-sentinel-certify"
install -Dm0644 "$ROOT/benchmarks/sentinel-ga-budgets.json" "$PREFIX/share/fluxvm/sentinel-ga-budgets.json"
install -Dm0644 "$ROOT/packaging/systemd/fluxvm-sentinel-reconcile.service" "/usr/lib/systemd/system/fluxvm-sentinel-reconcile.service"
install -Dm0644 "$ROOT/packaging/systemd/fluxvm-sentinel-reconcile.timer" "/usr/lib/systemd/system/fluxvm-sentinel-reconcile.timer"
echo "installed Sentinel GA certification/reconcile tooling"
