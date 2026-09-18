#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# S8 evidence: scrape Policy Observer Prometheus metrics and record RSS.
# Prefer a live DaemonSet endpoint; fall back to local process metrics.
#
#   OBSERVER_URL=http://127.0.0.1:9090 ./scripts/evidence-policy-observer-scrape.sh
#   # or with kubectl port-forward already open
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OBSERVER_EVIDENCE_DIR:-$ROOT/docs/benchmarks/evidence}"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/policy-observer-scrape-$TS.txt"

URL="${OBSERVER_URL:-}"
if [[ -z "$URL" ]]; then
  if command -v kubectl >/dev/null 2>&1; then
    POD="$(kubectl -n kube-system get pod -l app.kubernetes.io/name=fluxvm-policy-observer -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -n "$POD" ]]; then
      URL="$(kubectl -n kube-system get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
      if [[ -n "$URL" ]]; then
        URL="http://${URL}:9090"
      fi
    fi
  fi
fi
URL="${URL:-http://127.0.0.1:9090}"

{
  echo "policy-observer scrape evidence @ $TS"
  echo "url=$URL"
  echo "--- /metrics (head) ---"
  if curl -sf --max-time 5 "$URL/metrics" | tee /tmp/fluxvm-observer-metrics.$$ | head -n 80; then
    echo "--- series of interest ---"
    grep -E 'fluxvm_pr(hit|ules|idx)|fluxvm_policy|process_resident' /tmp/fluxvm-observer-metrics.$$ || true
    BYTES=$(wc -c </tmp/fluxvm-observer-metrics.$$ | tr -d ' ')
    echo "metrics_bytes=$BYTES"
  else
    echo "FAIL: could not scrape $URL/metrics"
    echo "sizing model (offline):"
    python3 "$ROOT/scripts/benchmark-policy-observer-set19.py" 2>/dev/null || true
    exit 1
  fi
  echo "--- RSS ---"
  if command -v kubectl >/dev/null 2>&1; then
    kubectl -n kube-system top pod -l app.kubernetes.io/name=fluxvm-policy-observer 2>/dev/null || true
  fi
  pgrep -af fluxvm-policy-observer | head -5 || true
  echo "--- sizing model ---"
  python3 "$ROOT/scripts/benchmark-policy-observer-set19.py" 2>/dev/null || echo "(sizing script absent)"
} | tee "$OUT"
rm -f /tmp/fluxvm-observer-metrics.$$
echo "wrote $OUT"
