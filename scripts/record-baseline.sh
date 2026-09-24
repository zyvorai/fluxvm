#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Record host metadata and run the existing benches before behavior changes.
# Non-Linux hosts record metadata and skip KVM benches (exit 0).
# avg_create_ms / boot_to_ready_ms from bench-sandbox.sh are API create time,
# not guest init. warm_claim_ms is a separate pool-claim measurement.
#
#   ./scripts/record-baseline.sh [output-file]

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${1:-${ROOT}/docs/benchmarks/evidence/baseline-${STAMP}.txt}"
mkdir -p "$(dirname "$OUT")"

{
  echo "schema=fluxvm-baseline-1"
  echo "recorded_at=${STAMP}"
  echo "commit=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "uname=$(uname -srm)"
  echo "os=$(uname -s)"
  if [[ -r /proc/cpuinfo ]]; then
    echo "cpu=$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ //')"
  else
    echo "cpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
  fi
  echo "nproc=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
  echo "config_note=production-hardening.toml is the profile these numbers are compared against; this run does not require that file to be loaded"
  echo "metric_note=avg_create_ms and boot_to_ready_ms are control-plane create latency, not guest-ready"
  echo "metric_note=warm_claim_ms is POST /v1/pools/{}/claim and is not comparable to cold create"
  echo "sla_note=not a sizing SLA; Firecracker 125ms and 5/core/sec targets are not FluxVM SLAs"
  echo
  if [[ "$(uname -s)" != "Linux" || ! -e /dev/kvm ]]; then
    echo "kvm=skipped"
    echo "bench-sandbox=skipped"
    echo "bench-density=skipped"
    echo "bench-secure-containers=skipped"
    echo "bench-warm-claim=skipped"
    echo "reason=Linux and /dev/kvm are required; metadata above is the Phase 0 record for this host"
  else
    echo "kvm=present"
    echo "--- bench-sandbox ---"
    bash "${ROOT}/scripts/bench-sandbox.sh" || echo "bench-sandbox=failed"
    echo "--- bench-density ---"
    bash "${ROOT}/scripts/bench-density.sh" || echo "bench-density=failed"
    echo "--- bench-secure-containers ---"
    bash "${ROOT}/scripts/bench-secure-containers.sh" || echo "bench-secure-containers=failed"
    echo "--- bench-warm-claim ---"
    bash "${ROOT}/scripts/bench-warm-claim.sh" || echo "bench-warm-claim=failed"
  fi
} | tee "$OUT"
echo "wrote ${OUT}"
