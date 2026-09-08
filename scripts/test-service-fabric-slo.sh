#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# CI-friendly Service Fabric SLO gate wrapper.
# Exports SLO_CI=1 so perf harness applies universal numeric defaults:
#   SLO_VIP_P99_MS=25 (when VIP set), SLO_PRESSURE_IDLE=1, SLO_EDT_FAIRNESS=1,
#   SLO_FAILOVER_LOSS_MS=500, SLO_MPPS_MIN=0.01, SLO_CI_SHAPE=1.
# Skips VIP/Mpps/RSS load gates cleanly when VIP is unset.
# Then runs RSS under-load PPS gate (soft-skip without VIP/iface).
#
# Env (optional overrides):
#   SLO_VIP_P99_MS / SLO_PRESSURE_IDLE / SLO_REQUIRE_CHANNELS / SLO_CI_SHAPE
#   SLO_EDT_FAIRNESS / SLO_FAILOVER_LOSS_MS / SLO_MPPS_MIN
#   SLO_RSS_PPS_MIN / SLO_RSS_STRICT / RSS_IFACE
#   VIP=… / VIP_PORT=… / SAMPLES=… / FABRIC_URL / SERVICE
#   FLUXVM_URL / TOKEN
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SLO_CI="${SLO_CI:-1}"
export SLO_CI_SHAPE="${SLO_CI_SHAPE:-1}"

"$ROOT/scripts/test-service-fabric-perf.sh" "$@"

echo "== RSS under-load PPS (CI) =="
export SLO_RSS_PPS_MIN="${SLO_RSS_PPS_MIN:-1000}"
"$ROOT/scripts/test-service-fabric-rss.sh"
