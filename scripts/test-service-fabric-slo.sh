#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# CI-friendly Service Fabric SLO gate wrapper.
# Skips VIP latency when VIP is unset; always validates status + pressure JSON.
# Optional lab thresholds are passed through to test-service-fabric-perf.sh.
#
# Env (optional):
#   SLO_VIP_P99_MS=…          VIP connect p99 ceiling (requires VIP=)
#   SLO_PRESSURE_IDLE=1       fail if pressure action is hard_reload
#   SLO_REQUIRE_CHANNELS=1    require RSS channel fields when NS ifaces present
#   VIP=… / VIP_PORT=… / SAMPLES=…
#   FLUXVM_URL / TOKEN
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SLO_CI_SHAPE="${SLO_CI_SHAPE:-1}"
exec "$ROOT/scripts/test-service-fabric-perf.sh" "$@"
