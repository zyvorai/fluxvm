#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Lab-grade Service Fabric SLO wrapper with higher Mpps / CPU ceilings.
# Exports SLO_LAB=1 so perf harness defaults to:
#   SLO_MPPS_MIN=0.05          (5× CI connect floor)
#   SLO_PKT_MPPS_MIN=0.10      packet Mpps from ethtool/service stats
#   SLO_CPU_MAX_PERCENT=85     fluxvm CPU% during storm
#   SLO_RSS_PPS_MIN=10000
#   SLO_VIP_P99_MS=50          when VIP set (override for tight labs)
#   MPPS_DURATION=3 MPPS_WORKERS=64
#
# Requires a reachable VIP for numeric gates; soft-skips packet/CPU when
# counters/pid are unavailable. CI floor remains scripts/test-service-fabric-slo.sh.
#
# Env overrides: same as test-service-fabric-perf.sh / test-service-fabric-rss.sh
#   VIP=… VIP_PORT=… FLUXVM_URL=… TOKEN=… FABRIC_URL=… SERVICE=…
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SLO_LAB="${SLO_LAB:-1}"
export SLO_CI_SHAPE="${SLO_CI_SHAPE:-1}"
# Do not force SLO_CI=1 — lab ceilings supersede the 0.01 Mpps CI floor.

"$ROOT/scripts/test-service-fabric-perf.sh" "$@"
