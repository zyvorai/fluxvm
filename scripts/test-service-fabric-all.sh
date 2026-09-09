#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Run the full Service Fabric lab/CI test battery:
#   1. CI SLO (test-service-fabric-slo.sh)
#   2. Lab ceilings (test-service-fabric-lab.sh) when SLO_LAB=1 (default on)
#   3. RSS under-load PPS
#   4. RSS multi-queue affinity proof
#
# Env: same as child scripts (FLUXVM_URL, VIP, VIP_PORT, TOKEN, FABRIC_URL, …).
#   SKIP_LAB=1     skip lab ceilings
#   SKIP_RSS=1     skip RSS PPS + affinity
#   SLO_CI=1       soft-skip modes in children
#
#   ./scripts/test-service-fabric-all.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
chmod +x scripts/test-service-fabric-*.sh 2>/dev/null || true

export SLO_CI="${SLO_CI:-1}"
export SLO_CI_SHAPE="${SLO_CI_SHAPE:-1}"

echo "########## Service Fabric: CI SLO ##########"
./scripts/test-service-fabric-slo.sh

if [[ "${SKIP_LAB:-}" != "1" ]]; then
  echo "########## Service Fabric: lab ceilings ##########"
  SLO_LAB=1 ./scripts/test-service-fabric-lab.sh
fi

if [[ "${SKIP_RSS:-}" != "1" ]]; then
  echo "########## Service Fabric: RSS under-load ##########"
  ./scripts/test-service-fabric-rss.sh
  echo "########## Service Fabric: RSS affinity ##########"
  ./scripts/test-service-fabric-rss-affinity.sh
fi

echo "########## ALL PASS: Service Fabric test battery ##########"
