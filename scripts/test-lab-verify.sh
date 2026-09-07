#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Full lab post-deploy verify for FluxVM (new four-tracks + regression).
#
#   sudo -E ./scripts/test-lab-verify.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

chmod +x scripts/test-lab-four-tracks-e2e.sh scripts/test-lab-regression.sh \
  scripts/test-kvm-pause-smoke.sh scripts/test-ebpf-smoke.sh \
  scripts/test-kvm-linux-boot-smoke.sh 2>/dev/null || true

echo "########## FluxVM lab: four-tracks e2e ##########"
./scripts/test-lab-four-tracks-e2e.sh
echo "########## FluxVM lab: regression ##########"
./scripts/test-lab-regression.sh
echo "########## FluxVM lab verify: ALL GREEN ##########"
