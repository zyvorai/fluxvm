#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Full lab post-deploy verify for FluxVM:
#   devops contract + live gate + upgrade-snapshot + four-tracks + regression.
#
#   sudo -E ./scripts/test-lab-verify.sh
#   FABRIC_URL=https://127.0.0.1:9095 FLUXVM_URL=http://127.0.0.1:7788 \
#     sudo -E ./scripts/test-lab-verify.sh
#
# Child KVM/serial smokes must not read the caller's stdin (e.g. ssh bash -s).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Avoid guest console / qemu reading the outer pipe/heredoc.
exec </dev/null

FABRIC_URL="${FABRIC_URL:-https://127.0.0.1:9095}"
FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"
export FABRIC_URL FLUXVM_URL

chmod +x scripts/test-lab-four-tracks-e2e.sh scripts/test-lab-regression.sh \
  scripts/test-kvm-pause-smoke.sh scripts/test-kvm-snapshot-smoke.sh \
  scripts/test-ebpf-smoke.sh \
  scripts/test-kvm-linux-boot-smoke.sh scripts/devops-gate.sh \
  scripts/test-devops-gate.sh scripts/upgrade-snapshot.sh \
  scripts/test-upgrade-snapshot.sh 2>/dev/null || true

echo "########## FluxVM lab: devops contract units ##########"
python3 -m unittest discover -s examples/devops -p 'test_*.py' -v

echo "########## FluxVM lab: devops-gate (offline contract) ##########"
bash scripts/test-devops-gate.sh

echo "########## FluxVM lab: devops-gate (live) ##########"
ZYVOR_ALLOW_OFFLINE=0 bash scripts/devops-gate.sh

echo "########## FluxVM lab: upgrade-snapshot ##########"
bash scripts/test-upgrade-snapshot.sh

echo "########## FluxVM lab: four-tracks e2e ##########"
./scripts/test-lab-four-tracks-e2e.sh

echo "########## FluxVM lab: regression ##########"
./scripts/test-lab-regression.sh

echo "########## FluxVM lab verify: ALL GREEN ##########"
