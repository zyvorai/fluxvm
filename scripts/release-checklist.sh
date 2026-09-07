#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

fail=0
need() {
  if [[ ! -f $1 ]]; then
    echo "MISSING $1"
    fail=1
  else
    echo "OK      $1"
  fi
}

need SECURITY.md
need CONTRIBUTING.md
need Makefile
need docs/PRODUCTION.md
need docs/production-dataplane.md
need configs/network-fabric-prod.toml
need LICENSE
need NOTICE

python3 scripts/test-security-groups.py
python3 scripts/test-network-policy.py
python3 scripts/test-production-dataplane.py
python3 scripts/test-project-production.py

exit "$fail"
