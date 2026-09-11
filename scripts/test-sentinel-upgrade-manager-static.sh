#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 - <<'PY' "$ROOT/tools/fluxvm_upgrade_manager.py"
import pathlib, sys
p=pathlib.Path(sys.argv[1])
compile(p.read_text(encoding='utf-8'), str(p), 'exec')
PY
python3 -m unittest -v "$ROOT/tools/tests/test_fluxvm_upgrade_manager.py"
python3 - <<'PY' "$ROOT/schemas/sentinel-upgrade-plan.schema.json" "$ROOT/examples/sentinel-upgrade-plan.json"
import json, sys
for p in sys.argv[1:]:
    json.load(open(p, encoding='utf-8'))
print('JSON parse: ok')
PY
python3 "$ROOT/tools/fluxvm_upgrade_manager.py" validate "$ROOT/examples/sentinel-upgrade-plan.json" >/dev/null
python3 "$ROOT/tools/fluxvm_upgrade_manager.py" plan "$ROOT/examples/sentinel-upgrade-plan.json" >/dev/null
# Prevent shell execution regressions and unsafe path handling from disappearing.
grep -q 'shell=True' "$ROOT/tools/fluxvm_upgrade_manager.py" && { echo 'shell=True is forbidden' >&2; exit 1; } || true
grep -q 'LOCK_NB' "$ROOT/tools/fluxvm_upgrade_manager.py"
grep -q 'plan changed after transaction began' "$ROOT/tools/fluxvm_upgrade_manager.py"
grep -q 'map ABI mismatch' "$ROOT/tools/fluxvm_upgrade_manager.py"
grep -q 'EVIDENCE.sha256' "$ROOT/tools/fluxvm_upgrade_manager.py"
grep -q 'ssh-keygen.*-Y.*sign' "$ROOT/tools/fluxvm_upgrade_manager.py"
find "$ROOT" -type d -name __pycache__ -print -quit | grep -q . && { echo '__pycache__ must not ship' >&2; exit 1; } || true
find "$ROOT" -type f -name '*.pyc' -print -quit | grep -q . && { echo '*.pyc must not ship' >&2; exit 1; } || true
echo 'Sentinel Set 14E static gates: PASS'
