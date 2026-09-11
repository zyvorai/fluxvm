#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$ROOT/tools/tests" -p 'test_fluxvm_fleet_rollout.py' -v
python3 - <<'PY' "$ROOT/tools/fluxvm_fleet_rollout.py" "$ROOT/schemas/sentinel-fleet-rollout.schema.json" "$ROOT/examples/sentinel-fleet-rollout.json"
import ast,json,sys
ast.parse(open(sys.argv[1]).read()); json.load(open(sys.argv[2])); json.load(open(sys.argv[3])); print('syntax/json: ok')
PY
bash -n "$ROOT/scripts/install-sentinel-fleet-rollout.sh"
grep -q 'StrictHostKeyChecking=yes' "$ROOT/tools/fluxvm_fleet_rollout.py"
grep -q 'ThreadPoolExecutor' "$ROOT/tools/fluxvm_fleet_rollout.py"
! grep -R --include='*.py' -n 'shell=True' "$ROOT/tools" || exit 1
! find "$ROOT" -type d -name __pycache__ | grep -q . || { echo '__pycache__ found' >&2; exit 1; }
echo "Set 15E static gates: PASS"
