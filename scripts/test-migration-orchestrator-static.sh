#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; export PYTHONDONTWRITEBYTECODE=1
python3 - "$ROOT/tools/fluxvm_migration_orchestrator.py" "$ROOT/tools/tests/test_fluxvm_migration_orchestrator.py" <<'PYCOMPILE'
import sys
for path in sys.argv[1:]: compile(open(path, encoding='utf-8').read(), path, 'exec')
print('python syntax: PASS')
PYCOMPILE
python3 -B -m unittest -v "$ROOT/tools/tests/test_fluxvm_migration_orchestrator.py"
python3 - "$ROOT/schemas/migration-plan.schema.json" "$ROOT/examples/migration-plan.json" <<'JSONCHECK'
import json,sys
for p in sys.argv[1:]: json.load(open(p))
print('json parse: PASS')
JSONCHECK
for f in "$ROOT"/scripts/*.sh; do bash -n "$f"; done
python3 -B "$ROOT/tools/fluxvm_migration_orchestrator.py" --state-root /tmp/fluxvm-set13e-test validate "$ROOT/examples/migration-plan.json" >/dev/null
! grep -R --include='*.py' -n 'shell=True' "$ROOT/tools"
if find "$ROOT" \( -name '__pycache__' -o -name '*.pyc' \) -print | grep -q .; then echo 'bytecode artifact found' >&2; exit 1; fi
echo 'migration orchestrator static gates: PASS'
