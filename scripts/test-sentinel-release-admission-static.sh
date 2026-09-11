#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 - <<'PY' "$ROOT/tools/fluxvm_release_admission.py"
import ast,sys
from pathlib import Path; ast.parse(Path(sys.argv[1]).read_text(encoding='utf-8'),filename=sys.argv[1])
PY
python3 "$ROOT/tools/tests/test_fluxvm_release_admission.py"
python3 - <<'PY' "$ROOT/schemas/sentinel-release-admission.schema.json" "$ROOT/examples/sentinel-release-admission.json"
import json,sys
from pathlib import Path
for p in sys.argv[1:]: json.loads(Path(p).read_text(encoding='utf-8'))
PY
bash -n "$ROOT/scripts/install-sentinel-release-admission.sh" "$ROOT/scripts/test-sentinel-release-admission-host.sh"
! find "$ROOT" -type d -name __pycache__ -print -quit | grep -q .
! find "$ROOT" -type f \( -name '*.pyc' -o -name '*.pyo' \) -print -quit | grep -q .
echo "Set 17E static gates: PASS"
