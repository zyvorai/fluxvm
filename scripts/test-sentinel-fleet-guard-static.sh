#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest "$ROOT/tools/tests/test_fluxvm_fleet_guard.py"
python3 - <<'PY' "$ROOT/schemas/sentinel-fleet-guard.schema.json" "$ROOT/examples/sentinel-fleet-guard.json"
import json,sys
for p in sys.argv[1:]: json.load(open(p))
print('json: ok')
PY
bash -n "$ROOT/scripts/install-sentinel-fleet-guard.sh" "$ROOT/scripts/test-sentinel-fleet-guard-host.sh"
if command -v systemd-analyze >/dev/null; then
  tmp=0
  if [[ ! -x /usr/libexec/fluxvm/fluxvm-fleet-guard ]]; then sudo install -Dm0755 "$ROOT/tools/fluxvm_fleet_guard.py" /usr/libexec/fluxvm/fluxvm-fleet-guard; tmp=1; fi
  systemd-analyze verify "$ROOT/packaging/systemd/fluxvm-fleet-guard.service" "$ROOT/packaging/systemd/fluxvm-fleet-guard.timer" >/dev/null
  (( tmp == 0 )) || sudo rm -f /usr/libexec/fluxvm/fluxvm-fleet-guard
fi
printf 'Set 16E static gates: PASS\n'
