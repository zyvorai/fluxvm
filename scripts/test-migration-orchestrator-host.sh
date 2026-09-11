#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; : "${FLUXVM_MIGRATION_HOST_TEST:=0}"
if [[ "$FLUXVM_MIGRATION_HOST_TEST" != 1 ]]; then echo 'SKIP: set FLUXVM_MIGRATION_HOST_TEST=1 on a lab host'; exit 0; fi
command -v fluxvm >/dev/null
python3 -B "$ROOT/tools/fluxvm_migration_orchestrator.py" --state-root /var/lib/fluxvm/migrations validate "${FLUXVM_MIGRATION_PLAN:?set FLUXVM_MIGRATION_PLAN}" >/dev/null
python3 -B "$ROOT/tools/fluxvm_migration_orchestrator.py" --state-root /var/lib/fluxvm/migrations run "$FLUXVM_MIGRATION_PLAN" --dry-run >/tmp/fluxvm-migrate-dryrun.json
python3 -m json.tool /tmp/fluxvm-migrate-dryrun.json >/dev/null
echo 'migration orchestrator host preflight: PASS'
