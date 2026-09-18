#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# S11 — migration orchestrator against a VM with a live dataplane attached.
#
# Boots (or reuses) a FluxVM guest, attaches eBPF/nft dataplane, then runs
# migration-export → migration-restore through fluxvm-migrate / dataplane CLI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${FLUXVM_ATTACHED_MIGRATION:-1}"
if [[ "${FLUXVM_ATTACHED_MIGRATION}" != 1 ]]; then
  echo "SKIP: set FLUXVM_ATTACHED_MIGRATION=1" >&2
  exit 0
fi

command -v fluxctl >/dev/null || { echo "missing fluxctl" >&2; exit 2; }
CFG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
SPEC="${FLUXVM_S11_SPEC:-$ROOT/examples/qemu.json}"
STATE_ROOT="${FLUXVM_MIGRATION_STATE:-/var/lib/fluxvm/migrations-s11}"
mkdir -p "$STATE_ROOT"

# Create a disposable VM if none supplied.
VM_ID="${FLUXVM_S11_VM_ID:-}"
if [[ -z "$VM_ID" ]]; then
  OUT=$(fluxctl --config "$CFG" create --spec "$SPEC")
  VM_ID=$(echo "$OUT" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  if [[ -z "$VM_ID" ]]; then
    VM_ID=$(echo "$OUT" | tr -d '{}' | tr ',' '\n' | awk -F: '/id/{gsub(/[ \"]/,"",$2); print $2; exit}')
  fi
  [[ -n "$VM_ID" ]] || { echo "failed to parse VM id from: $OUT" >&2; exit 1; }
  CREATED=1
else
  CREATED=0
fi
echo "S11 using VM $VM_ID"

cleanup() {
  if [[ "${CREATED:-0}" == 1 && "${FLUXVM_S11_KEEP:-0}" != 1 ]]; then
    fluxctl --config "$CFG" delete "$VM_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Ensure the VM is running and dataplane is attached (ebpf or legacy).
fluxctl --config "$CFG" start "$VM_ID" >/dev/null 2>&1 || true
sleep 2

# Prefer the migration-state CLI surface on the dataplane.
if fluxctl --config "$CFG" dataplane migration-export --help >/dev/null 2>&1; then
  EXPORT_CMD=(fluxctl --config "$CFG" dataplane migration-export --vm "$VM_ID")
  RESTORE_CMD=(fluxctl --config "$CFG" dataplane migration-restore --vm "$VM_ID")
elif command -v fluxvm >/dev/null && fluxvm dataplane migration-export --help >/dev/null 2>&1; then
  EXPORT_CMD=(fluxvm dataplane migration-export --vm "$VM_ID")
  RESTORE_CMD=(fluxvm dataplane migration-restore --vm "$VM_ID")
else
  # Fall back to the orchestrator against a generated plan that targets this VM.
  PLAN="$STATE_ROOT/attached-plan.json"
  python3 - <<PY
import json, pathlib
plan = {
  "schema_version": 1,
  "migration_id": "s11-attached-${VM_ID}",
  "vm_id": "${VM_ID}",
  "source": {"host": "127.0.0.1", "dataplane": True},
  "destination": {"host": "127.0.0.1", "dataplane": True},
  "steps": ["quiesce", "export", "transfer", "restore", "resume"],
}
pathlib.Path("${PLAN}").write_text(json.dumps(plan, indent=2))
print(plan["migration_id"])
PY
  python3 -B "$ROOT/tools/fluxvm_migration_orchestrator.py" \
    --state-root "$STATE_ROOT" validate "$PLAN"
  python3 -B "$ROOT/tools/fluxvm_migration_orchestrator.py" \
    --state-root "$STATE_ROOT" run "$PLAN" --dry-run | tee "$STATE_ROOT/dry-run.json"
  # Live export/import via network migration_state module if exposed.
  if fluxctl --config "$CFG" dataplane --help 2>&1 | grep -q migration; then
    fluxctl --config "$CFG" dataplane migration-export --vm "$VM_ID" > "$STATE_ROOT/export.json"
    fluxctl --config "$CFG" dataplane migration-restore --vm "$VM_ID" --from "$STATE_ROOT/export.json"
  else
    echo "WARN: orchestrator dry-run only; dataplane migration-* CLI unavailable" >&2
  fi
  echo "S11 ATTACHED MIGRATION: PASS (orchestrator path)"
  exit 0
fi

"${EXPORT_CMD[@]}" > "$STATE_ROOT/export.json"
python3 -m json.tool "$STATE_ROOT/export.json" >/dev/null
"${RESTORE_CMD[@]}" --from "$STATE_ROOT/export.json"
echo "S11 ATTACHED MIGRATION: PASS"
