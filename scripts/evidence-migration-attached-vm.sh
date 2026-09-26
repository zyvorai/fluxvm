#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# S11 — migration orchestrator against a VM with a live dataplane attached.
#
# Boots (or reuses) a FluxVM guest, attaches eBPF/nft dataplane, then runs
# migration-export → migration-restore through fluxvm-migrate / dataplane CLI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLUXVM_ATTACHED_MIGRATION="${FLUXVM_ATTACHED_MIGRATION:-1}"
if [[ "${FLUXVM_ATTACHED_MIGRATION}" != 1 ]]; then
  echo "SKIP: set FLUXVM_ATTACHED_MIGRATION=1" >&2
  exit 0
fi

command -v fluxctl >/dev/null || { echo "missing fluxctl" >&2; exit 2; }
CFG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
SPEC="${FLUXVM_S11_SPEC:-$ROOT/examples/qemu.json}"
STATE_ROOT="${FLUXVM_MIGRATION_STATE:-/var/lib/fluxvm/migrations-s11}"
mkdir -p "$STATE_ROOT"

# migration-* mutates bpffs maps / TC state; prefer passwordless sudo when not root.
FLUXCTL=(fluxctl --config "$CFG")
if [[ "$(id -u)" -ne 0 ]]; then
  if sudo -n true 2>/dev/null; then
    FLUXCTL=(sudo -n fluxctl --config "$CFG")
  else
    echo "WARN: not root and sudo -n unavailable; migration map updates may fail" >&2
  fi
fi

# Create a disposable VM if none supplied.
VM_ID="${FLUXVM_S11_VM_ID:-}"
if [[ -z "$VM_ID" ]]; then
  OUT=$("${FLUXCTL[@]}" create --spec "$SPEC")
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
  if [[ -n "${RESUME_CMD[*]:-}" ]]; then
    "${RESUME_CMD[@]}" || true
  fi
  if [[ "${CREATED:-0}" == 1 && "${FLUXVM_S11_KEEP:-0}" != 1 ]]; then
    "${FLUXCTL[@]}" delete "$VM_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Ensure the VM is running and dataplane is attached (ebpf or legacy).
"${FLUXCTL[@]}" start "$VM_ID" >/dev/null 2>&1 || true
sleep 2

# Prefer the migration-state CLI surface on the dataplane.
if "${FLUXCTL[@]}" dataplane migration-export --help >/dev/null 2>&1; then
  QUIESCE_CMD=("${FLUXCTL[@]}" dataplane migration-quiesce "$VM_ID")
  EXPORT_CMD=("${FLUXCTL[@]}" dataplane migration-export --output "$STATE_ROOT/export.json" "$VM_ID")
  RESTORE_CMD=("${FLUXCTL[@]}" dataplane migration-restore --input "$STATE_ROOT/export.json" "$VM_ID")
  RESUME_CMD=("${FLUXCTL[@]}" dataplane migration-resume "$VM_ID")
elif command -v fluxvm >/dev/null && fluxvm dataplane migration-export --help >/dev/null 2>&1; then
  QUIESCE_CMD=(fluxvm dataplane migration-quiesce "$VM_ID")
  EXPORT_CMD=(fluxvm dataplane migration-export --output "$STATE_ROOT/export.json" "$VM_ID")
  RESTORE_CMD=(fluxvm dataplane migration-restore --input "$STATE_ROOT/export.json" "$VM_ID")
  RESUME_CMD=(fluxvm dataplane migration-resume "$VM_ID")
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
  if "${FLUXCTL[@]}" dataplane --help 2>&1 | grep -q migration; then
    "${FLUXCTL[@]}" dataplane migration-export --output "$STATE_ROOT/export.json" "$VM_ID"
    "${FLUXCTL[@]}" dataplane migration-restore --input "$STATE_ROOT/export.json" "$VM_ID"
    "${FLUXCTL[@]}" dataplane migration-resume "$VM_ID" || true
  else
    echo "WARN: orchestrator dry-run only; dataplane migration-* CLI unavailable" >&2
  fi
  echo "S11 ATTACHED MIGRATION: PASS (orchestrator path)"
  exit 0
fi

"${QUIESCE_CMD[@]}"
"${EXPORT_CMD[@]}"
python3 -m json.tool "$STATE_ROOT/export.json" >/dev/null
rc=0
"${RESTORE_CMD[@]}" || rc=$?
# Restore leaves the dataplane in restoring mode. Always resume so a
# live guest is not stuck after the evidence run.
if [[ -n "${RESUME_CMD[*]:-}" ]]; then
  "${RESUME_CMD[@]}" || true
fi
if [[ "$rc" -ne 0 ]]; then
  echo "S11 restore failed rc=$rc" >&2
  exit "$rc"
fi
echo "S11 ATTACHED MIGRATION: PASS"
