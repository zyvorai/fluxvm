#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$ROOT/scripts/test-drop-reason-migration-host.sh"
grep -q 'DATAPLANE_SCHEMA_VERSION: u32 = 10' "$ROOT/crates/fluxvm-network/src/ebpf.rs"
grep -q 'pub struct DropReasonRecord' "$ROOT/crates/fluxvm-network/src/ebpf.rs"
grep -q 'fluxvm_drop_reasons' "$ROOT/bpf/fluxvm_tc.bpf.c"
grep -q 'fluxvm_migration' "$ROOT/bpf/fluxvm_tc.bpf.c"
grep -q 'FLUXVM_REASON_RATE_LIMIT' "$ROOT/bpf/fluxvm_tc.bpf.c"
grep -q 'FLUXVM_REASON_MIGRATION_QUIESCE' "$ROOT/bpf/fluxvm_tc.bpf.c"
grep -q 'fluxvm_pod_policy_verdict4' "$ROOT/bpf/fluxvm_pod_policy.bpf.h"
grep -q 'FLUXVM_POD_VERDICT_AUDIT' "$ROOT/bpf/fluxvm_pod_policy.bpf.h"
grep -q 'pub mod migration_state;' "$ROOT/crates/fluxvm-network/src/lib.rs"
grep -q 'pub fn export_snapshot' "$ROOT/crates/fluxvm-network/src/migration_state.rs"
grep -q 'pub fn restore_snapshot' "$ROOT/crates/fluxvm-network/src/migration_state.rs"
grep -q 'network/drop-reasons' "$ROOT/crates/fluxvm-api/src/lib.rs"
grep -q 'network/migration/quiesce' "$ROOT/crates/fluxvm-api/src/lib.rs"
grep -q 'MigrationQuiesce' "$ROOT/crates/fluxvm-cli/src/main.rs"
grep -q 'MigrationRestore' "$ROOT/crates/fluxvm-cli/src/main.rs"
grep -q 'diagnose_vm_with_reasons' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'exact-kernel' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"

python3 - "$ROOT" <<'PY'
import pathlib, sys
root=pathlib.Path(sys.argv[1])
for rel in [
    'crates/fluxvm-network/src/migration_state.rs',
    'crates/fluxvm-intelligence/src/lib.rs',
    'crates/fluxvm-intelligence/src/main.rs',
]:
    p=root/rel; s=p.read_text()
    assert s.count('{') == s.count('}'), f'unbalanced braces: {rel}'
    assert '\t' not in s, f'tab found: {rel}'
print('Rust structural gates: PASS')
PY

if command -v cargo >/dev/null 2>&1; then
  cargo test -p fluxvm-network -p fluxvm-intelligence -p fluxvm-api -p fluxvm-cli
else
  echo 'SKIP cargo tests: cargo not installed'
fi

if [[ -f /usr/include/bpf/bpf_helpers.h ]]; then
  "$ROOT/scripts/build-ebpf.sh" /tmp/fluxvm-set3-bpf
else
  echo 'SKIP eBPF compile: libbpf development headers not installed'
fi

echo 'drop-reason + migration-state static gates: PASS'
