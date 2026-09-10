#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$ROOT/scripts/build-runtime-intelligence.sh"
bash -n "$ROOT/scripts/install-runtime-intelligence.sh"
bash -n "$ROOT/scripts/test-tcx-host.sh"

grep -q 'pub mod tcx;' "$ROOT/crates/fluxvm-network/src/lib.rs"
grep -q 'FLUXVM_TCX' "$ROOT/crates/fluxvm-network/src/tcx.rs"
grep -q 'BPF_TCX_INGRESS' "$ROOT/tools/fluxvm-tcx.c"
grep -q 'bpf_link_update' "$ROOT/tools/fluxvm-tcx.c"
grep -q 'diagnose_vm' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q '/v1/intelligence/vms/{id}/diagnose' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
grep -q 'network/effective' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
grep -q 'network/flows?limit=' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
grep -q 'Diagnose {' "$ROOT/crates/fluxvm-cli/src/main.rs"
grep -q 'fluxvm_intelligence::diagnose_vm' "$ROOT/crates/fluxvm-cli/src/main.rs"

python3 - "$ROOT" <<'PY'
import pathlib, sys, tomllib
root=pathlib.Path(sys.argv[1])
tomllib.loads((root/'crates/fluxvm-intelligence/Cargo.toml').read_text())
# Cheap offline structural gate for environments without rustc/cargo.
for f in [root/'crates/fluxvm-network/src/tcx.rs', root/'crates/fluxvm-intelligence/src/lib.rs', root/'crates/fluxvm-intelligence/src/main.rs']:
    s=f.read_text()
    assert s.count('{') == s.count('}'), f'unbalanced braces: {f}'
    assert '\t' not in s, f'tab found: {f}'
print('TOML + Rust structural checks: PASS')
PY

if command -v cargo >/dev/null 2>&1; then
  cargo test -p fluxvm-network -p fluxvm-intelligence -p fluxvm-cli
else
  echo 'SKIP cargo tests: cargo not installed'
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null; then
  ${CC:-cc} -fsyntax-only -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$ROOT/tools/fluxvm-tcx.c"
else
  echo 'SKIP libbpf C compile: libbpf development package not installed'
fi

echo 'TCX + Drop Detective static gates: PASS'
