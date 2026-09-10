#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/build-memory-profiler.sh scripts/build-runtime-intelligence.sh scripts/install-runtime-intelligence.sh scripts/test-memory-profiler-host.sh; do
  bash -n "$ROOT/$f"
done

grep -q 'pub mod memprof;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'handle_mm_fault' "$ROOT/bpf/fluxvm_memprof.bpf.c"
grep -q 'mm_vmscan_direct_reclaim_begin' "$ROOT/bpf/fluxvm_memprof.bpf.c"
grep -q 'first_kvm_entry_ns' "$ROOT/bpf/fluxvm_memprof.bpf.c"
grep -q 'memory.events' "$ROOT/crates/fluxvm-intelligence/src/memprof.rs"
grep -q 'CLOCK_MONOTONIC' "$ROOT/crates/fluxvm-intelligence/src/memprof.rs"
grep -q 'snapshot-begin' "$ROOT/crates/fluxvm-intelligence/src/memprof.rs"
grep -q 'fluxvm_memprof_memory_psi_full_avg10' "$ROOT/crates/fluxvm-intelligence/src/memprof.rs"
grep -q 'Runtime Intelligence shared maps must be loaded' "$ROOT/tools/fluxvm-memprof-loader.c"

python3 - "$ROOT" <<'PY'
import pathlib,sys,tomllib
root=pathlib.Path(sys.argv[1])
tomllib.loads((root/'crates/fluxvm-intelligence/Cargo.toml').read_text())
# Lightweight lexical sanity for new Rust sources, ignoring strings/comments.
for rel in ['crates/fluxvm-intelligence/src/memprof.rs','crates/fluxvm-intelligence/src/bin/fluxvm-memprof.rs']:
    s=(root/rel).read_text(); stack=[]; i=0; pairs={')':'(',']':'[','}':'{'}
    while i<len(s):
        if s.startswith('//',i):
            j=s.find('\n',i); i=len(s) if j<0 else j+1; continue
        if s.startswith('/*',i):
            depth=1;i+=2
            while i<len(s) and depth:
                if s.startswith('/*',i): depth+=1;i+=2
                elif s.startswith('*/',i): depth-=1;i+=2
                else:i+=1
            continue
        c=s[i]
        if c in '"\'':
            q=c;i+=1
            while i<len(s):
                if s[i]=='\\': i+=2;continue
                if s[i]==q: i+=1;break
                i+=1
            continue
        if c in '([{': stack.append(c)
        elif c in ')]}':
            assert stack and stack.pop()==pairs[c], f'{rel}: delimiter mismatch at {i}'
        i+=1
    assert not stack, f'{rel}: unclosed delimiter(s)'
print('TOML + Rust structural checks: PASS')
PY

if command -v python3 >/dev/null && python3 -c 'import yaml' >/dev/null 2>&1; then
  python3 - <<PY
import yaml
with open('$ROOT/.github/workflows/memory-boot-profiler.yml') as f: yaml.safe_load(f)
print('workflow YAML: PASS')
PY
fi

if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT" && cargo test -p fluxvm-intelligence memprof)
else
  echo 'cargo unavailable: SKIP Rust compilation'
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf; then
  cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-memprof-loader.c" $(pkg-config --cflags libbpf)
  cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-memprof-events.c" $(pkg-config --cflags libbpf)
  "$ROOT/scripts/build-memory-profiler.sh" /tmp/fluxvm-set7-static-bpf
else
  echo 'libbpf development headers unavailable: SKIP real helper/BPF compilation'
fi

echo 'Memory + boot profiler static gates: PASS'
