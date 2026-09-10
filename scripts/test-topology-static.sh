#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/build-topology-intelligence.sh scripts/build-runtime-intelligence.sh scripts/install-runtime-intelligence.sh scripts/test-topology-host.sh; do
  bash -n "$ROOT/$f"
done

grep -q 'pub mod topology;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'topo_vcpu_cpu' "$ROOT/bpf/fluxvm_topology.bpf.c"
grep -q 'sched_migrate_task' "$ROOT/bpf/fluxvm_topology.bpf.c"
grep -q 'softirq_entry' "$ROOT/bpf/fluxvm_topology.bpf.c"
grep -q 'memory_pages_by_node' "$ROOT/crates/fluxvm-intelligence/src/topology.rs"
grep -q 'refuse rollback' "$ROOT/crates/fluxvm-intelligence/src/topology.rs"
grep -q 'hardware RSS indirection' "$ROOT/crates/fluxvm-intelligence/src/topology.rs"
grep -q 'cleanup_stale_tracked' "$ROOT/crates/fluxvm-intelligence/src/topology.rs"
grep -q 'fluxvm_vcpu_cross_numa' "$ROOT/crates/fluxvm-intelligence/src/topology.rs"
grep -q 'bpf_object__pin_maps' "$ROOT/tools/fluxvm-topology-loader.c"

python3 - "$ROOT" <<'PY'
import pathlib,sys
root=pathlib.Path(sys.argv[1])
for rel in ['crates/fluxvm-intelligence/src/topology.rs','crates/fluxvm-intelligence/src/bin/fluxvm-topology.rs']:
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
        if c in '\"\'':
            q=c;i+=1
            while i<len(s):
                if s[i]=='\\': i+=2; continue
                if s[i]==q: i+=1; break
                i+=1
            continue
        if c in '([{': stack.append(c)
        elif c in ')]}':
            assert stack and stack.pop()==pairs[c], f'{rel}: delimiter mismatch at {i}'
        i+=1
    assert not stack, f'{rel}: unclosed delimiter(s)'
print('Rust lexical structure: PASS')
PY

if command -v python3 >/dev/null && python3 -c 'import yaml' >/dev/null 2>&1; then
  python3 - <<PY
import yaml
with open('$ROOT/.github/workflows/topology-intelligence.yml') as f: yaml.safe_load(f)
print('workflow YAML: PASS')
PY
fi

if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT" && cargo test -p fluxvm-intelligence topology)
else
  echo 'cargo unavailable: SKIP Rust compilation'
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf; then
  cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-topology-loader.c" $(pkg-config --cflags libbpf)
  cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-topology-events.c" $(pkg-config --cflags libbpf)
  "$ROOT/scripts/build-topology-intelligence.sh" /tmp/fluxvm-set8-static-bpf
else
  echo 'libbpf development headers unavailable: SKIP real helper/BPF compilation'
fi

echo 'Topology intelligence static gates: PASS'
