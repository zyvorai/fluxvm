#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$ROOT/scripts/build-vmm-guard.sh"
bash -n "$ROOT/scripts/build-runtime-intelligence.sh"
bash -n "$ROOT/scripts/install-runtime-intelligence.sh"
bash -n "$ROOT/scripts/test-vmm-guard-qos-host.sh"

grep -q 'SEC("lsm/bprm_check_security")' "$ROOT/bpf/fluxvm_guard.bpf.c"
grep -q 'SEC("lsm/file_mprotect")' "$ROOT/bpf/fluxvm_guard.bpf.c"
grep -q 'SEC("lsm/file_open")' "$ROOT/bpf/fluxvm_guard.bpf.c"
grep -q 'bpf_get_current_cgroup_id' "$ROOT/bpf/fluxvm_guard.bpf.c"
grep -q 'generation = policy->generation' "$ROOT/bpf/fluxvm_guard.bpf.c"
grep -q 'bpf_program__attach_lsm' "$ROOT/tools/fluxvm-guard-loader.c"
grep -q 'ring_buffer__new' "$ROOT/tools/fluxvm-guard-events.c"
grep -q 'pub fn apply_policy' "$ROOT/crates/fluxvm-intelligence/src/guard.rs"
grep -q 'pub fn assess' "$ROOT/crates/fluxvm-intelligence/src/qos.rs"
grep -q 'pub fn apply' "$ROOT/crates/fluxvm-intelligence/src/qos.rs"
grep -q 'pub mod guard;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'pub mod qos;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"

python3 - "$ROOT" <<'PY'
import pathlib, sys, tomllib, yaml
root=pathlib.Path(sys.argv[1])
tomllib.loads((root/'crates/fluxvm-intelligence/Cargo.toml').read_text())
yaml.safe_load((root/'.github/workflows/vmm-guard-qos.yml').read_text())
for path in [
    root/'crates/fluxvm-intelligence/src/lib.rs',
    root/'crates/fluxvm-intelligence/src/guard.rs',
    root/'crates/fluxvm-intelligence/src/qos.rs',
    root/'crates/fluxvm-intelligence/src/bin/fluxvm-guard.rs',
    root/'crates/fluxvm-intelligence/src/bin/fluxvm-qos.rs',
]:
    s=path.read_text()
    stack=[]; pairs={')':'(',']':'[','}':'{'}
    i=0; quote=None; esc=False; line=False; block=0
    while i<len(s):
        c=s[i]; n=s[i+1] if i+1<len(s) else ''
        if line:
            if c=='\n': line=False
            i+=1; continue
        if block:
            if c=='/' and n=='*': block+=1; i+=2; continue
            if c=='*' and n=='/': block-=1; i+=2; continue
            i+=1; continue
        if quote:
            if esc: esc=False
            elif c=='\\': esc=True
            elif c==quote: quote=None
            i+=1; continue
        if c=='/' and n=='/': line=True; i+=2; continue
        if c=='/' and n=='*': block=1; i+=2; continue
        if c=='"': quote=c; i+=1; continue
        if c=="'" and i+2<len(s) and s[i+2]=="'": i+=3; continue
        if c=="'" and n=='\\' and i+3<len(s) and s[i+3]=="'": i+=4; continue
        if c in '([{': stack.append(c)
        elif c in ')]}':
            if not stack or stack.pop()!=pairs[c]: raise SystemExit(f'unbalanced {path}: {c} at {i}')
        i+=1
    if stack or quote or block: raise SystemExit(f'unclosed lexical structure: {path}')
print('TOML + YAML + Rust lexical gates: PASS')
PY

if command -v cargo >/dev/null 2>&1; then
  cargo test -p fluxvm-intelligence
else
  echo 'SKIP cargo tests: cargo not installed'
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null; then
  ${CC:-cc} -fsyntax-only -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$ROOT/tools/fluxvm-guard-loader.c"
  ${CC:-cc} -fsyntax-only -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$ROOT/tools/fluxvm-guard-events.c"
else
  echo 'SKIP real libbpf helper compile: libbpf development package not installed'
fi

echo 'VMM Guard + Adaptive QoS static gates: PASS'
