#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in scripts/build-afxdp-fastpath.sh scripts/build-runtime-intelligence.sh scripts/install-runtime-intelligence.sh scripts/test-afxdp-host.sh; do bash -n "$ROOT/$f"; done
grep -q 'pub mod afxdp;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'BPF_MAP_TYPE_XSKMAP' "$ROOT/bpf/fluxvm_afxdp.bpf.c"
grep -q 'bpf_redirect_map(&afxdp_xsks, key, XDP_PASS)' "$ROOT/bpf/fluxvm_afxdp.bpf.c"
grep -q 'XDP_FLAGS_UPDATE_IF_NOEXIST' "$ROOT/tools/fluxvm-afxdp-loader.c"
grep -q 'refusing replacement' "$ROOT/tools/fluxvm-afxdp-loader.c"
grep -q 'XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD' "$ROOT/tools/fluxvm-afxdp-worker.c"
grep -q 'XDP_USE_NEED_WAKEUP' "$ROOT/tools/fluxvm-afxdp-worker.c"
grep -q 'XDP_OPTIONS_ZEROCOPY' "$ROOT/tools/fluxvm-afxdp-worker.c"
grep -q 'ring_buffer__new' "$ROOT/tools/fluxvm-afxdp-events.c"
grep -q 'shared UMEM' "$ROOT/docs/afxdp-fastpath.md"
grep -q 'dedicated-interface confirmation' "$ROOT/crates/fluxvm-intelligence/src/afxdp.rs"
python3 - "$ROOT" <<'PY2'
import pathlib,sys
root=pathlib.Path(sys.argv[1])
for rel in ['crates/fluxvm-intelligence/src/afxdp.rs','crates/fluxvm-intelligence/src/bin/fluxvm-afxdp.rs']:
 s=(root/rel).read_text(); stack=[]; i=0; pairs={')':'(',']':'[','}':'{'}
 while i<len(s):
  if s.startswith('//',i):
   j=s.find('\n',i); i=len(s) if j<0 else j+1; continue
  if s.startswith('/*',i):
   d=1;i+=2
   while i<len(s) and d:
    if s.startswith('/*',i):d+=1;i+=2
    elif s.startswith('*/',i):d-=1;i+=2
    else:i+=1
   continue
  c=s[i]
  if c == '"':
   q=c;i+=1
   while i<len(s):
    if s[i]=='\\':i+=2;continue
    if s[i]==q:i+=1;break
    i+=1
   continue
  if c in '([{':stack.append(c)
  elif c in ')]}':assert stack and stack.pop()==pairs[c],f'{rel}: mismatch at {i}'
  i+=1
 assert not stack,f'{rel}: unclosed delimiters'
print('Rust lexical structure: PASS')
PY2
if python3 -c 'import yaml' >/dev/null 2>&1; then python3 - <<PY2
import yaml
with open('$ROOT/.github/workflows/afxdp-fastpath.yml') as f: yaml.safe_load(f)
print('workflow YAML: PASS')
PY2
fi
if command -v cargo >/dev/null 2>&1; then (cd "$ROOT" && cargo test -p fluxvm-intelligence afxdp); else echo 'cargo unavailable: SKIP Rust compilation'; fi
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf libxdp; then
 cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-afxdp-loader.c" $(pkg-config --cflags libbpf)
 cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-afxdp-worker.c" $(pkg-config --cflags libxdp libbpf)
 cc -fsyntax-only -Wall -Wextra -Werror "$ROOT/tools/fluxvm-afxdp-events.c" $(pkg-config --cflags libbpf)
 "$ROOT/scripts/build-afxdp-fastpath.sh" /tmp/fluxvm-set9-static-bpf /tmp/fluxvm-set9-static-bin
else echo 'libbpf/libxdp development headers unavailable: SKIP real helper/BPF compilation'; fi
echo 'AF_XDP fast-path static gates: PASS'
