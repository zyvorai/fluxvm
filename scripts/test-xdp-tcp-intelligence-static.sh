#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in \
  "$ROOT/scripts/build-network-intelligence.sh" \
  "$ROOT/scripts/build-runtime-intelligence.sh" \
  "$ROOT/scripts/install-runtime-intelligence.sh" \
  "$ROOT/scripts/test-xdp-tcp-intelligence-host.sh"; do bash -n "$f"; done

grep -q 'XDP_FLAGS_UPDATE_IF_NOEXIST' "$ROOT/tools/fluxvm-xdp-shield-loader.c"
if grep -q 'XDP_FLAGS_REPLACE' "$ROOT/tools/fluxvm-xdp-shield-loader.c"; then
  echo "unsafe XDP replacement flag found" >&2; exit 1
fi
grep -q 'refusing to replace existing XDP owner' "$ROOT/tools/fluxvm-xdp-shield-loader.c"
grep -q 'struct bpf_spin_lock lock' "$ROOT/bpf/fluxvm_xdp_shield.bpf.c"
grep -q 'generation' "$ROOT/bpf/fluxvm_xdp_shield.bpf.c"
grep -q 'FLUXVM_SHIELD_REASON_BUCKET_EXHAUSTED' "$ROOT/bpf/fluxvm_xdp_shield.bpf.c"
grep -q 'BPF_TCX_INGRESS' "$ROOT/tools/fluxvm-tcp-loader.c"
grep -q 'BPF_TCX_EGRESS' "$ROOT/tools/fluxvm-tcp-loader.c"
grep -q 'tcx_unsupported' "$ROOT/tools/fluxvm-tcp-loader.c"
grep -q 'TCP_EVENT_RETRANSMIT' "$ROOT/bpf/fluxvm_tcp_intel.bpf.c"
grep -q 'last_in_seq' "$ROOT/bpf/fluxvm_tcp_intel.bpf.c"
grep -q 'syn_origin' "$ROOT/bpf/fluxvm_tcp_intel.bpf.c"
grep -q 'pub mod shield;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'pub mod tcpintel;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'pub mod netintel;' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q '/v1/netintel/vms/{id}' "$ROOT/crates/fluxvm-intelligence/src/bin/fluxvm-netintel.rs"

python3 - "$ROOT" <<'PY'
import pathlib, sys, tomllib
root=pathlib.Path(sys.argv[1])
tomllib.loads((root/'crates/fluxvm-intelligence/Cargo.toml').read_text())
# lightweight structural gate catches accidental truncation/unbalanced delimiters
for p in list((root/'crates/fluxvm-intelligence/src').glob('*.rs'))+list((root/'crates/fluxvm-intelligence/src/bin').glob('*.rs')):
    s=p.read_text(); stack=[]; pairs={')':'(',']':'[','}':'{'}; opens=set(pairs.values())
    in_str=False; in_char=False; esc=False; line=False; block=0; i=0
    while i<len(s):
        c=s[i]; n=s[i+1] if i+1<len(s) else ''
        if line:
            if c=='\n': line=False
        elif block:
            if c=='/' and n=='*': block+=1; i+=1
            elif c=='*' and n=='/': block-=1; i+=1
        elif in_str:
            if esc: esc=False
            elif c=='\\': esc=True
            elif c=='"': in_str=False
        elif in_char:
            if esc: esc=False
            elif c=='\\': esc=True
            elif c=="'": in_char=False
        else:
            if c=='/' and n=='/': line=True; i+=1
            elif c=='/' and n=='*': block=1; i+=1
            elif c=='"': in_str=True
            elif c=="'" and (n=='\\' or (i+2<len(s) and s[i+2]=="'")): in_char=True
            elif c in opens: stack.append(c)
            elif c in pairs:
                if not stack or stack.pop()!=pairs[c]: raise SystemExit(f'unbalanced {p}: {c}')
        i+=1
    if stack or in_str or in_char or block: raise SystemExit(f'unclosed structure in {p}')
print('TOML + Rust structural checks: PASS')
PY

if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT" && cargo test -p fluxvm-intelligence)
else
  echo "SKIP cargo tests: cargo unavailable"
fi
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null; then
  CFLAGS="$(pkg-config --cflags libbpf)"; LIBS="$(pkg-config --libs libbpf)"
  ${CC:-cc} -O2 -Wall -Wextra -Werror $CFLAGS "$ROOT/tools/fluxvm-xdp-shield-loader.c" -o /tmp/fluxvm-xdp-shield-loader.$$ $LIBS
  ${CC:-cc} -O2 -Wall -Wextra -Werror $CFLAGS "$ROOT/tools/fluxvm-shield-events.c" -o /tmp/fluxvm-shield-events.$$ $LIBS
  ${CC:-cc} -O2 -Wall -Wextra -Werror $CFLAGS "$ROOT/tools/fluxvm-tcp-loader.c" -o /tmp/fluxvm-tcp-loader.$$ $LIBS
  ${CC:-cc} -O2 -Wall -Wextra -Werror $CFLAGS "$ROOT/tools/fluxvm-tcp-events.c" -o /tmp/fluxvm-tcp-events.$$ $LIBS
  rm -f /tmp/fluxvm-{xdp-shield-loader,shield-events,tcp-loader,tcp-events}.$$
else
  echo "SKIP real libbpf helper compilation: libbpf development package unavailable"
fi
echo "XDP Shield + TCP Intelligence static gates: PASS"
