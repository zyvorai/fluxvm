#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$ROOT/scripts/build-runtime-intelligence.sh"
bash -n "$ROOT/scripts/install-runtime-intelligence.sh"
bash -n "$ROOT/scripts/test-flight-recorder-host.sh"

grep -q 'kvm_exit_hist SEC(".maps")' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'latency_hist SEC(".maps")' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'flight_events SEC(".maps")' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'kprobe/blk_mq_start_request' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'kprobe/blk_account_io_done' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'kprobe/vhost_work_queue' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'tracked_cgroups SEC(".maps")' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'pub fn trace_events' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q 'pub struct FlightRecorderSnapshot' "$ROOT/crates/fluxvm-intelligence/src/lib.rs"
grep -q '/v1/intelligence/vms/{id}/flight' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
grep -q 'fluxvm_intel_kvm_exit_reason_total' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
grep -q 'ring_buffer__new' "$ROOT/tools/fluxvm-flight-reader.c"
grep -q 'kernel_symbol_available' "$ROOT/tools/fluxvm-intelligence-loader.c"
grep -q 'Trace {' "$ROOT/crates/fluxvm-cli/src/main.rs"

python3 - "$ROOT" <<'PY'
import pathlib, sys, tomllib
root=pathlib.Path(sys.argv[1])
tomllib.loads((root/'crates/fluxvm-intelligence/Cargo.toml').read_text())
# Cheap lexical sanity catches truncated generated sources without pretending
# to replace rustc/clang.
for path in [root/'crates/fluxvm-intelligence/src/lib.rs', root/'crates/fluxvm-intelligence/src/main.rs']:
    s=path.read_text()
    stack=[]; pairs={')':'(',']':'[','}':'{'}
    i=0; quote=None; esc=False; line=False; block=0
    while i < len(s):
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
        if c=="'" and i+2 < len(s) and s[i+2]=="'": i+=3; continue
        if c=="'" and n=='\\' and i+3 < len(s) and s[i+3]=="'": i+=4; continue
        if c in '([{': stack.append(c)
        elif c in ')]}':
            if not stack or stack.pop()!=pairs[c]: raise SystemExit(f'unbalanced {path}: {c} at {i}')
        i+=1
    if stack or quote or block: raise SystemExit(f'unterminated lexical construct in {path}')
print('Rust/TOML/YAML portable sanity: PASS')
PY

if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT" && cargo test -p fluxvm-intelligence -p fluxvm-cli)
else
  echo "SKIP cargo tests: cargo unavailable"
fi

if [[ -f /usr/include/bpf/bpf_helpers.h ]] && command -v clang >/dev/null 2>&1; then
  "$ROOT/scripts/build-ebpf.sh" >/dev/null
else
  echo "SKIP BPF target build: clang/libbpf development headers unavailable"
fi

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf; then
  ${CC:-cc} -O2 -Wall -Wextra -Werror "$ROOT/tools/fluxvm-intelligence-loader.c" -o /tmp/fluxvm-intelligence-loader-set4 $(pkg-config --cflags --libs libbpf)
  ${CC:-cc} -O2 -Wall -Wextra -Werror "$ROOT/tools/fluxvm-flight-reader.c" -o /tmp/fluxvm-flight-reader-set4 $(pkg-config --cflags --libs libbpf)
else
  echo "SKIP libbpf helper build: libbpf development package unavailable"
fi

echo "Flight Recorder portable gates: PASS"
