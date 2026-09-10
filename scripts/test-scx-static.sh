#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need() { grep -Fq -- "$2" "$ROOT/$1" || { echo "missing Set-11E marker '$2' in $1" >&2; exit 1; }; }

need bpf/fluxvm_scx.bpf.c 'SCX_OPS_SWITCH_PARTIAL'
need bpf/fluxvm_scx.bpf.c 'profile->tgid != tgid'
need bpf/fluxvm_scx.bpf.c 'scx_bpf_dsq_insert_vtime'
need bpf/fluxvm_scx.bpf.c 'scx_bpf_dsq_move_to_local'
need bpf/fluxvm_scx.bpf.c 'scx_bpf_task_set_dsq_vtime'
need bpf/fluxvm_scx.bpf.c 'latency_target_ns'
need bpf/fluxvm_scx.bpf.c 'BPF_MAP_TYPE_RINGBUF'
need crates/fluxvm-intelligence/src/scx.rs 'topology::discover_vcpus'
need crates/fluxvm-intelligence/src/scx.rs 'topology::snapshot'
need crates/fluxvm-intelligence/src/scx.rs 'possible restart or TID reuse'
need crates/fluxvm-intelligence/src/scx.rs 'scheduler_started_by_apply'
need crates/fluxvm-intelligence/src/scx.rs 'already-converted vCPUs were rolled back'
need crates/fluxvm-intelligence/src/scx.rs 'another sched_ext scheduler is already active'
need crates/fluxvm-intelligence/src/bin/fluxvm-scx.rs 'Some("reconcile")'
need tools/fluxvm-scx-loader.c 'bpf_map__attach_struct_ops'
need tools/fluxvm-scx-loader.c 'bpf_link__pin'
need tools/fluxvm-scx-taskctl.c 'SCHED_EXT'
need tools/fluxvm-scx-taskctl.c 'sched_setaffinity'
need scripts/build-scx-scheduler.sh 'tools/sched_ext/include'
need scripts/build-scx-scheduler.sh '/sys/kernel/btf/vmlinux'
need scripts/build-runtime-intelligence.sh 'FLUXVM_BUILD_SCX'
need docs/scx-vm-scheduler.md 'partial switching'
need packaging/systemd/fluxvm-scx.service 'fluxvm-scx serve'
if grep -Eq 'ExecStart=.*( apply | plan |start )' "$ROOT/packaging/systemd/fluxvm-scx.service"; then
  echo 'fluxvm-scx service must stay read-only and must not auto-activate the scheduler' >&2
  exit 1
fi

for f in \
  scripts/build-scx-scheduler.sh \
  scripts/test-scx-static.sh \
  scripts/test-scx-host.sh \
  scripts/build-runtime-intelligence.sh \
  scripts/install-runtime-intelligence.sh; do
  bash -n "$ROOT/$f"
done

if command -v cc >/dev/null; then
  cc -std=gnu11 -Wall -Wextra -Werror -fsyntax-only "$ROOT/tools/fluxvm-scx-taskctl.c"
else
  echo 'SKIP taskctl C compile: cc missing'
fi

if command -v pkg-config >/dev/null && pkg-config --exists libbpf 2>/dev/null; then
  CFLAGS="$(pkg-config --cflags libbpf)"
  # shellcheck disable=SC2086
  ${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -fsyntax-only $CFLAGS "$ROOT/tools/fluxvm-scx-loader.c"
  # shellcheck disable=SC2086
  ${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -fsyntax-only $CFLAGS "$ROOT/tools/fluxvm-scx-events.c"
else
  echo 'SKIP libbpf helper compile: libbpf development package missing'
fi

python3 - "$ROOT/crates/fluxvm-intelligence/src/scx.rs" "$ROOT/crates/fluxvm-intelligence/src/bin/fluxvm-scx.rs" <<'PY'
import sys
from pathlib import Path
for name in sys.argv[1:]:
    text=Path(name).read_text()
    stack=[]
    pairs={'}':'{',')':'(',']':'['}
    quote=None; esc=False; line=False; block=0; i=0
    while i < len(text):
        c=text[i]; n=text[i+1] if i+1<len(text) else ''
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
        if c == '"': quote=c; i+=1; continue
        if c in '({[': stack.append(c)
        elif c in ')}]':
            if not stack or stack.pop()!=pairs[c]: raise SystemExit(f'{name}: unbalanced delimiter {c}')
        i+=1
    if stack or quote or block: raise SystemExit(f'{name}: unterminated Rust structure')
print('Rust structural gates: PASS')
PY

if command -v cargo >/dev/null; then
  (cd "$ROOT" && cargo test -p fluxvm-intelligence scx -- --nocapture)
else
  echo 'SKIP cargo tests: cargo missing'
fi

if [[ -r /sys/kernel/sched_ext/state && -r /sys/kernel/btf/vmlinux ]] && command -v bpftool >/dev/null && command -v clang >/dev/null; then
  if FLUXVM_BUILD_SCX=required "$ROOT/scripts/build-scx-scheduler.sh" "${TMPDIR:-/tmp}/fluxvm-scx-static-bpf" "${TMPDIR:-/tmp}/fluxvm-scx-static-bin"; then
    echo 'target-kernel sched_ext compile: PASS'
  elif [[ "${FLUXVM_SCX_STATIC_REQUIRE_TARGET_BUILD:-0}" == 1 ]]; then
    exit 1
  else
    echo 'SKIP target-kernel sched_ext compile: matching tools/sched_ext headers unavailable'
  fi
else
  echo 'SKIP target-kernel sched_ext compile: sched_ext/BTF/bpftool/clang unavailable'
fi

echo 'Sentinel Set 11E sched_ext static gates: PASS'
