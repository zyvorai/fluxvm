#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
required="${FLUXVM_SCX_HOST_REQUIRED:-0}"
skip() { echo "SKIP: $*"; [[ "$required" != 1 ]]; }

[[ $EUID -eq 0 ]] || { skip 'root/CAP_SYS_NICE + BPF privileges required' || exit 1; exit 0; }
[[ -r /sys/kernel/sched_ext/state ]] || { skip 'kernel sched_ext unavailable' || exit 1; exit 0; }
[[ -r /sys/kernel/btf/vmlinux ]] || { skip 'kernel BTF unavailable' || exit 1; exit 0; }
for cmd in clang bpftool cc cargo pkg-config; do command -v "$cmd" >/dev/null || { skip "$cmd missing" || exit 1; exit 0; }; done
pkg-config --exists libbpf || { skip 'libbpf development package missing' || exit 1; exit 0; }

state="$(cat /sys/kernel/sched_ext/state 2>/dev/null || true)"
ops="$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || cat /sys/kernel/sched_ext/ops 2>/dev/null || true)"
if [[ "$state" == enabled && "$ops" != fluxvm_scx ]]; then
  skip "another sched_ext scheduler is active: ${ops:-unknown}" || exit 1
  exit 0
fi

TMP="$(mktemp -d)"
PIN="/sys/fs/bpf/fluxvm-scx-test-$$"
STATE="$TMP/state"
DIST="$TMP/dist"
WORKER_PID=''
UUID='11111111-1111-4111-8111-111111111111'
cleanup() {
  set +e
  if [[ -x "$ROOT/target/release/fluxvm-scx" ]]; then
    FLUXVM_SCX_PIN_ROOT="$PIN" FLUXVM_SCX_STATE_ROOT="$STATE" \
      FLUXVM_SCX_LOADER="$DIST/bin/fluxvm-scx-loader" \
      FLUXVM_SCX_TASKCTL="$DIST/bin/fluxvm-scx-taskctl" \
      FLUXVM_SCX_EVENTS="$DIST/bin/fluxvm-scx-events" \
      FLUXVM_SCX_OBJECT="$DIST/bpf/fluxvm_scx.bpf.o" \
      "$ROOT/target/release/fluxvm-scx" rollback "$UUID" >/dev/null 2>&1 || true
  fi
  [[ -z "$WORKER_PID" ]] || kill "$WORKER_PID" >/dev/null 2>&1 || true
  "$DIST/bin/fluxvm-scx-loader" stop "$PIN" >/dev/null 2>&1 || true
  rm -rf "$PIN" "$TMP"
}
trap cleanup EXIT

if ! FLUXVM_SCX_INCLUDE="${FLUXVM_SCX_INCLUDE:-}" "$ROOT/scripts/build-scx-scheduler.sh" "$DIST/bpf" "$DIST/bin"; then
  skip 'target sched_ext object could not be built; provide matching FLUXVM_SCX_INCLUDE' || exit 1
  exit 0
fi
cargo build -p fluxvm-intelligence --bin fluxvm-scx

cat > "$TMP/vcpu.c" <<'C'
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void sig(int n){(void)n;stop=1;}
static void *vcpu(void *arg){char n[16];snprintf(n,sizeof(n),"CPU %ld/KVM",(long)arg);pthread_setname_np(pthread_self(),n);volatile uint64_t x=1;while(!stop){for(int i=0;i<100000;i++)x=x*1664525u+1013904223u;sched_yield();}return (void *)(uintptr_t)x;}
int main(void){pthread_t a,b;signal(SIGTERM,sig);signal(SIGINT,sig);pthread_create(&a,0,vcpu,(void *)0L);pthread_create(&b,0,vcpu,(void *)1L);while(!stop)sleep(1);pthread_join(a,0);pthread_join(b,0);return 0;}
C
cc -O2 -pthread -Wall -Wextra -Werror "$TMP/vcpu.c" -o "$TMP/vcpu"
"$TMP/vcpu" & WORKER_PID=$!
sleep 1
mkdir -p "$STATE"

SCX=(env FLUXVM_SCX_PIN_ROOT="$PIN" FLUXVM_SCX_STATE_ROOT="$STATE" FLUXVM_SCX_LOADER="$DIST/bin/fluxvm-scx-loader" FLUXVM_SCX_TASKCTL="$DIST/bin/fluxvm-scx-taskctl" FLUXVM_SCX_EVENTS="$DIST/bin/fluxvm-scx-events" FLUXVM_SCX_OBJECT="$DIST/bpf/fluxvm_scx.bpf.o" "$ROOT/target/release/fluxvm-scx")
"${SCX[@]}" probe > "$TMP/probe.json"
python3 - "$TMP/probe.json" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))
assert p['supported_for_apply'], p
PY
"${SCX[@]}" plan "$UUID" "$WORKER_PID" --class latency --output "$TMP/plan.json" >/dev/null
"${SCX[@]}" apply "$TMP/plan.json" > "$TMP/receipt.json"
python3 - "$TMP/plan.json" "$DIST/bin/fluxvm-scx-taskctl" <<'PY'
import json,subprocess,sys
p=json.load(open(sys.argv[1]))
assert len(p['tasks'])==2, p
for t in p['tasks']:
    s=json.loads(subprocess.check_output([sys.argv[2],'get',str(t['tid'])]))
    assert s['policy']==7, s
    assert s['cpus']==str(t['target_cpu']), (s,t)
PY
sleep 2
"${SCX[@]}" status "$UUID" > "$TMP/status.json"
python3 - "$TMP/status.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
assert s['probe']['sched_ext_state']=='enabled', s
assert s['probe']['current_ops']=='fluxvm_scx', s
assert s['stats']['enqueues']>0, s
assert s['stats']['running_calls']>0, s
PY
"${SCX[@]}" metrics "$UUID" | grep -q 'fluxvm_scx_enqueues_total'
"${SCX[@]}" rollback "$UUID"
python3 - "$TMP/plan.json" "$DIST/bin/fluxvm-scx-taskctl" <<'PY'
import json,subprocess,sys
p=json.load(open(sys.argv[1]))
for t in p['tasks']:
    s=json.loads(subprocess.check_output([sys.argv[2],'get',str(t['tid'])]))
    assert s['policy']==t['old']['policy'], (s,t)
    assert s['priority']==t['old']['priority'], (s,t)
    assert s['cpus']==t['old']['cpus'], (s,t)
PY

echo 'Sentinel Set 11E sched_ext privileged host test: PASS'
