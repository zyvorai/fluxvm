#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: root required'; exit 0; }
for c in bpftool clang cc pkg-config taskset python3; do command -v "$c" >/dev/null || { echo "SKIP: $c missing"; exit 0; }; done
pkg-config --exists libbpf || { echo 'SKIP: libbpf-dev missing'; exit 0; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || { echo 'SKIP: bpffs unavailable'; exit 0; }
[[ -e /sys/kernel/tracing/events/sched/sched_switch/id || -e /sys/kernel/debug/tracing/events/sched/sched_switch/id ]] || { echo 'SKIP: sched_switch unavailable'; exit 0; }
TMP="$(mktemp -d)"; PIN="/sys/fs/bpf/fluxvm-set8-test-$$"; STATE="$TMP/state"; trap 'kill ${VMM_PID:-0} 2>/dev/null || true; rm -rf "$PIN" "$TMP"' EXIT
"$ROOT/scripts/build-topology-intelligence.sh" "$TMP/bpf"
cc -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-topology-loader.c" -o "$TMP/loader" $(pkg-config --cflags --libs libbpf)
cat > "$TMP/vmm.c" <<'C'
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void *run(void *p){long i=(long)p;char n[16];snprintf(n,sizeof(n),"CPU %ld/KVM",i);pthread_setname_np(pthread_self(),n);volatile unsigned long x=1;for(;;){for(unsigned long j=0;j<100000;j++)x=x*1664525+1013904223;sched_yield();}return NULL;}
int main(void){pthread_t a,b;if(pthread_create(&a,NULL,run,(void*)0)||pthread_create(&b,NULL,run,(void*)1))return 1;for(;;)pause();}
C
cc -O2 -pthread "$TMP/vmm.c" -o "$TMP/vmm"
"$TMP/loader" load "$TMP/bpf/fluxvm_topology.bpf.o" "$PIN"
"$TMP/vmm" & VMM_PID=$!
sleep 0.2
UUID=00000000-0000-0000-0000-000000000008
FLUXVM_TOPOLOGY_PIN_ROOT="$PIN" cargo run -q -p fluxvm-intelligence --bin fluxvm-topology -- register "$UUID" "$VMM_PID" > "$TMP/register.json"
sleep 1
FLUXVM_TOPOLOGY_PIN_ROOT="$PIN" cargo run -q -p fluxvm-intelligence --bin fluxvm-topology -- snapshot "$UUID" "$VMM_PID" > "$TMP/snapshot.json"
python3 - "$TMP/snapshot.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1])); assert len(s['vcpu_threads'])==2; assert sum(v['run_ns'] for v in s['vcpus'])>0
print('vCPU runtime attribution: PASS')
PY
FLUXVM_TOPOLOGY_PIN_ROOT="$PIN" cargo run -q -p fluxvm-intelligence --bin fluxvm-topology -- plan "$UUID" "$VMM_PID" "$TMP/plan.json" >/dev/null
FLUXVM_TOPOLOGY_STATE_ROOT="$STATE" cargo run -q -p fluxvm-intelligence --bin fluxvm-topology -- apply "$TMP/plan.json" >/dev/null
[[ -f "$STATE/$UUID.receipt.json" ]]
FLUXVM_TOPOLOGY_STATE_ROOT="$STATE" cargo run -q -p fluxvm-intelligence --bin fluxvm-topology -- rollback "$UUID" >/dev/null
[[ ! -e "$STATE/$UUID.receipt.json" ]]
"$TMP/loader" unload "$PIN"
echo 'Set 8 privileged host test: PASS'
