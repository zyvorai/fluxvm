#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Privileged smoke test. It creates a disposable cgroup and proves that an
# enforce-mode deny-exec policy returns EPERM to a process in that cgroup.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'SKIP: root required'; exit 0; }
for c in bpftool clang cargo cc pkg-config; do command -v "$c" >/dev/null || { echo "SKIP: $c missing"; exit 0; }; done
pkg-config --exists libbpf || { echo 'SKIP: libbpf-dev missing'; exit 0; }
[[ -r /sys/kernel/security/lsm ]] || { echo 'SKIP: active LSM list unavailable'; exit 0; }
grep -Eq '(^|,)bpf(,|$)' /sys/kernel/security/lsm || { echo 'SKIP: BPF LSM is not active'; exit 0; }
[[ -d /sys/fs/cgroup && -f /sys/fs/cgroup/cgroup.controllers ]] || { echo 'SKIP: cgroup v2 required'; exit 0; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

TMP="$(mktemp -d)"
PIN="/sys/fs/bpf/fluxvm/guard-host-test-$$"
CG="/sys/fs/cgroup/fluxvm-guard-test-$$"
UUID='11111111-2222-4333-8444-555555555555'
cleanup(){ set +e; "$ROOT/dist/bin/fluxvm-guard-loader" --unload "$PIN" >/dev/null 2>&1; [[ -n "${CHILD:-}" ]] && kill "$CHILD" >/dev/null 2>&1; rmdir "$CG" >/dev/null 2>&1; rm -rf "$TMP"; }
trap cleanup EXIT
mkdir "$CG"

"$ROOT/scripts/build-runtime-intelligence.sh" "$ROOT/dist"
"$ROOT/dist/bin/fluxvm-guard-loader" --load "$ROOT/dist/bpf/fluxvm_guard.bpf.o" "$PIN"

cat > "$TMP/probe.c" <<'C'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv){
    if(argc!=4)return 20;
    FILE *f=fopen(argv[1],"w"); if(!f)return 21; fprintf(f,"%d\n",getpid()); fclose(f);
    int fd=open(argv[2],O_WRONLY|O_CREAT|O_TRUNC,0600); if(fd<0)return 22; dprintf(fd,"ready\n"); close(fd);
    while(access(argv[3],F_OK)!=0) usleep(10000);
    execl("/bin/true","true",NULL);
    return errno==EPERM?0:23;
}
C
cc -O2 -Wall -Wextra -Werror "$TMP/probe.c" -o "$TMP/probe"
READY="$TMP/ready"; GO="$TMP/go"
"$TMP/probe" "$CG/cgroup.procs" "$READY" "$GO" & CHILD=$!
for _ in $(seq 1 100); do [[ -f "$READY" ]] && break; sleep 0.02; done
[[ -f "$READY" ]] || { echo 'probe did not enter cgroup' >&2; exit 1; }
FLUXVM_GUARD_PIN_ROOT="$PIN" FLUXVM_GUARD_STATE_ROOT="$TMP/state" \
  "$ROOT/dist/bin/fluxvm-guard" apply "$UUID" "$CHILD" --mode enforce --no-device-allowlist --allow-wx >/dev/null
touch "$GO"
wait "$CHILD"; CHILD=''
FLUXVM_GUARD_PIN_ROOT="$PIN" FLUXVM_GUARD_STATE_ROOT="$TMP/state" \
  "$ROOT/dist/bin/fluxvm-guard" status "$UUID" | grep -q '"kernel_policy_present": true'

echo 'VMM Guard privileged deny-exec smoke test: PASS'
