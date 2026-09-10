#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_OUT="${1:-$ROOT/dist/bpf}"
BIN_OUT="${2:-$ROOT/dist/bin}"
GEN="$ROOT/target/scx-gen"
mkdir -p "$BPF_OUT" "$BIN_OUT" "$GEN"

command -v clang >/dev/null || { echo "clang is required" >&2; exit 2; }
command -v bpftool >/dev/null || { echo "bpftool is required" >&2; exit 2; }
command -v pkg-config >/dev/null || { echo "pkg-config is required" >&2; exit 2; }
pkg-config --exists libbpf || { echo "libbpf development package is required" >&2; exit 2; }
[[ -r /sys/kernel/btf/vmlinux ]] || { echo "kernel BTF /sys/kernel/btf/vmlinux is required" >&2; exit 2; }
[[ -r /sys/kernel/sched_ext/state ]] || { echo "target kernel does not expose sched_ext; CONFIG_SCHED_CLASS_EXT is required" >&2; exit 2; }

find_scx_include() {
  if [[ -n "${FLUXVM_SCX_INCLUDE:-}" && -f "$FLUXVM_SCX_INCLUDE/scx/common.bpf.h" ]]; then
    printf '%s\n' "$FLUXVM_SCX_INCLUDE"
    return 0
  fi
  local candidate
  for candidate in \
    "/lib/modules/$(uname -r)/build/tools/sched_ext/include" \
    "/usr/src/linux/tools/sched_ext/include" \
    "/usr/src/linux-source/tools/sched_ext/include"; do
    if [[ -f "$candidate/scx/common.bpf.h" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  while IFS= read -r candidate; do
    if [[ -f "$candidate/scx/common.bpf.h" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(find /usr/src -maxdepth 5 -type d -path '*/tools/sched_ext/include' 2>/dev/null | sort -r)
  return 1
}

SCX_INCLUDE="$(find_scx_include || true)"
if [[ -z "$SCX_INCLUDE" ]]; then
  cat >&2 <<'MSG'
matching Linux tools/sched_ext/include headers are required.
Set FLUXVM_SCX_INCLUDE=/path/to/linux/tools/sched_ext/include after installing
or checking out the source for the target kernel. sched_ext has an unstable BPF
ABI, so FluxVM intentionally does not compile this object against unrelated
headers.
MSG
  exit 2
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$GEN/vmlinux.h"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) TARGET_ARCH=x86 ;;
  aarch64) TARGET_ARCH=arm64 ;;
  armv7*|armv8l) TARGET_ARCH=arm ;;
  s390x) TARGET_ARCH=s390 ;;
  ppc64le|ppc64) TARGET_ARCH=powerpc ;;
  riscv64) TARGET_ARCH=riscv ;;
  *) echo "unsupported BPF target architecture: $ARCH" >&2; exit 2 ;;
esac

CLANG_FLAGS=(
  -O2 -g -target bpf
  "-D__TARGET_ARCH_${TARGET_ARCH}"
  -Wall -Wextra -Werror
  -I"$GEN"
  -I"$SCX_INCLUDE"
)
# Multiarch libc headers are needed by some distro libbpf headers.
MULTIARCH="$(cc -print-multiarch 2>/dev/null || true)"
if [[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]]; then
  CLANG_FLAGS+=("-I/usr/include/$MULTIARCH")
fi
clang "${CLANG_FLAGS[@]}" -c "$ROOT/bpf/fluxvm_scx.bpf.c" -o "$BPF_OUT/fluxvm_scx.bpf.o"

CFLAGS=( -O2 -g -Wall -Wextra -Werror )
LIBBPF=( $(pkg-config --cflags --libs libbpf) )
${CC:-cc} "${CFLAGS[@]}" "$ROOT/tools/fluxvm-scx-loader.c" -o "$BIN_OUT/fluxvm-scx-loader" "${LIBBPF[@]}"
${CC:-cc} "${CFLAGS[@]}" "$ROOT/tools/fluxvm-scx-events.c" -o "$BIN_OUT/fluxvm-scx-events" "${LIBBPF[@]}"
${CC:-cc} "${CFLAGS[@]}" "$ROOT/tools/fluxvm-scx-taskctl.c" -o "$BIN_OUT/fluxvm-scx-taskctl"

echo "sched_ext object: $BPF_OUT/fluxvm_scx.bpf.o"
echo "sched_ext helpers: $BIN_OUT/fluxvm-scx-{loader,events,taskctl}"
echo "compiled against sched_ext headers: $SCX_INCLUDE"
