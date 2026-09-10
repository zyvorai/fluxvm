#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/bpf}"
mkdir -p "$OUT"
command -v clang >/dev/null || { echo "clang required" >&2; exit 2; }
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) TARGET_ARCH=x86 ;;
  aarch64|arm64) TARGET_ARCH=arm64 ;;
  riscv64) TARGET_ARCH=riscv ;;
  s390x) TARGET_ARCH=s390 ;;
  ppc64le|ppc64) TARGET_ARCH=powerpc ;;
  *) echo "unsupported BPF target architecture: $ARCH" >&2; exit 2 ;;
esac
INC=()
if command -v cc >/dev/null 2>&1; then
  MULTIARCH="$(cc -print-multiarch 2>/dev/null || true)"
  [[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]] && INC+=("-I/usr/include/$MULTIARCH")
fi
clang -O2 -g -target bpf -D"__TARGET_ARCH_${TARGET_ARCH}" "${INC[@]}" \
  -I/usr/include -I"$ROOT/bpf" -Wall -Werror \
  -c "$ROOT/bpf/fluxvm_topology.bpf.c" -o "$OUT/fluxvm_topology.bpf.o"
echo "Set 8 BPF object: $OUT/fluxvm_topology.bpf.o"
