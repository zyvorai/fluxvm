#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/bpf}"
BIN="${2:-$ROOT/dist/bin}"
mkdir -p "$OUT" "$BIN"
command -v clang >/dev/null || { echo "clang required" >&2; exit 2; }
command -v pkg-config >/dev/null || { echo "pkg-config required" >&2; exit 2; }
pkg-config --exists libbpf || { echo "libbpf development package required" >&2; exit 2; }
pkg-config --exists libxdp || { echo "libxdp development package required" >&2; exit 2; }
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
MULTIARCH="$(${CC:-cc} -print-multiarch 2>/dev/null || true)"
[[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]] && INC+=("-I/usr/include/$MULTIARCH")
clang -O2 -g -target bpf -D"__TARGET_ARCH_${TARGET_ARCH}" "${INC[@]}" -I/usr/include -I"$ROOT/bpf" -Wall -Werror -c "$ROOT/bpf/fluxvm_afxdp.bpf.c" -o "$OUT/fluxvm_afxdp.bpf.o"
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-afxdp-loader.c" -o "$BIN/fluxvm-afxdp-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-afxdp-worker.c" -o "$BIN/fluxvm-afxdp-worker" $(pkg-config --cflags --libs libxdp libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-afxdp-events.c" -o "$BIN/fluxvm-afxdp-events" $(pkg-config --cflags --libs libbpf)
echo "Set 9 AF_XDP artifacts: $OUT/fluxvm_afxdp.bpf.o $BIN/fluxvm-afxdp-loader $BIN/fluxvm-afxdp-worker $BIN/fluxvm-afxdp-events"
