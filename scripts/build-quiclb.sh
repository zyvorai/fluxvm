#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/bpf}"; BIN="${2:-$ROOT/dist/bin}"; mkdir -p "$OUT" "$BIN"
command -v clang >/dev/null || { echo "clang required" >&2; exit 2; }
command -v pkg-config >/dev/null || { echo "pkg-config required" >&2; exit 2; }
pkg-config --exists libbpf || { echo "libbpf development package required" >&2; exit 2; }
ARCH="$(uname -m)"; case "$ARCH" in x86_64) A=x86;; aarch64|arm64) A=arm64;; riscv64) A=riscv;; s390x) A=s390;; ppc64le|ppc64) A=powerpc;; *) echo "unsupported BPF target: $ARCH" >&2; exit 2;; esac
INC=(); MA="$(${CC:-cc} -print-multiarch 2>/dev/null || true)"; [[ -n "$MA" && -d "/usr/include/$MA" ]] && INC+=("-I/usr/include/$MA")
clang -O2 -g -target bpf -D"__TARGET_ARCH_${A}" "${INC[@]}" -I/usr/include -I"$ROOT/bpf" -Wall -Werror -c "$ROOT/bpf/fluxvm_quiclb.bpf.c" -o "$OUT/fluxvm_quiclb.bpf.o"
clang -O2 -g -target bpf -D"__TARGET_ARCH_${A}" -DFLUXVM_QUICLB_OFFLOAD_PROFILE "${INC[@]}" -I/usr/include -I"$ROOT/bpf" -Wall -Werror -c "$ROOT/bpf/fluxvm_quiclb.bpf.c" -o "$OUT/fluxvm_quiclb_hw.bpf.o"
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-quiclb-loader.c" -o "$BIN/fluxvm-quiclb-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-quiclb-events.c" -o "$BIN/fluxvm-quiclb-events" $(pkg-config --cflags --libs libbpf)
echo "Set 10 QUIC LB artifacts built in $OUT and $BIN"
