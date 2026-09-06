#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Build fluxvm_tc.bpf.o and fluxvm_xdp.bpf.o into dist/bpf/ (or OUT_DIR).
# Docs: docs/network-fabric.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist/bpf}"
CLANG="${CLANG:-clang}"
mkdir -p "$OUT_DIR"

case "$(uname -m)" in
  x86_64) BPF_ARCH=x86 ;;
  aarch64|arm64) BPF_ARCH=arm64 ;;
  s390x) BPF_ARCH=s390 ;;
  ppc64le) BPF_ARCH=powerpc ;;
  riscv64) BPF_ARCH=riscv ;;
  *) echo "unsupported BPF build architecture: $(uname -m)" >&2; exit 2 ;;
esac

CFLAGS=(
  -target bpf
  -O2
  -g
  -Wall
  -Werror
  "-D__TARGET_ARCH_${BPF_ARCH}"
)

# Debian/Ubuntu place asm/types.h under the GCC multiarch include path.
if command -v gcc >/dev/null 2>&1; then
  MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
  if [[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]]; then
    CFLAGS+=("-I/usr/include/$MULTIARCH")
  fi
fi

for src in fluxvm_tc fluxvm_xdp; do
  "$CLANG" "${CFLAGS[@]}" -c "$ROOT/bpf/${src}.bpf.c" -o "$OUT_DIR/${src}.bpf.o"
done

# Keep BTF sections intact. bpftool/libbpf uses the BTF-described map
# definitions emitted by modern clang. The objects are small enough that
# stripping them buys little and can vary across distro LLVM versions.

echo "built:"
echo "  $OUT_DIR/fluxvm_tc.bpf.o"
echo "  $OUT_DIR/fluxvm_xdp.bpf.o"
