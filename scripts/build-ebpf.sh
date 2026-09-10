#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Build fluxvm_tc.bpf.o and fluxvm_xdp.bpf.o into dist/bpf/ (or OUT_DIR).
# Service Fabric objects are also emitted as map-tier variants
# (fluxvm_service_tier_{S,M,L}.bpf.o and matching xdp/connect ELFs).
# Docs: docs/network-fabric.md · docs/service-fabric-phase6.md
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

# Service programs exceed clang 18's default 512-byte BPF stack verifier view;
# raise the compile-time stack size so Maglev/NAT/policy frames fit (runtime
# verifier still enforces the kernel limit via per-CPU scratch where needed).
SERVICE_CFLAGS=("${CFLAGS[@]}" -mllvm -bpf-stack-size=768)

for src in fluxvm_tc fluxvm_xdp fluxvm_qemu_device fluxvm_qemu_egress; do
  "$CLANG" "${CFLAGS[@]}" -c "$ROOT/bpf/${src}.bpf.c" -o "$OUT_DIR/${src}.bpf.o"
done

# Default M objects keep stable names (fluxvm_service.bpf.o, …).
for src in fluxvm_service fluxvm_service_xdp fluxvm_service_connect; do
  "$CLANG" "${SERVICE_CFLAGS[@]}" -DFLUXVM_MAP_TIER=M \
    -c "$ROOT/bpf/${src}.bpf.c" -o "$OUT_DIR/${src}.bpf.o"
done

# Explicit S/M/L tier ELFs for map_tier object selection.
for tier in S M L; do
  for src in fluxvm_service fluxvm_service_xdp fluxvm_service_connect; do
    "$CLANG" "${SERVICE_CFLAGS[@]}" -DFLUXVM_MAP_TIER="${tier}" \
      -c "$ROOT/bpf/${src}.bpf.c" \
      -o "$OUT_DIR/${src}_tier_${tier}.bpf.o"
  done
done

# Keep BTF sections intact. bpftool/libbpf uses the BTF-described map
# definitions emitted by modern clang. The objects are small enough that
# stripping them buys little and can vary across distro LLVM versions.

echo "built:"
echo "  $OUT_DIR/fluxvm_tc.bpf.o"
echo "  $OUT_DIR/fluxvm_xdp.bpf.o"
echo "  $OUT_DIR/fluxvm_qemu_device.bpf.o"
echo "  $OUT_DIR/fluxvm_qemu_egress.bpf.o"
echo "  $OUT_DIR/fluxvm_service.bpf.o  (default M)"
echo "  $OUT_DIR/fluxvm_service_xdp.bpf.o  (default M)"
echo "  $OUT_DIR/fluxvm_service_connect.bpf.o  (default M)"
for tier in S M L; do
  echo "  $OUT_DIR/fluxvm_service_tier_${tier}.bpf.o"
  echo "  $OUT_DIR/fluxvm_service_xdp_tier_${tier}.bpf.o"
  echo "  $OUT_DIR/fluxvm_service_connect_tier_${tier}.bpf.o"
done
