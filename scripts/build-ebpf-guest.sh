#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Build bpf/fluxvm_guest_cgroup.bpf.o (Set 8S) and bpf/fluxvm_guest_lsm.bpf.o
# (Set 9S) for embedding into fluxvm-container-agent (crates/fluxvm-
# container-agent/build.rs calls this). No map-tier variants -- guest
# container counts per Pod are small, unlike the node-wide Service Fabric
# maps scripts/build-ebpf.sh tiers for.
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

# Same Debian/Ubuntu asm/types.h workaround as scripts/build-ebpf.sh.
if command -v gcc >/dev/null 2>&1; then
  MULTIARCH="$(gcc -print-multiarch 2>/dev/null || true)"
  if [[ -n "$MULTIARCH" && -d "/usr/include/$MULTIARCH" ]]; then
    CFLAGS+=("-I/usr/include/$MULTIARCH")
  fi
fi

"$CLANG" "${CFLAGS[@]}" -c "$ROOT/bpf/fluxvm_guest_cgroup.bpf.c" -o "$OUT_DIR/fluxvm_guest_cgroup.bpf.o"
"$CLANG" "${CFLAGS[@]}" -c "$ROOT/bpf/fluxvm_guest_lsm.bpf.c" -o "$OUT_DIR/fluxvm_guest_lsm.bpf.o"

echo "built: $OUT_DIR/fluxvm_guest_cgroup.bpf.o $OUT_DIR/fluxvm_guest_lsm.bpf.o"
