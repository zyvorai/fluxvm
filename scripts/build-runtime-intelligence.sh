#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
mkdir -p "$OUT/bin" "$OUT/bpf"
"$ROOT/scripts/build-ebpf.sh" "$OUT/bpf"
command -v pkg-config >/dev/null || { echo "pkg-config required" >&2; exit 2; }
pkg-config --exists libbpf || { echo "libbpf development package required" >&2; exit 2; }
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-intelligence-loader.c" -o "$OUT/bin/fluxvm-intelligence-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcx.c" -o "$OUT/bin/fluxvm-tcx" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-flight-reader.c" -o "$OUT/bin/fluxvm-flight-reader" $(pkg-config --cflags --libs libbpf)
cargo build --release -p fluxvm-intelligence
cp "$ROOT/target/release/fluxvm-intelligence" "$OUT/bin/fluxvm-intelligence"
echo "runtime intelligence artifacts: $OUT/bin/fluxvm-intelligence $OUT/bin/fluxvm-intelligence-loader $OUT/bin/fluxvm-tcx $OUT/bin/fluxvm-flight-reader $OUT/bpf/fluxvm_intelligence.bpf.o"
