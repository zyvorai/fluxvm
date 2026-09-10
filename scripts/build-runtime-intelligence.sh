#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
mkdir -p "$OUT/bin" "$OUT/bpf"
"$ROOT/scripts/build-ebpf.sh" "$OUT/bpf"
"$ROOT/scripts/build-vmm-guard.sh" "$OUT/bpf"
"$ROOT/scripts/build-network-intelligence.sh" "$OUT/bpf"
"$ROOT/scripts/build-memory-profiler.sh" "$OUT/bpf"
command -v pkg-config >/dev/null || { echo "pkg-config required" >&2; exit 2; }
pkg-config --exists libbpf || { echo "libbpf development package required" >&2; exit 2; }
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-intelligence-loader.c" -o "$OUT/bin/fluxvm-intelligence-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcx.c" -o "$OUT/bin/fluxvm-tcx" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-flight-reader.c" -o "$OUT/bin/fluxvm-flight-reader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-guard-loader.c" -o "$OUT/bin/fluxvm-guard-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-guard-events.c" -o "$OUT/bin/fluxvm-guard-events" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-xdp-shield-loader.c" -o "$OUT/bin/fluxvm-xdp-shield-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-shield-events.c" -o "$OUT/bin/fluxvm-shield-events" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcp-loader.c" -o "$OUT/bin/fluxvm-tcp-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-tcp-events.c" -o "$OUT/bin/fluxvm-tcp-events" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-memprof-loader.c" -o "$OUT/bin/fluxvm-memprof-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-memprof-events.c" -o "$OUT/bin/fluxvm-memprof-events" $(pkg-config --cflags --libs libbpf)
cargo build --release -p fluxvm-intelligence --bins
for bin in fluxvm-intelligence fluxvm-guard fluxvm-qos fluxvm-shield fluxvm-tcpintel fluxvm-netintel fluxvm-memprof; do cp "$ROOT/target/release/$bin" "$OUT/bin/$bin"; done
echo "runtime intelligence + guard + Set 6 network intelligence + Set 7 memory profiler artifacts are in $OUT/bin and $OUT/bpf"
