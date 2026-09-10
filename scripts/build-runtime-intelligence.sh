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
"$ROOT/scripts/build-topology-intelligence.sh" "$OUT/bpf"
"$ROOT/scripts/build-afxdp-fastpath.sh" "$OUT/bpf" "$OUT/bin"
"$ROOT/scripts/build-quiclb.sh" "$OUT/bpf" "$OUT/bin"
if [[ "${FLUXVM_BUILD_SCX:-auto}" != "off" ]]; then
  if ! "$ROOT/scripts/build-scx-scheduler.sh" "$OUT/bpf" "$OUT/bin"; then
    if [[ "${FLUXVM_BUILD_SCX:-auto}" == "required" ]]; then
      echo "Sentinel Set 11E sched_ext build was required and failed" >&2
      exit 2
    fi
    echo "optional Sentinel Set 11E sched_ext target build skipped; set FLUXVM_BUILD_SCX=required to make this fatal" >&2
  fi
fi
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
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-topology-loader.c" -o "$OUT/bin/fluxvm-topology-loader" $(pkg-config --cflags --libs libbpf)
${CC:-cc} -O2 -g -Wall -Wextra -Werror "$ROOT/tools/fluxvm-topology-events.c" -o "$OUT/bin/fluxvm-topology-events" $(pkg-config --cflags --libs libbpf)
cargo build --release -p fluxvm-intelligence --bins
for bin in fluxvm-intelligence fluxvm-guard fluxvm-qos fluxvm-shield fluxvm-tcpintel fluxvm-netintel fluxvm-memprof fluxvm-topology fluxvm-afxdp fluxvm-quiclb fluxvm-scx; do cp "$ROOT/target/release/$bin" "$OUT/bin/$bin"; done
echo "runtime intelligence + guard + Set 6 network intelligence + Set 7 memory profiler + Set 8 topology intelligence + Set 9 AF_XDP fast-path + Set 10 QUIC LB + Sentinel Set 11E sched_ext artifacts are in $OUT/bin and $OUT/bpf"
