#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for f in "$ROOT/scripts/build-ebpf.sh" "$ROOT/scripts/build-runtime-intelligence.sh" "$ROOT/scripts/install-runtime-intelligence.sh"; do bash -n "$f"; done
grep -q 'crates/fluxvm-intelligence' "$ROOT/Cargo.toml"
grep -q 'SEC("tracepoint/kvm/kvm_exit")' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'SEC("tracepoint/sched/sched_switch")' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'tracked_tgids' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'vm_stats' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'kvm_exit_hist' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q 'flight_events' "$ROOT/bpf/fluxvm_intelligence.bpf.c"
grep -q '/v1/intelligence/vms/{id}' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
grep -q 'fluxvm_intel_kvm_exits_total' "$ROOT/crates/fluxvm-intelligence/src/main.rs"
if command -v cargo >/dev/null 2>&1; then cargo test -p fluxvm-intelligence; else echo 'SKIP cargo: cargo not installed'; fi
if [[ -f /usr/include/bpf/bpf_helpers.h ]]; then "$ROOT/scripts/build-ebpf.sh" /tmp/fluxvm-intel-bpf-test; else echo 'SKIP BPF compile: libbpf development headers not installed'; fi
if [[ -f /usr/include/bpf/libbpf.h ]] && command -v pkg-config >/dev/null && pkg-config --exists libbpf; then cc -fsyntax-only -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$ROOT/tools/fluxvm-intelligence-loader.c" "$ROOT/tools/fluxvm-flight-reader.c"; else echo 'SKIP helper compile: libbpf development headers not installed'; fi
echo 'runtime-intelligence static gates: PASS'
