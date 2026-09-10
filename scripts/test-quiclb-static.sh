#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash -n "$ROOT/scripts/build-quiclb.sh" "$ROOT/scripts/test-quiclb-host.sh" "$ROOT/scripts/install-runtime-intelligence.sh"
grep -q 'XDP_FLAGS_UPDATE_IF_NOEXIST' "$ROOT/tools/fluxvm-quiclb-loader.c"
grep -q 'bpf_program__set_ifindex' "$ROOT/tools/fluxvm-quiclb-loader.c"
grep -q 'FLUXVM_QUICLB_OFFLOAD_PROFILE' "$ROOT/bpf/fluxvm_quiclb.bpf.c"
grep -q 'short_dcid_len' "$ROOT/bpf/fluxvm_quiclb.bpf.c"
grep -q 'fluxvm_quic_affinity' "$ROOT/bpf/fluxvm_quiclb.bpf.c"
grep -q 'publish_generation' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
grep -q 'hardware offload requires explicit --ack-hardware-offload' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
grep -q 'export_affinity' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
grep -q 'source_last_seen_ns' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
grep -q 'pub struct SmartNicProbe' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
grep -q 'backend_key(g:u32,sid:u32,id:u32)' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
grep -q 'udp_end' "$ROOT/bpf/fluxvm_quiclb.bpf.c"
grep -q 'route add 198.51.100.100/32' "$ROOT/scripts/test-quiclb-host.sh"
grep -q 'DSR mode preserves the VIP' "$ROOT/crates/fluxvm-intelligence/src/quiclb.rs"
python3 - "$ROOT" <<'PY'
import pathlib,sys,yaml
r=pathlib.Path(sys.argv[1]); yaml.safe_load((r/'.github/workflows/quiclb-smartnic.yml').read_text())
for p in [r/'crates/fluxvm-intelligence/src/quiclb.rs',r/'crates/fluxvm-intelligence/src/bin/fluxvm-quiclb.rs']:
    s=p.read_text(); assert s.count('{')>=s.count('}') and 'TODO' not in s
print('YAML + source structural checks: PASS')
PY
if command -v cargo >/dev/null; then cargo test -p fluxvm-intelligence quiclb; else echo 'SKIP cargo: cargo unavailable'; fi
if pkg-config --exists libbpf 2>/dev/null; then ${CC:-cc} -fsyntax-only -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$ROOT/tools/fluxvm-quiclb-loader.c"; ${CC:-cc} -fsyntax-only -Wall -Wextra -Werror $(pkg-config --cflags libbpf) "$ROOT/tools/fluxvm-quiclb-events.c"; else echo 'SKIP real libbpf header compile: libbpf-dev unavailable'; fi
echo 'QUIC LB + SmartNIC static gates: PASS'
