#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs
# SPDX-License-Identifier: Apache-2.0
# Host behavior tests of production BPF C; no root, KVM or BPF loader needed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-gcc}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FLAGS=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-unknown-pragmas)
if [[ "${SANITIZE:-0}" == 1 ]]; then
  FLAGS+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
"$CC" "${FLAGS[@]}" "$ROOT/tests/ebpf-host/policy.c" -o "$WORK/policy"
"$WORK/policy"

# Copy authoritative production struct declarations into the host fixture.
python3 - "$ROOT" "$WORK" <<'PYFIXTURE'
from pathlib import Path
import sys
root, work = map(Path, sys.argv[1:])
source = (root / "bpf/fluxvm_tc.bpf.c").read_text()
blocks = []
for name in ("flow_key", "flow_value", "flow_event"):
    start = source.index("struct " + name + " {")
    end = source.index("\n};", start) + 3
    blocks.append(source[start:end])
(work / "flow-fixture.h").write_text("\n".join(blocks) + "\n")
PYFIXTURE
"$CC" "${FLAGS[@]}" -I"$WORK" "$ROOT/tests/ebpf-host/telemetry.c" -o "$WORK/telemetry"
"$WORK/telemetry"
