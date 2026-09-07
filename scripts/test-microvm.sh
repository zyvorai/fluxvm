#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 scripts/test-microvm-policy.py
cargo test -p fluxvm-microvm
bin=target/debug/fluxvm-microvm
[[ -x $bin ]] || { cargo build -p fluxvm-microvm; }
out="$("$bin" --print-crd)"
echo "$out" | grep -q MicroVM
echo "$out" | grep -q MicroVMJob
echo "$out" | grep -q MicroVMPool
echo "$out" | grep -q GuestImage
echo "$out" | grep -q microvm.fluxvm.zyvor.io
echo "$out" | grep -q 'microvms.microvm.fluxvm.zyvor.io\|"group": "microvm.fluxvm.zyvor.io"'
echo "microvm gates passed"
