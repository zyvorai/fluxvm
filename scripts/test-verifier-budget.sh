#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Verifier-complexity guard for the shipped TC objects. Linux root + bpftool.
#
# Why this exists: on Linux 7.0.0-31 the VM-edge program (fluxvm_tc.bpf.o) was
# rejected outright -- "processed 1000001 insns (limit 1000000)" -- because its
# pod-policy rule scan (a 64-iteration loop) inlined the whole rule match at every
# iteration and in both address-family paths. It was fixed by making the per-rule
# match a global BPF function (verified once) and removing the per-byte branches
# from the prefix compare. Verifier complexity is kernel- and compiler-dependent,
# so this loads each object and fails when it uses more than a budget of the
# 1,000,000-insn limit, catching a regression long before a kernel rejects it.
#
#   sudo ./scripts/test-verifier-budget.sh
#   FLUXVM_VERIFIER_BUDGET=400000 FLUXVM_BPF_DIR=dist/bpf sudo ./scripts/test-verifier-budget.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIMIT=1000000
BUDGET="${FLUXVM_VERIFIER_BUDGET:-500000}"   # 50% of the limit: room for kernel drift
say()  { echo "test-verifier-budget: $*"; }
skip() { say "SKIP: $*"; exit 0; }
FAILS=0

[[ "$(uname -s)" == "Linux" ]] || skip "Linux required"
[[ "$(id -u)" -eq 0 ]] || skip "root required (run with sudo)"
command -v bpftool >/dev/null || skip "bpftool not found"
[[ "$(findmnt -n -o FSTYPE /sys/fs/bpf 2>/dev/null)" == "bpf" ]] || skip "bpffs is not mounted at /sys/fs/bpf"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/verifier-budget.XXXXXX")"
PIN="/sys/fs/bpf/fvvb$$"
trap 'rm -rf "$PIN" "$WORK"' EXIT INT TERM

if [[ -n "${FLUXVM_BPF_DIR:-}" ]]; then
  BPF="$FLUXVM_BPF_DIR"
else
  command -v clang >/dev/null || skip "clang not found (set FLUXVM_BPF_DIR to prebuilt objects)"
  BPF="$WORK/bpf"
  bash "$ROOT/scripts/build-ebpf.sh" "$BPF" >/dev/null 2>&1 || { say "FAIL: build-ebpf.sh"; exit 1; }
fi

echo "== verifier budget: <= ${BUDGET} of ${LIMIT} processed insns per object =="
echo "   kernel: $(uname -r)"
for obj in fluxvm_tc fluxvm_pod_ingress fluxvm_direct; do
  f="$BPF/${obj}.bpf.o"
  [[ -f "$f" ]] || { echo "  ❌ $obj: object missing at $f" >&2; FAILS=$((FAILS + 1)); continue; }
  rm -rf "$PIN"; mkdir -p "$PIN/maps"
  if bpftool -d prog load "$f" "$PIN/prog" type classifier pinmaps "$PIN/maps" >"$WORK/$obj.log" 2>&1; then
    n=$(grep -oE '^processed [0-9]+ insns' "$WORK/$obj.log" | tail -1 | awk '{print $2}')
    if [[ -z "$n" ]]; then
      echo "  ❌ $obj loads but the verifier log has no 'processed N insns' line; cannot check the budget" >&2
      FAILS=$((FAILS + 1))
    elif [[ "$n" -le "$BUDGET" ]]; then
      echo "  ✅ $obj: $n insns ($((n * 100 / LIMIT))% of the limit)"
    else
      echo "  ❌ $obj: $n insns exceeds the ${BUDGET} budget ($((n * 100 / LIMIT))% of the limit)" >&2
      FAILS=$((FAILS + 1))
    fi
  else
    why=$(grep -oE 'processed [0-9]+ insns \(limit [0-9]+\)|too large|invalid[^:]*' "$WORK/$obj.log" | tail -1)
    echo "  ❌ $obj: rejected by this kernel's verifier (${why:-see log})" >&2
    FAILS=$((FAILS + 1))
  fi
done

echo
if [[ "$FAILS" -eq 0 ]]; then echo "🎉 verifier budget PASS"; else echo "verifier budget: $FAILS FAILED" >&2; exit 1; fi
