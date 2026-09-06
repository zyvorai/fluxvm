#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required tool: $1" >&2
    return 1
  }
}

echo "==> shell syntax"
bash -n scripts/build-ebpf.sh
bash -n scripts/test-ebpf-smoke.sh
bash -n scripts/test-network-fabric.sh
bash -n scripts/validate-network-fabric.sh

echo "==> Python flow-exporter tests"
python3 scripts/test_flow_exporter.py

if need clang && [[ -f /usr/include/bpf/bpf_helpers.h ]]; then
  echo "==> eBPF object build"
  ./scripts/build-ebpf.sh
else
  echo "SKIP eBPF object build: clang or libbpf headers unavailable"
fi

if command -v cargo >/dev/null 2>&1; then
  echo "==> cargo fmt"
  cargo fmt --all -- --check
  echo "==> cargo build"
  cargo build --workspace --all-targets
  echo "==> cargo test"
  cargo test --workspace
  echo "==> cargo clippy"
  cargo clippy --workspace --all-targets || true
else
  echo "SKIP Rust compile/tests: cargo not installed"
fi

if [[ "${FLUXVM_PRIVILEGED_SMOKE:-0}" == "1" ]]; then
  echo "==> privileged kernel smoke"
  if [[ "$EUID" -eq 0 ]]; then
    ./scripts/test-ebpf-smoke.sh
  else
    sudo -E ./scripts/test-ebpf-smoke.sh
  fi
  echo "==> full Network Fabric e2e (FluxVm + REST)"
  if [[ "$EUID" -eq 0 ]]; then
    ./scripts/test-network-fabric.sh
  else
    sudo -E ./scripts/test-network-fabric.sh
  fi
else
  echo "SKIP privileged kernel smoke: set FLUXVM_PRIVILEGED_SMOKE=1"
fi

echo "validation complete"
