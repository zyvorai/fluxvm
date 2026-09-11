#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_ROOT="${FLUXVM_BPF_ROOT:-/sys/fs/bpf/fluxvm}"
AGE="${FLUXVM_SENTINEL_STALE_AGE_SECONDS:-300}"
ARGS=(reconcile --root "$BPF_ROOT" --min-age-seconds "$AGE")
if [[ "${1:-}" == "--apply" ]]; then
  ARGS+=(--apply)
fi
exec python3 "$ROOT/tools/fluxvm-sentinel-certify.py" "${ARGS[@]}"
