#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/tools/fluxvm-policy-observer"
go test -run '^$' -bench . -benchmem ./internal/observer ./internal/metrics
