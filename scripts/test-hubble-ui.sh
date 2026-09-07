#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HTML="$ROOT/crates/fluxvm-api/src/hubble_ui.html"
grep -q 'Colorful' "$HTML"
grep -q 'Normal' "$HTML"
grep -q '/v1/network/hubble/flows' "$HTML"
grep -q 'packet path' "$HTML"
# renderer module exists and documents both modes
grep -q 'FlowOutput' "$ROOT/crates/fluxvm-network/src/packetflow.rs"
grep -q 'plain/normal mode must be raw text' "$ROOT/crates/fluxvm-network/src/packetflow.rs"
echo "test-hubble-ui: ok"
