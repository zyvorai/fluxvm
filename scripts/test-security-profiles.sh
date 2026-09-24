#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Hardware-free Phase 6 regression: security profiles, confidential QEMU
# providers, and fleet placement that still gates an explicit node.
#
# Usage (from repo root):
#   ./scripts/test-security-profiles.sh
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> fluxvm-core security"
cargo test -p fluxvm-core security -- --nocapture

echo "==> fluxvm-qemu confidential"
cargo test -p fluxvm-qemu confidential -- --nocapture

echo "==> fluxvm-agent security placement"
cargo test -p fluxvm-agent explicit_node_targeting_still_rejects_ineligible_confidential_profile -- --nocapture
cargo test -p fluxvm-agent automatic_placement_skips_nodes_that_cannot_satisfy_snp -- --nocapture

echo "OK — Phase 6 security-profile tests passed (no SNP/TDX hardware required)."
echo "See docs/security-profiles.md and docs/guides/security-profiles-howto.md"
