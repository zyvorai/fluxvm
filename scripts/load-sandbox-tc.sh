#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Legacy stub — retained for operators who still call this script by hand.
# The real TC/eBPF dataplane is `crates/fluxvm-network/src/ebpf.rs` (modes
# `ebpf` / `cilium` under `[sandbox.dataplane]`). See docs/ebpf-cilium.md.
#
# Usage: load-sandbox-tc.sh <sandbox-uuid>

set -euo pipefail

ID="${1:?sandbox uuid required}"

echo "fluxvm: load-sandbox-tc.sh is a no-op stub for ${ID}." >&2
echo "fluxvm: enable [sandbox.dataplane] mode = \"ebpf\"|\"cilium\" and build via ./scripts/build-ebpf.sh" >&2
exit 0
