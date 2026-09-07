#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/upgrade-snapshot.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

STATE="$WORKDIR/var/lib/fluxvm"
CFG="$WORKDIR/etc/fluxvm.toml"
SNAPS="$WORKDIR/snaps"
mkdir -p "$STATE/vms" "$(dirname "$CFG")"
echo 'listen = "127.0.0.1:7788"' >"$CFG"
echo 'guest=web-1' >"$STATE/vms/web-1.json"

"$SCRIPT" snapshot --tag before-nplus1 \
  --state-dir "$STATE" --config "$CFG" --backup-root "$SNAPS"

echo 'guest=broken' >"$STATE/vms/web-1.json"
echo 'listen = "127.0.0.1:1"' >"$CFG"

"$SCRIPT" restore --tag before-nplus1 \
  --state-dir "$STATE" --config "$CFG" --backup-root "$SNAPS"

grep -q 'guest=web-1' "$STATE/vms/web-1.json"
grep -q '7788' "$CFG"
echo "test-upgrade-snapshot: ok"
