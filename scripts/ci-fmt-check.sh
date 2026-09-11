#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# rustfmt-check only this repo's workspace members. Sibling path deps
# (guestkit) have their own CI and must not fail FluxVM fmt gates.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mapfile -t pkgs < <(
  cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; [print(p["name"]) for p in json.load(sys.stdin)["packages"]]'
)
args=()
for p in "${pkgs[@]}"; do
  args+=(-p "$p")
done
cargo fmt "${args[@]}" -- --check
