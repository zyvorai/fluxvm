#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Build fluxvm-guest-agent as a fully static musl binary so it runs in any
# Linux guest regardless of the guest's glibc (a binary built on a modern
# host fails to exec in e.g. Ubuntu 18.04 / glibc 2.27 with
# "version GLIBC_2.28 not found").
#
# Usage: scripts/build-guest-agent-static.sh [output-path]
# Requires: rustup target x86_64-unknown-linux-musl (and musl-gcc is not
# needed: the target ships its own self-contained C runtime).
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${GUEST_AGENT_TARGET:-x86_64-unknown-linux-musl}"
TARGET_DIR="${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}"
BUILT="${TARGET_DIR}/${TARGET}/release/fluxvm-guest-agent"
OUT="${1:-$BUILT}"

if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx "$TARGET"; then
  echo "missing Rust target ${TARGET}; run: rustup target add ${TARGET}" >&2
  exit 2
fi

(cd "$PROJECT_DIR" && cargo build --release -p fluxvm-guest-agent --target "$TARGET")

[ -x "$BUILT" ] || { echo "build produced no binary at $BUILT" >&2; exit 1; }

# Prove it is static: a dynamic binary has an INTERP program header or NEEDED
# entries, and `ldd` reports "not a dynamic executable" only for static ones.
if ldd "$BUILT" 2>&1 | grep -qiE "not a dynamic executable|statically linked"; then
  :
else
  echo "FAIL: ${BUILT} is dynamically linked:" >&2
  ldd "$BUILT" >&2 || true
  exit 1
fi

if [ "$OUT" != "$BUILT" ]; then
  install -D -m755 "$BUILT" "$OUT"
fi
echo "static guest agent: ${OUT} ($(stat -c %s "$OUT" 2>/dev/null || stat -f %z "$OUT") bytes)"
