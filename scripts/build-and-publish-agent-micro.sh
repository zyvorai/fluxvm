#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# CI wrapper: build the static aarch64 guest agent, build the agent-micro image, and write a catalog entry for it.
#
#   sudo -E scripts/build-and-publish-agent-micro.sh [DIST_DIR]
#
# Environment:
#   VERSION             recorded in the catalog entry (default: git describe)
#   SOURCE_URL          where the .raw will be published; the catalog entry's `source` (default: the local path)
#   FLUXVM_CATALOG_KEY  base64 Ed25519 key from `fluxctl catalog keygen`; when set the entry is signed
#   FLUXCTL             fluxctl binary (default: target/release/fluxctl, else fluxctl on PATH)
# Output in DIST_DIR (default dist/): agent-micro-arm64.raw, .sha256, agent-micro.catalog.json. Uploading is left to the CI job.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${1:-${PROJECT_DIR}/dist}"
VERSION="${VERSION:-$(git -C "$PROJECT_DIR" describe --tags --always 2>/dev/null || echo dev)}"
FLUXCTL="${FLUXCTL:-${PROJECT_DIR}/target/release/fluxctl}"
[ -x "$FLUXCTL" ] || FLUXCTL="$(command -v fluxctl || true)"
[ -n "$FLUXCTL" ] || { echo "fluxctl not found (cargo build --release -p fluxctl, or set FLUXCTL)" >&2; exit 2; }

AGENT="${PROJECT_DIR}/target/aarch64-unknown-linux-musl/release/fluxvm-guest-agent"
if [ ! -x "$AGENT" ]; then
  echo "==> building the static aarch64 guest agent"
  # As the invoking user when run under sudo, so target/ stays theirs.
  if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" env GUEST_AGENT_TARGET=aarch64-unknown-linux-musl "${PROJECT_DIR}/scripts/build-guest-agent-static.sh"
  else
    GUEST_AGENT_TARGET=aarch64-unknown-linux-musl "${PROJECT_DIR}/scripts/build-guest-agent-static.sh"
  fi
fi

echo "==> building the image"
AGENT_BIN="$AGENT" "${PROJECT_DIR}/scripts/build-agent-micro.sh" "$DIST"

RAW="${DIST}/agent-micro-arm64.raw"
SHA="$(cut -d' ' -f1 "${RAW}.sha256")"
SOURCE="${SOURCE_URL:-$RAW}"
ENTRY="${DIST}/agent-micro.catalog.json"

if [ -n "${FLUXVM_CATALOG_KEY:-}" ]; then
  echo "==> signing the catalog entry"
  rm -f "$ENTRY"
  "$FLUXCTL" catalog sign --key "$FLUXVM_CATALOG_KEY" --name agent-micro --source "$SOURCE" --sha256 "$SHA" \
    --format raw --distro debian --version "$VERSION" --arch aarch64 --catalog-file "$ENTRY" >/dev/null
else
  printf '[{"name":"agent-micro","source":"%s","sha256":"%s","format":"raw","distro":"debian","version":"%s","arch":"aarch64"}]\n' \
    "$SOURCE" "$SHA" "$VERSION" > "$ENTRY"
fi
echo "catalog entry: $ENTRY"
echo "publish ${RAW} at ${SOURCE}, then merge the entry into each Mac's catalog.json"
