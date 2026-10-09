#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fills the version and checksum of the Homebrew formula from a release package.
#   scripts/update-homebrew-formula.sh <version> <package.tar.gz | sha256> [formula.rb]
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:?version}"; SRC="${2:?package or sha256}"; FORMULA="${3:-packaging/homebrew/fluxvm.rb}"
if [[ -f "$SRC" ]]; then SHA="$(shasum -a 256 "$SRC" | cut -d' ' -f1)"; else SHA="$SRC"; fi
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "not a sha256: $SHA" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || { echo "not a version: $VERSION" >&2; exit 2; }
sed -i.bak -E "s/^  version \".*\"/  version \"$VERSION\"/; s/^  sha256 \".*\"/  sha256 \"$SHA\"/" "$FORMULA" && rm -f "$FORMULA.bak"
echo "$FORMULA: version $VERSION, sha256 $SHA"
