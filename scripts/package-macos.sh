#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds fluxctl and the signed Virtualization.framework runner and packs them for Homebrew / a GitHub release:
#   target/package/fluxvm-<version>-macos-arm64.tar.gz  (+ .sha256)
#   scripts/package-macos.sh [--profile release|debug] [--version X.Y.Z]
# Needs Apple silicon, the Xcode command line tools, Rust, and guestkit checked out next to this repo (fluxvm-image uses it).
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Apple silicon macOS only" >&2; exit 2; }

PROFILE=release
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' crates/fluxctl/Cargo.toml | head -n1)"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    *) echo "usage: $0 [--profile release|debug] [--version X.Y.Z]" >&2; exit 2 ;;
  esac
done
[[ "$PROFILE" == release || "$PROFILE" == debug ]] || { echo "--profile must be release or debug" >&2; exit 2; }
[[ -n "$VERSION" ]] || { echo "could not work out the version" >&2; exit 2; }

if [[ "$PROFILE" == release ]]; then cargo build --release -p fluxctl; else cargo build -p fluxctl; fi

# build.rs of fluxvm-apple compiles and signs the runner into its OUT_DIR; take the newest one.
RUNNER="$(find "target/$PROFILE/build" -path '*fluxvm-apple-*/out/fluxvm-vz-runner' -type f -print0 | xargs -0 ls -t | head -n1)"
[[ -n "$RUNNER" ]] || { echo "the Swift runner was not built (install the Xcode command line tools)" >&2; exit 1; }
codesign -d --entitlements - "$RUNNER" 2>&1 | grep -q com.apple.security.virtualization \
  || { echo "the runner lacks the com.apple.security.virtualization entitlement" >&2; exit 1; }

NAME="fluxvm-$VERSION-macos-arm64"
OUT="target/package"; STAGE="$OUT/$NAME"
rm -rf "$STAGE" "$OUT/$NAME.tar.gz" "$OUT/$NAME.tar.gz.sha256"
mkdir -p "$STAGE/bin"
cp "target/$PROFILE/fluxctl" "$STAGE/bin/fluxctl"
# Not stripped: stripping would invalidate the runner's signature, and the entitlement is what lets it start VMs.
cp "$RUNNER" "$STAGE/bin/fluxvm-vz-runner"
cp LICENSE NOTICE "$STAGE/" 2>/dev/null || cp LICENSE "$STAGE/"
cp config.example.toml "$STAGE/"
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
( cd "$OUT" && shasum -a 256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
echo "$OUT/$NAME.tar.gz"
cat "$OUT/$NAME.tar.gz.sha256"
