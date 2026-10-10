#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${TMPDIR:-/tmp}/fluxvm-vmnetd"
xcrun swiftc -swift-version 5 -O -target arm64-apple-macosx26.0 "$ROOT/main.swift" "$ROOT/../../runner/VmnetOptions.swift" \
    -framework Foundation -framework vmnet -o "$OUT"
codesign --force --sign - --entitlements "$ROOT/Entitlements.plist" "$OUT"
sudo install -m 0755 "$OUT" /usr/local/libexec/fluxvm-vmnetd
mkdir -p "$HOME/Library/LaunchAgents"
cp "$ROOT/dev.zyvor.fluxvm.vmnetd.plist" "$HOME/Library/LaunchAgents/"
launchctl bootout "gui/$UID/dev.zyvor.fluxvm.vmnetd" 2>/dev/null || true
launchctl bootstrap "gui/$UID" "$HOME/Library/LaunchAgents/dev.zyvor.fluxvm.vmnetd.plist"
