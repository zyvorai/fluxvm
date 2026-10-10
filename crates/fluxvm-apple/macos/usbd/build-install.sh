#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="${TMPDIR:-/tmp}/FluxVMUSBAccess.app"
rm -rf "$APP" && mkdir -p "$APP/Contents/MacOS"
cp "$ROOT/Info.plist" "$APP/Contents/Info.plist"
xcrun swiftc -swift-version 5 -O -target arm64-apple-macosx27.0 "$ROOT/main.swift" \
  -framework AppKit -framework Foundation -framework AccessoryAccess -o "$APP/Contents/MacOS/FluxVMUSBAccess"
codesign --force --deep --sign - --entitlements "$ROOT/Entitlements.plist" "$APP"
sudo rm -rf /Applications/FluxVMUSBAccess.app
sudo cp -R "$APP" /Applications/FluxVMUSBAccess.app
mkdir -p "$HOME/Library/LaunchAgents"
cp "$ROOT/dev.zyvor.fluxvm.usbd.plist" "$HOME/Library/LaunchAgents/"
launchctl bootout "gui/$UID/dev.zyvor.fluxvm.usbd" 2>/dev/null || true
launchctl bootstrap "gui/$UID" "$HOME/Library/LaunchAgents/dev.zyvor.fluxvm.usbd.plist"
echo "Open the macOS Accessory Access menu and grant the desired USB device to FluxVM USB Access."
