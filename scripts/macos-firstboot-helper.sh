#!/bin/bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# FluxVM macOS guest first-boot helper. Run it once inside the guest as an admin (or from a LaunchDaemon baked into the
# template). It reads the FluxVM first-boot share (apple.firstboot), installs the keys as a root-owned AuthorizedKeysFile
# outside any home directory, so fresh clones accept them before anyone has logged in, and turns on Remote Login.
#
#   bash "/Volumes/My Shared Files/firstboot/firstboot.sh" [share-dir]

set -euo pipefail

SRC="${1:-/Volumes/My Shared Files/firstboot}"
KEYS_DST=/etc/ssh/fluxvm_authorized_keys
SSHD_DROPIN=/etc/ssh/sshd_config.d/050-fluxvm.conf

if [[ $EUID -ne 0 ]]; then
  exec sudo "$0" "$@"
fi

if [[ ! -f "$SRC/authorized_keys" ]]; then
  echo "firstboot: no authorized_keys under $SRC" >&2
  exit 1
fi

install -m 0644 -o root -g wheel "$SRC/authorized_keys" "$KEYS_DST"
mkdir -p "$(dirname "$SSHD_DROPIN")"
printf 'AuthorizedKeysFile .ssh/authorized_keys %s\n' "$KEYS_DST" >"$SSHD_DROPIN"
chmod 0644 "$SSHD_DROPIN"

if [[ -f "$SRC/enable_remote_login" ]]; then
  systemsetup -setremotelogin on >/dev/null 2>&1 || launchctl enable system/com.openssh.sshd || true
fi
launchctl kickstart -k system/com.openssh.sshd 2>/dev/null || true
echo "firstboot: installed $(grep -c . "$KEYS_DST") key(s) into $KEYS_DST"
