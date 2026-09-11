#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc/fluxvm}"
STATE_DIR="${STATE_DIR:-/var/lib/fluxvm/sentinel-upgrades}"
install -d -m 0755 "$PREFIX/libexec/fluxvm" "$PREFIX/share/fluxvm/schemas" "$PREFIX/share/fluxvm/examples"
install -d -m 0700 "$STATE_DIR"
install -m 0755 "$ROOT/tools/fluxvm_upgrade_manager.py" "$PREFIX/libexec/fluxvm/fluxvm-upgrade"
install -m 0644 "$ROOT/schemas/sentinel-upgrade-plan.schema.json" "$PREFIX/share/fluxvm/schemas/"
install -m 0644 "$ROOT/examples/sentinel-upgrade-plan.json" "$PREFIX/share/fluxvm/examples/"
if command -v systemctl >/dev/null 2>&1 && [[ "${INSTALL_SYSTEMD:-1}" == "1" ]]; then
  install -d -m 0755 /etc/systemd/system
  install -m 0644 "$ROOT/packaging/systemd/fluxvm-upgrade-reconcile.service" /etc/systemd/system/
  install -m 0644 "$ROOT/packaging/systemd/fluxvm-upgrade-reconcile.timer" /etc/systemd/system/
  systemctl daemon-reload
fi
printf '%s\n' "installed: $PREFIX/libexec/fluxvm/fluxvm-upgrade"
