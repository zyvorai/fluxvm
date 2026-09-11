#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; PREFIX="${PREFIX:-/usr/local}"
install -D -m0755 "$ROOT/tools/fluxvm_migration_orchestrator.py" "$PREFIX/libexec/fluxvm/fluxvm-migrate"
for u in fluxvm-migration-observer.service fluxvm-migration-reconcile.service fluxvm-migration-reconcile.timer; do install -D -m0644 "$ROOT/packaging/systemd/$u" "/etc/systemd/system/$u"; done
install -d -m0700 /var/lib/fluxvm/migrations
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
