#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install -Dm0755 "$ROOT/tools/fluxvm_fleet_rollout.py" /usr/libexec/fluxvm/fluxvm-fleet
ln -sfn /usr/libexec/fluxvm/fluxvm-fleet /usr/local/bin/fluxvm-fleet
install -Dm0644 "$ROOT/packaging/systemd/fluxvm-fleet-reconcile.service" /etc/systemd/system/fluxvm-fleet-reconcile.service
install -Dm0644 "$ROOT/packaging/systemd/fluxvm-fleet-reconcile.timer" /etc/systemd/system/fluxvm-fleet-reconcile.timer
systemctl daemon-reload
echo "installed fluxvm-fleet"
