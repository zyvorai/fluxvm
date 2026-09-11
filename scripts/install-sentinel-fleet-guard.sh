#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install -Dm0755 "$ROOT/tools/fluxvm_fleet_guard.py" /usr/libexec/fluxvm/fluxvm-fleet-guard
install -Dm0644 "$ROOT/packaging/systemd/fluxvm-fleet-guard.service" /usr/lib/systemd/system/fluxvm-fleet-guard.service
install -Dm0644 "$ROOT/packaging/systemd/fluxvm-fleet-guard.timer" /usr/lib/systemd/system/fluxvm-fleet-guard.timer
install -d -m0750 /etc/fluxvm
if [[ ! -e /etc/fluxvm/sentinel-fleet-guard.json ]]; then install -Dm0640 "$ROOT/examples/sentinel-fleet-guard.json" /etc/fluxvm/sentinel-fleet-guard.json; fi
systemctl daemon-reload
systemctl enable fluxvm-fleet-guard.timer
