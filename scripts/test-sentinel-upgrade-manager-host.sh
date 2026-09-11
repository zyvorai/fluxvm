#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="${FLUXVM_UPGRADE_BIN:-$ROOT/tools/fluxvm_upgrade_manager.py}"
"$ROOT/scripts/test-sentinel-upgrade-manager-static.sh"
python3 "$TOOL" probe "$ROOT/examples/sentinel-upgrade-plan.json" | tee /tmp/fluxvm-upgrade-probe.json
python3 - <<'PY'
import json
p=json.load(open('/tmp/fluxvm-upgrade-probe.json'))
assert p['manager_version'].startswith('14e.')
assert 'kernel' in p and 'machine' in p
PY
# Destructive bpffs/map tests require an explicit throwaway-lab marker.
if [[ "${FLUXVM_UPGRADE_DESTRUCTIVE_E2E:-0}" != "1" ]]; then
  echo 'SKIP destructive upgrade E2E (set FLUXVM_UPGRADE_DESTRUCTIVE_E2E=1 on a throwaway lab host)'
  exit 0
fi
[[ -f /etc/fluxvm/ALLOW_DESTRUCTIVE_E2E ]] || { echo 'missing /etc/fluxvm/ALLOW_DESTRUCTIVE_E2E safety marker' >&2; exit 2; }
command -v bpftool >/dev/null || { echo 'bpftool required' >&2; exit 2; }
mountpoint -q /sys/fs/bpf || { echo 'bpffs must be mounted' >&2; exit 2; }
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; rm -f /sys/fs/bpf/fluxvm/set14e-test-map 2>/dev/null || true' EXIT
mkdir -p /sys/fs/bpf/fluxvm
bpftool map create /sys/fs/bpf/fluxvm/set14e-test-map type hash key 4 value 8 entries 8 name set14e_test
bpftool map update pinned /sys/fs/bpf/fluxvm/set14e-test-map key hex 01 00 00 00 value hex 2a 00 00 00 00 00 00 00
cat > "$TMP/plan.json" <<JSON
{
  "schema_version": 1,
  "transaction_id": "set14e-host-test",
  "state_dir": "$TMP/state",
  "bpffs_root": "/sys/fs/bpf/fluxvm",
  "repo_root": "$TMP/repo",
  "components": [{
    "name": "map-roundtrip",
    "apply": ["/bin/true"],
    "health": ["/bin/true"],
    "rollback": ["/bin/true"],
    "maps": [{"pin":"set14e-test-map","state":"replace","abi":{"type":"hash","key_size":4,"value_size":8}}]
  }]
}
JSON
mkdir -p "$TMP/repo"
python3 "$TOOL" run "$TMP/plan.json" >/dev/null
python3 "$TOOL" verify-evidence "$TMP/state/set14e-host-test" >/dev/null
bpftool map dump pinned /sys/fs/bpf/fluxvm/set14e-test-map | grep -q '2a 00 00 00 00 00 00 00'
echo 'Sentinel Set 14E destructive host smoke: PASS'
