#!/usr/bin/env bash
set -euo pipefail

ROOT=${FLUXVM_CONTAINERD_STATE_DIR:-/run/fluxvm/containerd}
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
paths = sorted(root.glob('*/*/runtime-state.json'))
if not paths:
    print(f"no Secure Containers journals found under {root}")
    raise SystemExit(0)
for path in paths:
    try:
        state = json.loads(path.read_text())
    except Exception as exc:
        print(f"journal={path} ERROR={exc}")
        continue
    sandbox = state.get('sandbox') or {}
    stats = state.get('device_stats') or {}
    print(f"journal={path}")
    print(f"  vm={sandbox.get('vm_id','-')} ready={sandbox.get('ready',False)} "
          f"attach_total={stats.get('attach_total',0)} detach_total={stats.get('detach_total',0)} "
          f"unplug_failures={stats.get('unplug_failures',0)} recovery_checks={stats.get('recovery_checks',0)}")
    devices = sandbox.get('devices') or []
    if not devices:
        print("  devices=none")
        continue
    for d in devices:
        owners = d.get('owners', None)
        if owners is None:
            state_name = 'legacy-pinned'
            owners_text = '?'
        elif not owners:
            state_name = 'pending-unplug'
            owners_text = '-'
        else:
            state_name = 'claimed'
            owners_text = ','.join(owners)
        if d.get('kind') == 'block':
            identity = f"{d.get('host_path')} rdev={d.get('host_major')}:{d.get('host_minor')} serial={d.get('serial')}"
        else:
            identity = f"{d.get('bdf')} iommu_group={d.get('iommu_group')} guest_path={d.get('guest_path')}"
        print(f"  {d.get('kind')} key={('block:'+str(d.get('host_path'))) if d.get('kind')=='block' else ('vfio:'+str(d.get('bdf')))} "
              f"qdev={d.get('device_id')} state={state_name} owners={owners_text} {identity}")
PY
