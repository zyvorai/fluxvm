#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json, pathlib, sys
if len(sys.argv) < 3:
    raise SystemExit("usage: sentinel-ga-merge-measurements.py OUT INPUT...")
out={"schema_version":1,"metadata":{"sources":[]},"metrics":{}}
for name in sys.argv[2:]:
    d=json.load(open(name))
    if d.get('schema_version') != 1: raise SystemExit(f"unsupported schema in {name}")
    overlap=set(out['metrics']) & set(d.get('metrics',{}))
    if overlap: raise SystemExit(f"duplicate metric(s) in {name}: {sorted(overlap)}")
    out['metrics'].update(d.get('metrics',{})); out['metadata']['sources'].append(name)
pathlib.Path(sys.argv[1]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
