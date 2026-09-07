# 08 — Audit mode

**Goal:** Turn on Cilium-style **audit mode** so would-be drops are logged /
sampled while traffic still forwards — useful while migrating from
permissive networking.

## How FluxVM encodes audit

`spec.auditMode: true` sets `policy.audit_mode`. At map configure time the
control plane sets **bit 31** of `iface_config.sample_rate`. The TC program
forwards the packet and records the audited drop path instead of
`TC_ACT_SHOT`.

## Apply an audit CNP

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cilium/cnp-audit-mode.json

sudo fluxvm --config /etc/fluxvm.toml group get audit-web \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);assert d["policy"]["audit_mode"] is True; print("audit_mode ok")'
```

Attach labels on a VM:

```bash
curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{"default_allow":false,"labels":["app=audit"],"groups":[],"allow_cidrs":["10.0.0.0/8"],"allow_ports":["tcp/443"]}'
```

Re-apply the CNP so Running VMs reconcile, then inspect flows/stats:

```bash
curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/stats" | python3 -m json.tool
curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/flows?limit=20" | python3 -m json.tool
```

## Flip to enforce

Edit the CNP JSON to `"auditMode": false`, re-apply, and the same deny/allow
rules become hard drops.

## Cleanup

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp delete audit-web
```

## Next

- [09 — Observe](09-observe.md)
- [05 — Default deny](05-default-deny.md)
