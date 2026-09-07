# 09 — Observe (Hubble-lite)

**Goal:** Take a single snapshot of identities, groups, CNPs, and labeled
VM endpoints — the FluxVM stand-in for a quick `hubble observe` / identity
dashboard glance.

## CLI

```bash
sudo fluxvm --config /etc/fluxvm.toml observe | python3 -m json.tool
```

## REST

```bash
curl -s http://127.0.0.1:7788/v1/network/observe | python3 -m json.tool
```

## Shape

```json
{
  "identities": [ { "id": 2, "name": "reserved:world", "reserved": true, "...": "..." } ],
  "groups": [ { "name": "web-egress", "identity": 1688068488, "...": "..." } ],
  "policies": [ { "metadata": { "name": "web-egress" }, "...": "..." } ],
  "endpoints": [
    {
      "vm_id": "...",
      "name": "fluxvm-cnp-e2e",
      "status": "Running",
      "labels": ["app=web"],
      "groups": [],
      "identity": 12345
    }
  ]
}
```

`endpoints` only lists VMs that already have a persisted network-policy
file under `$state_dir/network-policy/`.

## Per-VM flows (deeper than observe)

```bash
curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/flows?limit=50" | python3 -m json.tool
curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/stats" | python3 -m json.tool
```

NDJSON exporter for shipping elsewhere:

```bash
python3 scripts/export_network_flows.py --help
```

## Next

- [02 — Identities](02-identities.md)
- [10 — Multi-group merge](10-multi-group-merge.md)
