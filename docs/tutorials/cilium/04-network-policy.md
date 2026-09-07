# 04 — Network policy (CiliumNetworkPolicy)

**Goal:** Apply a `CiliumNetworkPolicy`-shaped JSON the way you would
`kubectl apply -f cnp.yaml`, then verify the compiled security group and
effective VM policy.

## 1. Apply the sample CNP

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cilium-network-policy-web.json

sudo fluxvm --config /etc/fluxvm.toml cnp list
sudo fluxvm --config /etc/fluxvm.toml cnp get web-egress
```

REST equivalent:

```bash
curl -s -X POST http://127.0.0.1:7788/v1/network/cnp \
  -H 'Content-Type: application/json' \
  --data @examples/cilium-network-policy-web.json | python3 -m json.tool
```

**Expect:** a security group named `web-egress` with:

- `allow_cidrs` including `10.0.0.0/8` (plus entity expansions)
- `deny_cidrs` including `10.66.0.0/16`
- `allow_ports` including `tcp/443`, `tcp/80`, `udp/53`, and the expanded
  range `tcp/8000`…`tcp/8003`
- `default_allow=false` from `enableDefaultDeny.egress`
- `labels` derived from `endpointSelector.matchLabels` → `app=web`

```bash
sudo fluxvm --config /etc/fluxvm.toml group get web-egress | python3 -m json.tool
```

## 2. Select endpoints (VMs) with labels

Cilium uses `endpointSelector`. On FluxVM, put the same labels on the VM
network policy:

```bash
curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{"default_allow":true,"labels":["app=web"],"groups":[],"allow_cidrs":[],"allow_ports":[]}'

curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/effective" | python3 -m json.tool
```

**Expect:** `membership.matched` contains `web-egress`.

## 3. Live reconcile

Editing/re-applying a CNP reconfigures Running/Paused VMs that already match
the group (no delete/recreate required):

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cilium-network-policy-web.json
```

## 4. Delete

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp delete web-egress
# compiled group is removed with the CNP store entry
sudo fluxvm --config /etc/fluxvm.toml group list
```

## Anatomy of the example

See [`examples/cilium-network-policy-web.json`](../../../examples/cilium-network-policy-web.json):

| CNP field | FluxVM result |
|-----------|---------------|
| `endpointSelector.matchLabels` | Group labels |
| `egress[].toCIDR` | `allow_cidrs` |
| `egress[].toEntities` | Extra allow CIDRs via identity map |
| `egress[].toFQDNs` | `allow_fqdns` (resolve via domain allowlist path) |
| `egress[].toPorts` | `allow_ports` (`tcp/N`, ranges expanded) |
| `egressDeny[].toCIDRSet` | `deny_cidrs` → `fluxvm_deny4/6` |
| `enableDefaultDeny.egress` | `default_allow=false` |
| `auditMode` | Audit bit on iface sample_rate |

## Next

- [05 — Default deny](05-default-deny.md)
- [06 — Named ports](06-named-ports.md)
- [07 — Entities and FQDNs](07-entities-and-fqdns.md)
