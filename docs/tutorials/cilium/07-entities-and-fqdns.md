# 07 — Entities and FQDNs

**Goal:** Allow egress to Cilium **entities** (`world`, `host`, `cluster`, …)
and record **FQDN** allow rules the same way a CNP would.

## Entities

`toEntities` expands through [`identity::entity_cidrs`](../../../crates/fluxvm-network/src/identity.rs)
into concrete CIDRs folded into the group allowlist.

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cilium/cnp-entities-world.json

sudo fluxvm --config /etc/fluxvm.toml group get talk-to-world | python3 -m json.tool
```

**Expect:** `allow_cidrs` includes entity expansions (for example
`0.0.0.0/0` / `::/0` for `world`, depending on the mapping), plus any
explicit `toCIDR` entries.

List the reserved identity table that backs entity names:

```bash
sudo fluxvm --config /etc/fluxvm.toml identity list \
  | python3 -c 'import json,sys;print([i["name"] for i in json.load(sys.stdin)])'
```

## FQDNs

CNP `toFQDNs[].matchName` is stored on the compiled group as `allow_fqdns`.
Resolution uses FluxVM’s existing domain-allowlist / egress path (not an
inline DNS proxy inside the TC program).

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cilium-network-policy-web.json

sudo fluxvm --config /etc/fluxvm.toml group get web-egress \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["policy"].get("allow_fqdns"))'
```

**Expect:** `["example.com"]` (from the sample CNP).

Pair with sandbox egress domains in config when you want L7 redirect:

```toml
[sandbox]
egress_allow_domains = ["example.com", ".github.com"]
```

## Cleanup

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp delete talk-to-world
sudo fluxvm --config /etc/fluxvm.toml cnp delete web-egress
```

## Next

- [08 — Audit mode](08-audit-mode.md)
- [09 — Observe](09-observe.md)
