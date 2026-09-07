# Cilium parity on the FluxVM VM-edge

FluxVM is not a CNI and does not write Cilium-private maps. This document is
the supported **semantic** subset of Cilium that compiles onto Network Fabric
v4 pins under `/sys/fs/bpf/fluxvm`.

## Mapped features

| Cilium | FluxVM |
|--------|--------|
| Numeric identities (`reserved:world=2`, local ≥256) | `identity.rs` + group FNV ≥ `0x10000` |
| `endpointSelector.matchLabels` | Group labels `app=web` |
| `CiliumNetworkPolicy` | `POST /v1/network/cnp`, `fluxvm cnp apply` |
| `toCIDR` / `toCIDRSet` / `except` | `allow_cidrs` / `deny_cidrs` |
| `toEntities` world/host/cluster/remote-node | Entity → CIDR expansion |
| `toFQDNs` | Stored on policy; resolve with existing domain allowlist |
| `toPorts` + ranges | `tcp/443`, `tcp/8000-8003` expanded (≤256) |
| `egressDeny` / `ingressDeny` | `fluxvm_deny4/6` before allow |
| `enableDefaultDeny` | `default_allow=false` |
| `auditMode` | sample_rate bit 31; log drop, forward packet |
| Conntrack | `fluxvm_ct` LRU learn/hit |
| Hubble identities | `GET /v1/network/identities`, `fluxvm identity list` |
| Group / identity policy | `fluxvm_gid` written at configure_maps |
| Cilium agent coexistence | `mode=cilium` still only *checks* `cilium.sock` |

Not in this PR (would be a separate CNI/endpoint program): kube-proxy
replacement, Maglev/DSR service LB, WireGuard/IPsec encryption datapath,
L7 Envoy/Kafka parsers, ClusterMesh, Hubble UI.

## Apply a CNP

```bash
fluxvm cnp apply --spec examples/cilium-network-policy-web.json
fluxvm cnp list
fluxvm identity list
fluxvm observe
```

Label the VM policy so the compiled group matches:

```json
{ "labels": ["app=web"], "default_allow": false }
```

## Tutorials (Cilium-style)

Hands-on guides modeled on Cilium’s getting-started docs:

**[docs/tutorials/cilium/](tutorials/cilium/README.md)** — getting started,
identities, security groups, CNP, default deny, named ports, entities/FQDNs,
audit mode, observe, multi-group merge.

## Tests

```bash
python3 scripts/test-cilium-parity.py
cargo test -p fluxvm-network --lib
```
