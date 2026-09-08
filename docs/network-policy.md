# Network policy on the FluxVM VM-edge

FluxVM is not a CNI. This document is the supported **CNP-shaped** policy
subset that compiles onto **Network Fabric (GA; dataplane schema v4)** pins
under `/sys/fs/bpf/fluxvm`.

Coexistence with a node CNI (`mode=cilium`) is separate — see
[ebpf-cilium.md](ebpf-cilium.md). That mode only *checks* the agent socket;
FluxVM never writes foreign private BPF maps.

Production runbook: [production-dataplane.md](production-dataplane.md).
Security groups: [network-groups.md](network-groups.md).

## Mapped features

| Concept | FluxVM |
|---------|--------|
| Numeric identities (`reserved:world=2`, local ≥256) | `identity.rs` + group FNV ≥ `0x10000` |
| `endpointSelector.matchLabels` | Group labels `app=web` |
| CNP document (`kind` NetworkPolicy / CNP JSON) | `POST /v1/network/cnp`, `fluxvm cnp apply` |
| `toCIDR` / `toCIDRSet` / `except` | `allow_cidrs` / `deny_cidrs` |
| `toEntities` world/host/cluster/remote-node | Entity → CIDR expansion |
| `toFQDNs` | Resolve to IPv4/32 + IPv6/128 at apply; wildcards skipped |
| `toPorts` + ranges + named ports | `tcp/443`, `tcp/8000-8003`, `https`→443 |
| `egressDeny` / `ingressDeny` | `fluxvm_deny4/6` before allow |
| `enableDefaultDeny` | `default_allow=false` |
| `auditMode` | sample_rate bit 31; log drop, forward packet |
| Conntrack | `fluxvm_ct` LRU learn/hit |
| Identity list | `GET /v1/network/identities`, `fluxvm identity list` |
| Group / identity policy | `fluxvm_gid` written at configure_maps |
| Observe snapshot | `GET /v1/network/observe`, `fluxvm observe` |
| toFQDNs live refresh | `POST /v1/network/refresh-dns`, `fluxvm dataplane refresh-dns` |
| ipcache | Guest IP → identity (`GET /v1/network/ipcache`) |
| Production health | `fluxvm dataplane health`, [production-dataplane.md](production-dataplane.md) |

Not in scope for **this** policy plane: kube-proxy replacement, WireGuard/IPsec
datapath, L7 Envoy/Kafka parsers, ClusterMesh, or a full flow UI.

Maglev / DSR / SNAT service LB lives in **Service Fabric v5 (BPF schema 4)**
([service-fabric.md](service-fabric.md)), not in CNP/group compilers.

## Apply a CNP

```bash
fluxvm cnp apply --spec examples/cnp-web.json
fluxvm cnp list
fluxvm identity list
fluxvm observe
```

Label the VM policy so the compiled group matches:

```json
{ "labels": ["app=web"], "default_allow": false }
```

## Tutorials

Hands-on Network Fabric policy guides:

**[docs/tutorials/network-policy/](tutorials/network-policy/README.md)** —
getting started, identities, security groups, CNP, default deny, named ports,
entities/FQDNs, audit mode, observe, multi-group merge.

## Tests

```bash
python3 scripts/test-network-policy.py
cargo test -p fluxvm-network --lib
python3 scripts/test-production-dataplane.py
sudo -E ./scripts/test-security-groups-e2e.sh
sudo -E ./scripts/test-production-dataplane-e2e.sh
```
