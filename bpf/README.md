# FluxVM TC classifier / XDP objects

Network Fabric **v3** BPF sources for the optional `ebpf` / `cilium` sandbox
dataplane.

| File | Role |
|------|------|
| `fluxvm_tc.bpf.c` | VM-edge TC classifier: IPv4/IPv6 L3 + L4 allow/deny, group identities, CT, ICMP, Mbps/PPS, stats, flows, events |
| `fluxvm_xdp.bpf.c` | Optional node-ingress XDP IPv4/IPv6 source-CIDR blocklist (disabled by default; refused in `cilium` mode) |

## Map layout (TC)

```mermaid
flowchart LR
  Pkt[Packet] --> Id[fluxvm_id]
  Id --> V4[fluxvm_v4]
  Id --> V6[fluxvm_v6]
  Id --> L4[fluxvm_l4]
  Id --> Rate[fluxvm_rate]
  Id --> Stats[fluxvm_stats]
  Id --> Flows[fluxvm_flows]
  Id --> Ev[fluxvm_events]
```

Build:

```bash
./scripts/build-ebpf.sh
# outputs: dist/bpf/fluxvm_tc.bpf.o  dist/bpf/fluxvm_xdp.bpf.o
```

Validate (syntax + optional build/tests/smoke):

```bash
../scripts/validate-network-fabric.sh
FLUXVM_PRIVILEGED_SMOKE=1 ../scripts/validate-network-fabric.sh
```

Docs: [docs/network-fabric.md](../docs/network-fabric.md),
[docs/ebpf-cilium.md](../docs/ebpf-cilium.md),
[README architecture](../README.md#network-fabric-architecture-how-it-works).
