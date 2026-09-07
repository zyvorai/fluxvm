# Packet flow (Hubble-style)

FluxVM samples **VM-edge** flows from the TC/eBPF dataplane and renders them
the way operators use `hubble observe`: a verdict, a 5-tuple, identities, and
an explicit hop path.

This is **not** Cilium Hubble gRPC and it does **not** write Cilium-private
maps. On `mode=cilium` the path includes a coexistence hop only.

## Packet path

Egress (default for the VM-edge allowlist):

```
guest (virtio-net)
  → tap / veth
  → tc clsact + FluxVM eBPF (L3/L4 + optional rate limit)
  → [cilium coexistence, if mode=cilium]
  → host uplink / bridge
  → peer (reserved:world=2 or another identity)
```

Ingress is the reverse, used when the flow destination equals the guest IP.

## CLI — colorful and normal

```bash
# Colorful one-liners (ANSI). NO_COLOR=1 forces plain.
fluxvm hubble observe
fluxvm hubble observe --output color

# Normal / plain text (no ANSI) — logs, tickets, CI
fluxvm hubble observe --output plain
fluxvm hubble observe --output normal

# Full hop path (detailed)
fluxvm hubble observe --detailed
fluxvm hubble flow --output color
fluxvm hubble flow --output plain

# Filters
fluxvm hubble observe --verdict DROPPED --protocol tcp --limit 100

# Machine
fluxvm hubble observe --output json
```

Color map:

| Verdict | Color |
|---------|--------|
| FORWARDED | green |
| DROPPED | red |
| AUDIT | yellow |
| identities / proto | cyan |
| hops | blue |

## REST

| Path | Role |
|------|------|
| `GET /v1/network/hubble/flows` | Hubble-subset JSON + `hops`, `summary`, ports, counters |
| `GET /v1/network/hubble/flows/text?output=color&detailed=true` | ANSI or plain text |
| `GET /v1/network/hubble/flows/text?output=plain&verdict=DROPPED` | normal text |
| `GET /v1/network/hubble/ui` | UI with **Colorful** / **Normal** theme toggle |
| `GET /v1/network/endpoints` | CiliumEndpoint-shaped views |

Query: `limit`, `verdict`, `protocol`, `output`, `detailed`.

```bash
curl -sS 'http://127.0.0.1:7788/v1/network/hubble/flows'
curl -sS 'http://127.0.0.1:7788/v1/network/hubble/flows/text?output=plain&detailed=true'
xdg-open http://127.0.0.1:7788/v1/network/hubble/ui
```

## Identities

Same reserved space as Cilium `toEntities`: `host=1`, `world=2`, local VM
identities from `ebpf::identity_for`.

## Tests

```bash
# in crates/fluxvm-network
cargo test -p fluxvm-network packetflow
```
