# Set 10 — QUIC-aware Load Balancing and SmartNIC Readiness

Set 10 is a node-local XDP DSR accelerator for QUIC/UDP services. Fabric remains the owner of distributed service intent, BGP/ECMP and remote-node routing; this component only selects among backends that are explicitly reachable by a local redirect interface.

## QUIC affinity

Long headers carry an encoded DCID length, so Set 10 extracts up to 20 bytes directly. Short headers do not encode DCID length; `short_dcid_len` is therefore a service contract. A non-zero value gives CID affinity across client-address/port migration. If it is zero, short-header packets use a 5-tuple affinity key unless `quic_only` causes non-recognized traffic to pass to the normal stack.

A generation-independent affinity map retains a selected backend across configuration generations while that backend remains Ready or Draining. Unhealthy/missing backends are reselected from the active Maglev generation. New flows never select Draining or Unhealthy backends.

## Atomic updates

Service, backend and Maglev keys contain a generation. Userspace writes the full new generation and publishes one `active_generation` array entry last. The old generation is garbage-collected only after publication. An interrupted update therefore exposes either the old complete generation or the new complete generation; it never exposes a partially populated table.

## Migration-safe affinity

`affinity-export` serializes only real QUIC CID bindings, not 5-tuple fallbacks. `affinity-import` accepts bindings only when the destination instance has the same service ID and the backend ID is still Ready/Draining. The source `last_seen_ns` is retained as audit metadata but is deliberately not imported into the kernel map because monotonic clocks are host-local.

```bash
fluxvm-quiclb affinity-export <instance> affinity.json
# copy as part of the VM/service migration transaction
fluxvm-quiclb affinity-import <instance> affinity.json
```

## DSR contract

The XDP program changes only the Ethernet destination MAC and redirects to a configured backend interface. The VIP remains the packet's IP destination. Every backend must own the VIP locally (normally loopback) and return traffic directly. Set 10 deliberately does not implement reverse NAT or distributed routing.

## XDP ownership

The loader uses `XDP_FLAGS_UPDATE_IF_NOEXIST` and first checks native, generic and hardware XDP modes. It refuses to replace any existing program, including Cilium. Detach also verifies the live program ID matches the pinned FluxVM program before removing it.

## SmartNIC readiness

`fluxvm-quiclb probe <iface>` records driver/bus information and runs `bpftool feature probe dev`. `eligible_hint` is only preflight. The hardware object is compiled with `FLUXVM_QUICLB_OFFLOAD_PROFILE`, which replaces LRU affinity with bounded HASH state and omits ring-buffer events, but the NIC driver's real BPF verifier/load is authoritative.

Hardware mode also requires the explicit `--ack-hardware-offload` flag at apply time. FluxVM sets program/map ifindex before `BPF_PROG_LOAD`; if the device cannot offload one of the program or map features, startup fails rather than falling back silently to host-native XDP.

## Example

```json
{
  "instance_id": "1d9016f2-8957-42bc-9dd7-32d684d76446",
  "interface": "edge0",
  "mode": "native",
  "services": [{
    "name": "quic-api",
    "vip": "203.0.113.80",
    "port": 443,
    "short_dcid_len": 8,
    "quic_only": true,
    "maglev_table_size": 4093,
    "backends": [
      {"id": 1, "interface": "vm-edge-a", "mac": "02:00:00:00:01:01", "weight": 1, "state": "ready"},
      {"id": 2, "interface": "vm-edge-b", "mac": "02:00:00:00:01:02", "weight": 1, "state": "ready"}
    ]
  }]
}
```

```bash
fluxvm-quiclb probe edge0
fluxvm-quiclb plan spec.json plan.json
sudo fluxvm-quiclb apply plan.json
fluxvm-quiclb status 1d9016f2-8957-42bc-9dd7-32d684d76446
fluxvm-quiclb events 1d9016f2-8957-42bc-9dd7-32d684d76446 10 256
```

IPv6 v1 supports direct UDP after the base IPv6 header. Extension-header walking is intentionally left to a later verifier-portability pass. VLAN parsing supports up to two tags.
