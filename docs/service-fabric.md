# FluxVM Service Fabric v3

FluxVM is the node-local service dataplane. Zyvor Fabric is the distributed control plane.

## Dataplane

Service Fabric v3 supports dual-stack TCP/UDP VIPs, weighted Maglev, NAT, routed DSR, SNAT, VM-edge TC, north-south TC and optional XDP acceleration.

The v3 lifecycle maps add **forward conntrack**. New flows select a Ready backend through Maglev and pin that backend. Existing flows keep their backend when weights or Maglev membership change. A Draining backend is removed from new-flow selection while established flows remain pinned. Unhealthy backends are not retained.

Timeouts are protocol/state aware: TCP SYN, established, FIN and RST use separate deadlines; UDP uses its own deadline. Userspace GC removes expired entries and entries whose drain deadline passed.

## Backend state

```json
{
  "address": "10.40.1.21",
  "port": 8443,
  "weight": 2,
  "enabled": true,
  "state": "draining",
  "drain_until_unix_ms": 1788850000000
}
```

States:

- `ready`: eligible for new and established flows;
- `draining`: existing pinned flows only;
- `unhealthy`: excluded and existing affinity is allowed to fail over.

## Active health

A service can request node-local TCP connect health checks:

```json
"health_check": {
  "kind": "tcp",
  "timeout_ms": 500,
  "unhealthy_threshold": 3,
  "healthy_threshold": 2
}
```

Health is runtime overlay state. FluxVM never rewrites Fabric's durable backend state. UDP/application health belongs in an application-aware control-plane probe rather than a generic UDP packet test.

## VIP advertisement boundary

FluxVM does not embed a BGP control plane. It publishes an atomic snapshot at:

```text
/run/fluxvm/service-advertisements.json
```

The snapshot contains VIP/prefix, generation and advertise/withdraw decision. An FRR/BIRD/Fabric routing adapter consumes this contract. A VIP is withdrawn if Fabric's node intent has `advertise=false` or if the node has no Ready backend.

This keeps BGP session ownership and edge election in Fabric while keeping local readiness enforcement in FluxVM.

## HA state transfer

The REST contract can export/import only these service-owned maps:

- `fluxvm_fct4`, `fluxvm_fct6`;
- `fluxvm_nat4`, `fluxvm_nat6`.

Import verifies schema, service name/id and a fixed map allowlist. Fabric decides if/when a standby edge should receive this state.

## Safety

- frontend hit with no eligible backend: drop;
- map update: fail closed with the service guard;
- XDP FIB miss: untouched packet falls through to TC;
- foreign/Cilium XDP: FluxVM refuses replacement;
- service schema changes rebuild owned pin roots instead of reusing incompatible maps;
- service-catalog updates preserve lifecycle state maps;
- imported HA state cannot target arbitrary BPF maps.
