# FluxVM Service Fabric v3

FluxVM is the **node-local** service dataplane. Zyvor Fabric is the **distributed**
control plane (intent, edge leases, fan-out, BGP/ECMP policy). This document covers
what FluxVM owns and exposes.

Related: [Fabric contract](https://github.com/zyvorai/fabric/blob/main/docs/ebpf-service-fabric.md) ·
[ownership boundary](https://github.com/zyvorai/fabric/blob/main/docs/FLUXVM-FABRIC-BOUNDARY.md) ·
[phase 4 candidates](service-fabric-phase4.md).

## Dataplane

Service Fabric **schema v3** supports:

- dual-stack TCP/UDP VIPs;
- weighted Maglev;
- NAT and routed DSR;
- collision-safe SNAT with symmetric reverse NAT;
- VM-edge TC and north-south TC;
- optional XDP acceleration sharing TC maps;
- **forward conntrack** affinity across Maglev/backend membership changes.

New flows select a **Ready** backend through Maglev and pin that backend. Existing
flows keep their backend when weights or Maglev membership change. A **Draining**
backend is removed from new-flow selection while established flows remain pinned.
**Unhealthy** backends are not retained (affinity may fail over).

Timeouts are protocol/state aware: TCP SYN, established, FIN and RST use separate
deadlines; UDP uses its own deadline. Userspace GC removes expired entries and
entries whose drain deadline passed.

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

| State | New flows | Established affinity |
|-------|-----------|----------------------|
| `ready` | yes | yes |
| `draining` | no | yes (until expiry / drain deadline) |
| `unhealthy` | no | may fail over |

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

Health is **runtime overlay** state. FluxVM never rewrites Fabric's durable backend
intent. UDP/application health belongs in an application-aware control-plane probe.

Reconcile: `POST /v1/network/services/health/reconcile`. Report:
`GET /v1/network/services/health`.

## VIP advertisement boundary

FluxVM does **not** embed a BGP control plane. It publishes an atomic snapshot at:

```text
/run/fluxvm/service-advertisements.json
```

(also `GET /v1/network/services/advertisements`). The snapshot contains VIP/prefix,
generation and advertise/withdraw decision. An FRR/BIRD/Fabric routing adapter
consumes this contract. A VIP is withdrawn if Fabric's node intent has
`advertise=false` or if the node has no Ready backend.

## HA state transfer

Export/import is restricted to these service-owned maps:

- `fluxvm_fct4`, `fluxvm_fct6` (forward affinity);
- `fluxvm_nat4`, `fluxvm_nat6` (reverse NAT).

Import verifies schema version, service name/id and a fixed map allowlist. Fabric
decides if/when a standby edge should receive this state.

## REST surface

```text
GET    /v1/network/services
POST   /v1/network/services
GET    /v1/network/services/status          # schema_version, interfaces, XDP
GET    /v1/network/services/stats
GET    /v1/network/services/health
POST   /v1/network/services/health/reconcile
POST   /v1/network/services/conntrack/gc
GET    /v1/network/services/advertisements
GET    /v1/network/services/{name}
DELETE /v1/network/services/{name}
GET    /v1/network/services/{name}/conntrack/export
POST   /v1/network/services/{name}/conntrack/import
GET    /v1/vms/{id}/network/services/stats
```

East-west Maglev example:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @docs/examples/service-fabric-v3-east-west.json \
  http://127.0.0.1:7788/v1/network/services
```

## BPF objects

| Object | Role |
|--------|------|
| `fluxvm_service.bpf.o` | TC Maglev / NAT / DSR / affinity |
| `fluxvm_service_xdp.bpf.o` | Optional north-south XDP (reuses TC pinmaps) |

Build: `./scripts/build-ebpf.sh`. Install under `/usr/lib/fluxvm/bpf/`. Schema bumps
rebuild owned pin roots instead of reusing incompatible maps. Service-catalog
updates preserve lifecycle state maps (`fct*`, `nat*`).

## Safety

- frontend hit with no eligible backend: drop;
- map update: fail closed with the service guard;
- XDP FIB miss: untouched packet falls through to TC;
- foreign/Cilium XDP: FluxVM refuses replacement;
- never write Cilium/CNI private maps;
- learn affinity **before** `fib_redirect` / `bpf_skb_store_bytes` (packet pointers invalidate after helpers).

## Roadmap history

| Phase | Status | Doc |
|-------|--------|-----|
| v1 east-west Maglev | shipped | — |
| v2 dual-stack DSR/SNAT/XDP | shipped | [phase-2 archive](service-fabric-phase-2.md) |
| v3 affinity/health/drain/HA ads | **current** | this page |
| Phase 4 (perf / BGP adapter / OTLP) | candidates | [service-fabric-phase4.md](service-fabric-phase4.md) |
