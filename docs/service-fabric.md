# FluxVM Service Fabric v6 (BPF schema 4)

FluxVM is the **node-local** service dataplane. Zyvor Fabric is the **distributed**
control plane (intent, edge leases, fan-out, BGP/ECMP policy). **v6** is the current
Maglev VIP plane; the TC/XDP **BPF value ABI remains schema 4** with **program
generation 6** (additive maps / reload guard — not a `svc_value` layout bump).

Related: [Fabric contract](https://github.com/zyvorai/fabric/blob/main/docs/ebpf-service-fabric.md) ·
[ownership boundary](https://github.com/zyvorai/fabric/blob/main/docs/FLUXVM-FABRIC-BOUNDARY.md) ·
[phase 4](service-fabric-phase4.md) ·
[phase 5](service-fabric-phase5.md) ·
[phase 6 (shipped + remaining)](service-fabric-phase6.md).

## Dataplane

Service Fabric **v6** builds on v5 HA/leases while keeping BPF **schema 4**. The
dataplane includes everything from v5:

- dual-stack TCP/UDP VIPs;
- weighted Maglev;
- NAT and routed DSR;
- collision-safe SNAT with symmetric reverse NAT;
- VM-edge TC and north-south TC;
- optional XDP acceleration sharing TC maps;
- **forward conntrack** affinity across Maglev/backend membership changes;
- **per-service EDT** pacing (`max_egress_mbps`) when `edt_enabled` is set;
- **FluxScope** service flows (`fluxvm_sflows`) + optional OTLP export;
- opt-in **host_routing** FIB fast path after NAT (miss → host stack);
- and **v6** additions below.

New flows select a **Ready** backend through Maglev and pin that backend. Existing
flows keep their backend when weights or Maglev membership change. A **Draining**
backend is removed from new-flow selection while established flows remain pinned.
**Unhealthy** backends are not retained (affinity may fail over).

Timeouts are protocol/state aware: TCP SYN, established, FIN and RST use separate
deadlines; UDP uses its own deadline. Userspace GC removes expired entries and
entries whose drain deadline passed.

## v6 — identity policy, L7 redirect, HA mutation queue

Additive control/state plane (does **not** change `svc_value` / NAT / conntrack
value layouts):

| Capability | Behavior |
|------------|----------|
| Identity-aware service policy | Default allow/deny + allow/deny identity lists + `audit_only`; compiled from FluxVM ipcache into `fluxvm_spol` / `fluxvm_sid4` / `fluxvm_sid6` |
| Unresolved identities | Surfaced in policy status (not silently dropped) |
| Fail-closed reconcile | Reuses `fluxvm_sguard`; generation-6 reloads keep the guard closed until policy maps restore |
| Envoy L7 contract | Optional HTTP/gRPC `observe` / `enforce`; TC owns redirect; XDP returns `XDP_PASS` for L7-enforced VIPs; bypass mark stops redirect loops |
| HA mutation queue | Conntrack/NAT creates/deletes emit 128-byte records into `fluxvm_haq`; userspace drains via `bpf()` (not per-event `bpftool`); v5 snapshot-diff remains the correctness backstop; `fluxvm_hadrop` counts overflows |

Example identity policy (`examples/service-fabric-v6/identity-policy.json`):

```json
{
  "service": "payments-api",
  "enabled": true,
  "default_action": "deny",
  "allow_identities": [1001, 1002],
  "deny_identities": [2001],
  "audit_only": false,
  "l7": null
}
```

L7 / Envoy metadata example: `examples/service-fabric-v6/http-envoy-policy.json`.
`authorities` / `path_prefixes` are control-plane hints for an Envoy/xDS adapter —
eBPF does not parse HTTP.

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

## EDT pacing (v4)

Set `max_egress_mbps` on a service only when `[sandbox.dataplane.service]` has
`edt_enabled = true`. FluxVM compiles a byte rate into the TC service map and
schedules `skb->tstamp` via `fluxvm_edt`. Optional `edt_manage_fq` applies only to
explicitly listed `edt_interfaces`. XDP is never paced (EDT needs TC/qdisc).

## FluxScope flows (v4)

TC and XDP share `fluxvm_sflows`. Records carry service/backend id, addresses,
ports, allow/drop, reason codes, packets/bytes. Export:

```text
GET  /v1/network/services/flows?limit=256
POST /v1/network/services/telemetry/export?limit=1024
```

OTLP/HTTP JSON is off until `otlp_endpoint` is configured. Sampling uses
`flow_sample_rate` (`0` disables).

## Host routing (v4)

For NAT services with `host_routing=true`, FluxVM may `bpf_fib_lookup()` + redirect
after translation. A soft FIB miss (`TC_ACT_UNSPEC`) falls through to the host
stack with `TC_ACT_OK` (not drop). Counters: `host_routed_packets`,
`host_route_fallbacks`.

When backends live on the local host, enable `accept_local` on the VM-edge
interface so DNAT'd flows can reach loopback/local listeners.

## Maglev and VM-edge policy

After a successful Maglev NAT rewrite, the service TC program returns `TC_ACT_OK`
and stops the clsact chain. Sandbox Network Fabric policy therefore does **not**
re-filter the rewritten backend address/port. Operators do **not** need backend
service ports in the VM `allow_ports` list for Maglev-forwarded flows.

## VIP advertisement boundary

FluxVM does **not** embed a BGP control plane. It publishes an atomic snapshot at:

```text
/run/fluxvm/service-advertisements.json
```

(also `GET /v1/network/services/advertisements`). Fabric FRR/BIRD/File adapters
consume this contract. A VIP is withdrawn if Fabric's node intent has
`advertise=false` or if the node has no Ready backend.

## HA state transfer (v5)

Export/import and bounded **delta journal** replication are restricted to these
service-owned maps:

- `fluxvm_fct4`, `fluxvm_fct6` (forward affinity);
- `fluxvm_nat4`, `fluxvm_nat6` (reverse NAT).

Full snapshots use `conntrack/export` + `conntrack/import`. **v5** adds
sequence/ack delta batches (`conntrack/delta`, `…/delta/import`, `…/delta/ack`)
with gap detection, `reset_required`, and full-snapshot fallback on history gaps.
Import verifies schema version, service name/id and a fixed map allowlist. Fabric
decides if/when a standby edge should receive this state and advances source
journal ack only to the minimum replicated target cursor.

**Prerequisites:** configure `[sandbox.dataplane.service] north_south_interfaces`
so north-south TC pin maps exist. HA export/import/delta/ack require that edge.
`advertise=true` requires `exposure` north-south or both. North-south NAT requires
`snat_address` so backend replies return through FluxVM.

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
GET    /v1/network/services/flows
POST   /v1/network/services/telemetry/export
GET    /v1/network/services/{name}
DELETE /v1/network/services/{name}
GET    /v1/network/services/{name}/conntrack/export
POST   /v1/network/services/{name}/conntrack/import
GET    /v1/network/services/{name}/conntrack/delta
POST   /v1/network/services/{name}/conntrack/delta/import
POST   /v1/network/services/{name}/conntrack/delta/ack
GET    /v1/vms/{id}/network/services/stats

# v6 identity / L7 policy (admin for mutations)
GET    /v1/network/services/policies
POST   /v1/network/services/policies
POST   /v1/network/services/policies/reconcile
GET    /v1/network/services/{name}/policy
DELETE /v1/network/services/{name}/policy
GET    /v1/network/services/{name}/l7/envoy
```

East-west Maglev example:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @docs/examples/service-fabric-v4-east-west.json \
  http://127.0.0.1:7788/v1/network/services
```

East-west VIP smoke (operator):

- A Maglev VIP is not on the same L2 as the client — do not expect gratuitous ARP.
- Route the VIP via the guest default gateway (netns edge or host route).
- Ensure no orphan host veths share the same `169.254.x.1/28` (see
  [network-fabric.md](network-fabric.md#named-netns-and-orphan-edges)).

## BPF objects

| Object | Role |
|--------|------|
| `fluxvm_service.bpf.o` | TC Maglev / NAT / DSR / affinity / EDT / flows / v6 policy + HA queue |
| `fluxvm_service_xdp.bpf.o` | Optional north-south XDP (reuses TC pinmaps + `fluxvm_sflows`) |
| `fluxvm_service_v6.bpf.h` | Shared v6 map/event layouts (compile-time size assertions) |

Build: `./scripts/build-ebpf.sh`. Install under `/usr/lib/fluxvm/bpf/`. Schema bumps
rebuild owned pin roots instead of reusing incompatible maps. **Program generation 6**
forces a reload of older pins before policy reconcile can succeed. Service-catalog
updates preserve lifecycle state maps (`fct*`, `nat*`).

## Safety

- frontend hit with no eligible backend: drop;
- map update: fail closed with the service guard;
- `max_egress_mbps` without `edt_enabled`: reject apply;
- XDP FIB miss: untouched packet falls through to TC;
- host-routing FIB miss: fallback to host stack with `TC_ACT_OK`;
- after Maglev NAT rewrite: `TC_ACT_OK` stops clsact (VM policy does not see backend port);
- foreign/Cilium XDP: FluxVM refuses replacement;
- never write Cilium/CNI private maps;
- learn affinity **before** `fib_redirect` / `bpf_skb_store_bytes` (packet pointers invalidate after helpers);
- v6 policy inputs are bounded; L7 enforce is TCP+NAT only and needs a nonzero proxy ifindex;
- generation-6 reload stays fail-closed until additive policy maps restore;
- HA queue overflow is counted (`fluxvm_hadrop`); snapshot-diff remains the backstop.

## Roadmap history

| Phase | Status | Doc |
|-------|--------|-----|
| v1 east-west Maglev | shipped | — |
| v2 dual-stack DSR/SNAT/XDP | shipped | [phase-2 archive](service-fabric-phase-2.md) |
| v3 affinity/health/drain/HA ads | shipped | — |
| v4 EDT / FluxScope / host-routing | shipped | [phase4](service-fabric-phase4.md) |
| v5 HA deltas / durable leases / incremental reconcile | shipped | [phase5](service-fabric-phase5.md) |
| v6 identity policy / Envoy L7 / HA mutation queue | **current** | [phase6](service-fabric-phase6.md) · [v6 notes](service-fabric-v6-phase6.md) |
| Later | candidates | remaining bullets in [phase6](service-fabric-phase6.md) |