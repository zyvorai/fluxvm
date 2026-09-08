# Service Fabric Phase 5 — delivered tranche

This cumulative tranche delivers the state-plane/HA layer on top of v4 while
deliberately retaining the v4 TC/XDP ABI (`SERVICE_SCHEMA_VERSION=4`).

## Delivered

1. **Bounded HA delta journal in FluxVM**
   - monotonic sequence numbers;
   - source acknowledgement watermark;
   - bounded replay retention;
   - gap detection and explicit `reset_required`;
   - full-snapshot barrier for history gaps;
   - per-service standby replay cursor;
   - whitelisted conntrack/NAT maps only (`fct4/6`, `nat4/6`).

2. **Streaming/delta replication orchestration in Fabric**
   - durable per source/target cursor store;
   - per-target catch-up loops;
   - full-snapshot fallback on a journal gap;
   - source journal acknowledgement only to the **minimum** replicated target cursor;
   - replay-safe idempotent target import.

3. **Durable edge lease controller**
   - atomic JSON state store;
   - persistent per-service fencing epoch high-water marks (no ABA reuse);
   - healthy lease expiry extension without epoch churn;
   - expired-lease compaction while retaining epoch history;
   - withdraw-before-release for unhealthy edges;
   - deterministic replacement selection;
   - replacement staged with advertisement disabled;
   - conntrack state seeded before advertisement;
   - local FluxVM advertisement readiness verified before the replacement counts as active.

4. **Incremental BPF service-intent reconciliation**
   - desired map image calculated in userspace;
   - unchanged map entries left untouched;
   - only changed/new entries updated; stale intent deleted;
   - forward conntrack, reverse NAT and backend telemetry remain lifecycle state;
   - update guard remains fail-closed if reconciliation fails.

## REST (new)

```text
GET  /v1/network/services/{name}/conntrack/delta?after_seq=0&max_entries=1024
POST /v1/network/services/{name}/conntrack/delta/import
POST /v1/network/services/{name}/conntrack/delta/ack
```

Fabric proxies the same paths under `/api/dataplane/services/…`.

HA conntrack export/import/delta/ack and `advertise=true` require configured
`[sandbox.dataplane.service] north_south_interfaces` and north-south (or both)
exposure. North-south NAT needs `snat_address`. See
[service-fabric.md](service-fabric.md#ha-state-transfer-v5).

## See also

- Operator: [service-fabric.md](service-fabric.md)
- Phase 4 (shipped): [service-fabric-phase4.md](service-fabric-phase4.md)
- Phase 6 candidates: [service-fabric-phase6.md](service-fabric-phase6.md)
