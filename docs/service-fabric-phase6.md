# Service Fabric Phase 6

## Shipped on main

BPF **schema 4** is unchanged. FluxVM **program generation 7** covers the
post-v6 ops tranche (connect / pressure / offload status).

| Item | Status |
|------|--------|
| Identity-aware service policy (ipcache → `fluxvm_spol` / `sid4` / `sid6`) | shipped (v6) |
| Default allow/deny, allow/deny identities, audit-only | shipped (v6) |
| Envoy HTTP/gRPC transparent redirect contract | shipped (v6) |
| Bypass-mark loop prevention | shipped (v6) |
| Fabric multi-node policy fan-out with snapshot/rollback | shipped (v6) |
| HA mutation queue (`fluxvm_haq`) + userspace drain | shipped (v6) |
| Opt-in **cgroup/connect4** acceleration (fail-open to TC/XDP) | shipped |
| **Adaptive map pressure** controller (`map_tier`, soft/hard %, reload) | shipped |
| **RSS/offload / XDP mode** validation in `services/status` | shipped |
| **Perf qualification** harness `scripts/test-service-fabric-perf.sh` | shipped |
| Fabric **site_id / route_domain** anycast + policy fencing | shipped (minimal) |

Operator doc: [service-fabric.md](service-fabric.md) ·
[v6 notes](service-fabric-v6-phase6.md) · Fabric:
[ebpf-service-fabric.md](https://github.com/zyvorai/fabric/blob/main/docs/ebpf-service-fabric.md).

## Remaining candidates

Still open after this tranche:

1. **cgroup/connect6** and full Maglev affinity parity with TC (connect4 is VIP→Ready Maglev only).
2. **Compile-time map tier ELFs** (`-DFLUXVM_MAP_TIER=L`) published as alternate objects — today `map_tier` is a label + pressure policy; resize still needs rebuild/reload.
3. **Automated multi-queue RSS affinity tests** under load (status reports channels; no PPS gate in CI yet).
4. **Broader perf lab gates** in CI (CPU/Mpps, EDT fairness, failover loss window) — harness exists, lab numbers not yet SLOs.
5. **Full ClusterMesh-like identity sync** across sites (remote identity directory); current fencing only scopes advertise/policy by `site_id`/`route_domain`.

Ownership remains unchanged: FluxVM owns local packet/runtime mechanics; Fabric owns distributed leases, routing, service discovery, multi-site policy and HA coordination.
