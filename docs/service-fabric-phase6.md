# Service Fabric Phase 6

## Shipped on main

BPF **schema 4** is unchanged. FluxVM **program generation 8** covers
connect{4,6} + affinity parity, map-tier ELF selection, and pressure/offload
status (value ABI still schema 4).

| Item | Status |
|------|--------|
| Identity-aware service policy (ipcache → `fluxvm_spol` / `sid4` / `sid6`) | shipped (v6) |
| Default allow/deny, allow/deny identities, audit-only | shipped (v6) |
| Envoy HTTP/gRPC transparent redirect contract | shipped (v6) |
| Bypass-mark loop prevention | shipped (v6) |
| Fabric multi-node policy fan-out with snapshot/rollback | shipped (v6) |
| HA mutation queue (`fluxvm_haq`) + userspace drain | shipped (v6) |
| Opt-in **cgroup/connect4+connect6** acceleration (fail-open to TC/XDP) | shipped |
| **Adaptive map pressure** controller (`map_tier`, soft/hard %, reload) | shipped |
| **Compile-time map tier ELFs** (`-DFLUXVM_MAP_TIER=S\|M\|L`) | shipped |
| **RSS/offload / XDP mode** validation in `services/status` | shipped |
| **Perf qualification** harness `scripts/test-service-fabric-perf.sh` | shipped |
| **Perf / RSS SLO gates** (`SLO_*` env + `scripts/test-service-fabric-slo.sh`) | shipped |
| Fabric **site_id / route_domain** anycast + policy fencing | shipped (minimal) |
| **Remote ipcache write APIs** (`POST/DELETE /v1/network/ipcache/remote`) for Fabric ClusterMesh-like directory fan-out | shipped (minimal) |

### Map tier objects

`./scripts/build-ebpf.sh` emits default **M** objects plus explicit tier ELFs:

- `fluxvm_service.bpf.o` / `_xdp` / `_connect` — default M
- `fluxvm_service_tier_{S,M,L}.bpf.o` (and matching xdp/connect)

Capacities come from `bpf/fluxvm_service_maps.bpf.h`. Config
`[sandbox.dataplane.service] map_tier = "S"|"M"|"L"` selects the object under
`/usr/lib/fluxvm/bpf/` (override with `FLUXVM_SERVICE_BPF_OBJECT` /
`FLUXVM_SERVICE_XDP_OBJECT` / `FLUXVM_SERVICE_CONNECT_OBJECT`). Changing tier
rewrites pin roots via a `.map_tier` marker (no schema bump).

### SLO harness

`scripts/test-service-fabric-perf.sh` accepts optional gates:

| Env | Check |
|-----|--------|
| `SLO_VIP_P99_MS` | VIP connect p99 ≤ threshold (requires `VIP=`) |
| `SLO_PRESSURE_IDLE=1` | pressure action must not be `hard_reload` |
| `SLO_REQUIRE_CHANNELS=1` | when NS ifaces configured, status must report RSS channels |
| `SLO_CI_SHAPE=1` | status `program_generation` + pressure JSON shape (VIP optional) |

`scripts/test-service-fabric-slo.sh` sets `SLO_CI_SHAPE=1` and delegates.
Lab numeric thresholds remain operator-set.

Operator doc: [service-fabric.md](service-fabric.md) ·
[v6 notes](service-fabric-v6-phase6.md) · Fabric:
[ebpf-service-fabric.md](https://github.com/zyvorai/fabric/blob/main/docs/ebpf-service-fabric.md).

## Remaining candidates

Still open after this tranche:

1. **Automated multi-queue RSS affinity tests** under load (status reports channels; no PPS gate in CI yet).
2. **Broader perf lab gates** in CI (CPU/Mpps, EDT fairness, failover loss window) — harness + SLO hooks exist; lab numbers not universal.
3. **Full mesh datapath** beyond the minimal remote identity directory (Fabric catalog + remote ipcache upsert/delete).

Ownership remains unchanged: FluxVM owns local packet/runtime mechanics; Fabric owns distributed leases, routing, service discovery, multi-site policy and HA coordination.
