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
| **Universal CI Mpps / EDT / failover gates** (`SLO_CI=1` defaults) | shipped |
| **RSS under-load PPS gate** (`scripts/test-service-fabric-rss.sh`) | shipped |
| Fabric **site_id / route_domain** anycast + policy fencing | shipped (minimal) |
| **Remote ipcache write APIs** (`POST/DELETE /v1/network/ipcache/remote`) for Fabric ClusterMesh-like directory fan-out | shipped (minimal) |
| **Full mesh datapath (remote backends)** via Fabric Maglev service upsert merge | shipped (v1; Fabric-owned) |
| Geneve / VXLAN service tunnels | N/A (L3/anycast + remote backends) |

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

`scripts/test-service-fabric-perf.sh` accepts optional gates. With **`SLO_CI=1`**
(set by `scripts/test-service-fabric-slo.sh`), universal CI defaults apply
(overridable by env):

| Env | CI default | Check |
|-----|------------|--------|
| `SLO_VIP_P99_MS` | `25` when `VIP=` set; else skip | VIP connect p99 ≤ threshold |
| `SLO_PRESSURE_IDLE` | `1` | pressure action must not be `hard_reload` |
| `SLO_EDT_FAIRNESS` | `1` | if any service has `max_egress_mbps`: require `edt_packets` present/non-absurd; **skip** when EDT not configured |
| `SLO_FAILOVER_LOSS_MS` | `500` | when `FABRIC_URL`+`SERVICE` set: HA delta fetch RTT ≤ threshold; else skip |
| `SLO_MPPS_MIN` | `0.01` | synthetic connect-burst Mpps vs VIP; skip if no VIP |
| `SLO_CI_SHAPE` | `1` | status `program_generation` + pressure JSON shape (VIP optional) |
| `SLO_REQUIRE_CHANNELS` | (unset) | when NS ifaces configured, status must report RSS channels |

RSS under-load PPS (`scripts/test-service-fabric-rss.sh`, also invoked from the
SLO wrapper):

| Env | Default | Check |
|-----|---------|--------|
| `SLO_RSS_PPS_MIN` | `1000` | measured iface/service PPS under short VIP storm |
| `SLO_RSS_STRICT` | (unset) | fail when channels null on dummy ifaces; else soft-skip |
| `RSS_IFACE` | from status | override north-south iface |

CI without VIP/API soft-skips load gates; shape gates still run when status is reachable.

Operator doc: [service-fabric.md](service-fabric.md) ·
[v6 notes](service-fabric-v6-phase6.md) · Fabric:
[ebpf-service-fabric.md](https://github.com/zyvorai/fabric/blob/main/docs/ebpf-service-fabric.md).

## Remaining candidates

Still open after this tranche:

1. **Stricter multi-queue RSS affinity** (pin flows, assert queue mapping) — under-load PPS + best-effort multi-queue RX shipped; full affinity proofs still lab-only.
2. **CPU / higher Mpps lab ceilings** beyond the universal CI floor (`SLO_MPPS_MIN=0.01`).

**Full mesh datapath** (remote backends / endpoint mesh) is owned by Fabric:
catalog + reconcile merges peer Ready backends into existing Maglev service
upserts. FluxVM needs no new tunnel APIs; Geneve/VXLAN remain N/A.

Ownership remains unchanged: FluxVM owns local packet/runtime mechanics; Fabric owns distributed leases, routing, service discovery, multi-site policy and HA coordination, remote identity directory, and remote backend mesh.
