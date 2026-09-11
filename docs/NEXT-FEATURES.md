# Next features (ranked)

Living backlog after Secure Containers Set 18 (EndpointSlice-aware Service
VIP policy), Set 17 (rule-attributed NetworkPolicy telemetry) and Set 16
(conntrack revocation safety + VM-level SCTP), plus Sentinel's operational
tooling — Set 12E (GA certification / evidence gates), Set 13E (migration
orchestrator), Set 14E (stateful upgrade manager), Set 15E (fleet rollout +
canary controller), Set 16E (fleet drift & SLO guard) — and in-tree KVM
FC/CH parity (P0–P2). Prefer closing proven gates over inventing new wire
formats.

## Sentinel / Secure Containers (highest leverage)

| Priority | Feature | Why | Source |
|---|---|---|---|
| **S1** | Live stateful conntrack-bypass proof under a real TCP handshake | Bidirectional bypass (set14) and revocation-safe expiry/anti-replay (set16) are both implemented; nothing has yet proven a real handshake crosses a restrictive opposite-direction policy, that a tightened policy revokes an established flow before a new one, or that the SYN/INIT anti-replay check actually fires against live traffic | set14, set16, PRODUCTION |
| **S2** | Multi-node NetworkPolicy conformance | Single-node reconcile is proven; production needs Cilium + ≥1 other CNI, real Pod-to-Pod allow/deny | set14 #4, set13 |
| **S3** | True per-direction counters + rule-hit identity | **Implemented by Set 17** with optional `fluxvm_prhit` (no schema-v8 ABI bump); live production scrape remains a gate | set14 #5, set15, set17 |
| **S4** | EndpointSlice-aware Service VIP policy | **Implemented by Set 18** (EndpointSlice routing proof for opt-in ClusterIP mode); live k8s gate remains optional evidence | set14 #3, set18 |
| **S5** | Indexed LPM/L4 (or verifier-budget raise) | 64-rule linear `fluxvm_prules` scan may become p99-costly | set14 #1 |
| **S6** | IPv6 extension-header walking | Incomplete IPv6 L4 parse under verifier budget; also blocks SCTP behind IPv6 extension headers (set16) | set14 #2, set16 |
| **S7** | Wire Set 8S guest cgroup policy from Pod Set 6S/14 | Containers fail-closed locally but do not inherit Pod policy content | PRODUCTION |
| **S8** | Policy Observer prod sizing + Prometheus scrape | Observer is read-only; needs realistic VM/rule load + scrape wiring | set15 |
| **S9** | Kata P0/P1 gates (OCI fixtures, Multus, hostPath broker, NOTIF_ADDFD, TTY churn, warm-pool claim) | RuntimeClass is not Kata-equivalent yet | secure-containers.md |
| **S10** | Real multi-node fleet rollout run | `fluxvm-fleet` (set15e) is validated against a single loopback-simulated "node" via a local ssh shim; no run has exercised genuinely separate hosts, real SSH host-key trust, or a real multi-node canary/wave/rollback sequence | set15e |
| **S11** | Migration orchestrator against a real attached VM | `fluxvm-migrate` (set13e) was proven against the real `fluxvm dataplane migration-*` CLI surface and its own real failure/rollback path, but not yet against a VM with a live dataplane actually attached, so `migration-export`/`-restore` were never exercised end to end | set13e |

## In-tree hypervisor / agent sandboxes

| Priority | Feature | Why | Source |
|---|---|---|---|
| **H1** | Virtio **device live-state** in `FLUXKVM1` | RAM + all vCPUs snap today; backends re-attach from boot config — Firecracker remains production snap | hypervisor README, agent-sandbox-gaps |
| **H2** | Full virtio-pci BAR / Windows path | `--pci` ECAM + ACPI exist; Windows production stays CH SoT until BAR wiring lands | DESIGN / README |
| **H3** | vhost-net multi-queue bind | `/dev/vhost-net` opens; queues still userspace until full bind | hypervisor boot smoke / DESIGN |
| **H4** | P3 on demand: virtio-fs, live migration, hotplug | Stubs return `Unsupported` until product asks | DESIGN |
| **H5** | Published kvm density / warm-pool numbers | Lab pause+snap exist; claims need measured benches | ROADMAP-DENSITY, benchmarks |

## Fabric / density (adjacent)

| Priority | Feature | Why |
|---|---|---|
| **F1** | Hubble SID attribution for VM traffic | CEP enrich exists; SID for VM flows still open |
| **F2** | Scrape `MICROVM_METRICS_ADDR` (`:9108`) from Prometheus | Metric endpoint exists; scrape not default |

## Suggested next implementation set

Set 18 closed S4 (EndpointSlice-backed Service VIP admission). Set 17 closed
S3 with optional `fluxvm_prhit` (Set 15 shared-counter fallback retained).
S1 and S2 remain open exactly as described above. Prefer a thin,
evidence-first follow-up rather than another schema rewrite:

1. live CT-bypass + revocation TCP proof script against a real Secure
   Containers Pod (S1);
2. document + CI gate for multi-node NP smoke where lab allows (S2 starter);
3. production Prometheus scrape of Set 17 directional/rule metrics (S3 live
   gate / S8).

Hypervisor work should stay Firecracker/CH-matched (no novel device models):
prefer **H1** or **H3** over inventing P3 features.
