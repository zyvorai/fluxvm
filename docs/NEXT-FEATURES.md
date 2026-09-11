# Next features (ranked)

Living backlog after Secure Containers Set 19 (GA completion candidate:
schema-v10, `fluxvm_pridx`, IPv6 extension walk, guest policy mirror, Observer
ops) plus Sets 16–18, and Sentinel's operational tooling — Set 12E (GA
certification), Set 13E–17E (migrate/upgrade/fleet/drift/admission) — and
in-tree KVM FC/CH parity (P0–P2). Prefer closing proven gates over inventing
new wire formats.

## Sentinel / Secure Containers (highest leverage)

| Priority | Feature | Why | Source |
|---|---|---|---|
| **S1** | Live stateful conntrack-bypass proof under a real TCP handshake | Bidirectional bypass (set14) and revocation-safe expiry/anti-replay (set16) are both implemented; nothing has yet proven a real handshake crosses a restrictive opposite-direction policy, that a tightened policy revokes an established flow before a new one, or that the SYN/INIT anti-replay check actually fires against live traffic | set14, set16, PRODUCTION |
| **S2** | Multi-node NetworkPolicy conformance | Single-node reconcile is proven; production needs Cilium + ≥1 other CNI, real Pod-to-Pod allow/deny | set14 #4, set13 |
| **S3** | True per-direction counters + rule-hit identity | **Implemented by Set 17** with optional `fluxvm_prhit` (no schema-v8 ABI bump); live production scrape remains a gate | set14 #5, set15, set17 |
| **S4** | EndpointSlice-aware Service VIP policy | **Implemented by Set 18** (EndpointSlice routing proof for opt-in ClusterIP mode); live k8s gate remains optional evidence | set14 #3, set18 |
| **S5** | Indexed LPM/L4 (or verifier-budget raise) | **Implemented by Set 19** via `fluxvm_pridx` candidate bitmap over the existing 64 `fluxvm_prules` slots (`fluxvm_prules` remains authoritative) | set14 #1, set19 |
| **S6** | IPv6 extension-header walking | **Implemented by Set 19** (schema-v10 bounded walk in both TC directions; fragments never conntrack-learned) | set14 #2, set16, set19 |
| **S7** | Wire Set 8S guest cgroup policy from Pod Set 6S/14 | **Implemented by Set 19** (create-time + live CIDR/direction mirror; host TC remains protocol/port SoT) | PRODUCTION, set19 |
| **S8** | Policy Observer prod sizing + Prometheus scrape | **Partially by Set 19** (schema-v10 recognition, ServiceMonitor example, sizing model); real RSS/scrape evidence remains a lab gate | set15, set19 |
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

Set 19 closed code-side S5–S7 and advanced S8; Sets 17–18 remain for S3–S4.
**S1, S2, S9–S11** remain evidence/lab gates — prefer the fail-hard
`scripts/secure-containers-ga-gate-set19.sh` runner over another schema rewrite:

1. live CT-bypass + revocation TCP proof against a real Secure Containers Pod (S1);
2. multi-node NP smoke + second CNI where lab allows (S2);
3. real RSS/scrape of Set 17/19 Observer metrics (S8 live);
4. Kata / multi-host fleet / attached-migration proofs (S9–S11).

Hypervisor work should stay Firecracker/CH-matched (no novel device models):
prefer **H1** or **H3** over inventing P3 features.
