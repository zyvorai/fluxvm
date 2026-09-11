# Next features (ranked)

Living backlog after Secure Containers Set 15 and in-tree KVM FC/CH parity
(P0–P2). Prefer closing proven gates over inventing new wire formats.

## Sentinel / Secure Containers (highest leverage)

| Priority | Feature | Why | Source |
|---|---|---|---|
| **S1** | Live stateful conntrack-bypass proof | Path is implemented; smoke does not yet prove reply traffic skips ingress under a real TCP handshake | set14, PRODUCTION |
| **S2** | Multi-node NetworkPolicy conformance | Single-node reconcile is proven; production needs Cilium + ≥1 other CNI, real Pod-to-Pod allow/deny | set14 #4, set13 |
| **S3** | True per-direction counters + rule-hit identity | **Implemented by Set 17** with optional `fluxvm_prhit`; live production scrape remains a gate | set14 #5, set15, set17 |
| **S4** | EndpointSlice-aware Service VIP policy | Optional ClusterIP mode is selector-conservative; EndpointSlice closes Service-IP parity | set14 #3 |
| **S5** | Indexed LPM/L4 (or verifier-budget raise) | 64-rule linear `fluxvm_prules` scan may become p99-costly | set14 #1 |
| **S6** | IPv6 extension-header walking | Incomplete IPv6 L4 parse under verifier budget | set14 #2 |
| **S7** | Wire Set 8S guest cgroup policy from Pod Set 6S/14 | Containers fail-closed locally but do not inherit Pod policy content | PRODUCTION |
| **S8** | Policy Observer prod sizing + Prometheus scrape | Observer is read-only; needs realistic VM/rule load + scrape wiring | set15 |
| **S9** | Kata P0/P1 gates (OCI fixtures, Multus, hostPath broker, NOTIF_ADDFD, TTY churn, warm-pool claim) | RuntimeClass is not Kata-equivalent yet | secure-containers.md |

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

If continuing the Secure Containers numbering, **Set 16** should be a thin,
evidence-first set rather than another schema rewrite:

1. live CT-bypass TCP proof script (S1);
2. optional dual `fluxvm_ppstat` direction keys or rule-hit map (S3);
3. document + CI gate for multi-node NP smoke where lab allows (S2 starter).

Hypervisor work should stay Firecracker/CH-matched (no novel device models):
prefer **H1** or **H3** over inventing P3 features.
