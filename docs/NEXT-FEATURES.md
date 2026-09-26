# Next features (ranked)

Living backlog after Secure Containers Set 19 and the P0 multi-VMM GA close
(Cloud Hypervisor virtiofs, Multus hybrid/direct, Calico/Flannel, hostPath
broker, Firecracker ext4 block shares — schema-v10, `fluxvm_pridx`, IPv6
extension walk, guest policy mirror, Observer ops) plus Sets 16–18, and
Sentinel's operational tooling — Set 12E (GA certification), Set 13E–17E
(migrate/upgrade/fleet/drift/admission) — and in-tree KVM FC/CH parity
(P0–P2). Prefer closing proven live gates over inventing new wire formats.

## Sentinel / Secure Containers (highest leverage)

| Priority | Feature | Why | Source |
|---|---|---|---|
| **S1** | Live stateful conntrack-bypass proof under a real TCP handshake | **Done (depth)** — mid-flow kill + live SYN anti-replay under load: `scripts/e2e-networkpolicy-s1-depth.sh` (plus set16/set17 starters) | set14, set16, PRODUCTION |
| **S2** | Multi-node NetworkPolicy conformance | **Done** — `REQUIRE_MULTI_NODE=1` Set 17 + `scripts/evidence-networkpolicy-second-cni.sh` (second kubeconfig or nftables policy-engine stand-in) | set14 #4, set13 |
| **S3** | True per-direction counters + rule-hit identity | **Implemented by Set 17** with optional `fluxvm_prhit` (no schema-v8 ABI bump); live production scrape remains a gate | set14 #5, set15, set17 |
| **S4** | EndpointSlice-aware Service VIP policy | **Implemented by Set 18** (EndpointSlice routing proof for opt-in ClusterIP mode); live k8s gate remains optional evidence | set14 #3, set18 |
| **S5** | Indexed LPM/L4 (or verifier-budget raise) | **Implemented by Set 19** via `fluxvm_pridx` candidate bitmap over the existing 64 `fluxvm_prules` slots (`fluxvm_prules` remains authoritative) | set14 #1, set19 |
| **S6** | IPv6 extension-header walking | **Implemented by Set 19** (schema-v10 bounded walk in both TC directions; fragments never conntrack-learned) | set14 #2, set16, set19 |
| **S7** | Wire Set 8S guest cgroup policy from Pod Set 6S/14 | **Implemented by Set 19** (create-time + live CIDR/direction mirror; host TC remains protocol/port SoT) | PRODUCTION, set19 |
| **S8** | Policy Observer prod sizing + Prometheus scrape | **Done (code + evidence path)** — ServiceMonitor example, sizing model, `scripts/evidence-policy-observer-scrape.sh` + `deploy/prometheus/fluxvm-scrape.yaml`; archive a live RSS scrape into `docs/benchmarks/evidence/` | set15, set19 |
| **S9** | Kata P0/P1 gates (OCI fixtures, Multus, hostPath broker, NOTIF_ADDFD, TTY churn, warm-pool claim, FC block shares) | **Done (matrix)** — `scripts/evidence-kata-p0p1-matrix.sh` + `tests/oci-fixtures/`; hostPath allowlist broker; `SECCOMP_IOCTL_NOTIF_ADDFD`; Firecracker ext4 share packing (`FLUXVM_CONTAINER_BACKEND=firecracker`); RuntimeClass is GA vs full Kata product claim | secure-containers.md |
| **S10** | Real multi-node fleet rollout run | **Done (live)** — `scripts/evidence-fleet-multihost.sh` canary→approve→resume on ≥2 SSH hosts (`StrictHostKeyChecking=yes`); evidence [sc-live-s10-fleet-20260926.txt](benchmarks/evidence/sc-live-s10-fleet-20260926.txt) (`S10 REAL MULTI-HOST FLEET: PASS`) | set15e |
| **S11** | Migration orchestrator against a real attached VM | **Done (gate)** — `scripts/evidence-migration-attached-vm.sh` runs export/restore against a live VM via dataplane migration-* / orchestrator | set13e |
| **CNI** | Cilium-like CNI for Secure Containers | **Done (primary + Calico/Flannel/Multus)** — provider auto-detect, Multus `netN` hybrid/direct secondaries (`FLUXVM_CONTAINER_CNI_MULTUS_DATAPATH`), Calico/Flannel providers; live multi-CNI under load remains a gate | secure-containers P0 |
| **DP** | Direct (bridge-less) datapath: Cilium-style redirect between the Pod veth / host uplink and the guest tap | **Done, default `auto` for Secure Containers** — shim `FLUXVM_CONTAINER_CNI_DATAPATH=auto\|direct\|bridge` (default `auto`), daemon loader in the Pod netns (TCX + legacy tc), `l2-uplink` standalone mode (shared per-uplink maps, ARP steering, MicroVM CRD `networkMode: direct`), warm-pool hotplug via QMP fd-passing, Linux 7.x verifier fix, hop view, capability probe, bench + evidence scripts. Live Cilium + KVM evidence passed (`FLUXVM_DIRECT_LIVE=1`, [direct-datapath-live-20260919T202359Z.txt](benchmarks/evidence/direct-datapath-live-20260919T202359Z.txt)); real-guest run ([direct-datapath-live-realguest-20260920.txt](benchmarks/evidence/direct-datapath-live-realguest-20260920.txt)): default/auto fallback/`l2-uplink`/warm-pool hotplug verified, bridge-vs-direct shows no detectable guest-visible difference; Multus secondaries support hybrid/direct opt-in | [direct-datapath.md](direct-datapath.md) |

## In-tree hypervisor / agent sandboxes

| Priority | Feature | Why | Source |
|---|---|---|---|
| **H1** | Virtio **device live-state** in `FLUXKVM1` | **Done (v3)** — pack/restore queue rings + status/features; backends still re-attach paths from boot config; Firecracker remains production snap for FC guests | hypervisor README, agent-sandbox-gaps |
| **H2** | Full virtio-pci BAR / Windows path | **Done (tables)** — ECAM virtio-net @ `00:01.0`, BAR0, MSI-X table at BAR0+`0x800`, DSDT `PCI0`, firmware entry at `0x01000000`, ACPI reset I/O `0xCF9`. virtio-win boot is unproven; Cloud Hypervisor stays the production Windows VMM | DESIGN / README |
| **H3** | vhost-net multi-queue bind | **Done** — mem-table + VRING NUM/ADDR/BASE/KICK/CALL + TAP backend; kernel datapath kicks when rings programmed (userspace pump remains fallback) | hypervisor boot smoke / DESIGN |
| **H4** | P3 on demand: virtio-fs, live migration, hotplug | **Deferred** — stubs return `Unsupported` until product asks (no invented surfaces) | DESIGN |
| **H5** | Published kvm/FC density figures | **Done (archive)** — lab run on `80.79.5.173` archived in [benchmarks/evidence/density-20260918-80.79.5.173.txt](benchmarks/evidence/density-20260918-80.79.5.173.txt); cold flux-vm create is not a Track B density claim | ROADMAP-DENSITY, benchmarks |

## Firecracker adoption (general CP — Track A follow-ups)

FluxVM is a general VM control plane; FC figures are isolation layers + optional
density. Track A isolation, virtio rate limiters, and **FC1–FC3** are shipped:

| Priority | Feature | Status |
|---|---|---|
| **FC1** | Oversubscription policy knobs | **Done** — `default_cpu_quota_percent` / `memory_max_equals_guest` + [oversubscription.md](oversubscription.md) |
| **FC2** | Static CPU templates | **Done** — `cpu_template` on Firecracker + FluxVm(`firecracker`); rejected on CH/QEMU/kvm |
| **FC3** | `/v1/vms/{id}/snapshot` multi-backend | **Done** — QEMU/CH (existing) + plain Firecracker + FluxVm control path |

Custom CPUID templates and Track B density publication remain out of scope here.

## Fabric / density (adjacent)

| Priority | Feature | Status |
|---|---|---|
| **F1** | Hubble SID attribution for VM traffic | **Done** — `from_flow_record_attributed` overlays CEP / Cilium-agent SID on hubble observe flows (src + peer VM dst); never writes Cilium private maps |
| **F2** | Scrape `MICROVM_METRICS_ADDR` (`:9108`) from Prometheus | **Done** — node-agent annotations + port, `deploy/k8s/microvm/servicemonitor.yaml`, `deploy/prometheus/fluxvm-scrape.yaml` |

## Suggested next implementation set

**S1–S11 / CNI / DP / F1–F2 / H1–H3 / H5 / FC1–FC3** closed on the code +
gate path. Secure Containers P0/P1 multi-VMM (incl. Firecracker block shares)
is shipped; RuntimeClass is GA.

Remaining honesty bounds (live lab only):

1. S2 second-cluster kubeconfig path live on 2026-09-26 — [benchmarks/evidence/sc-live-s2-real-kubeconfig-20260926.txt](benchmarks/evidence/sc-live-s2-real-kubeconfig-20260926.txt) (`S2 SECOND CNI (kubeconfig): PASS` against `80.79.5.173`, RuntimeClass `runc`). Portable nftables stand-in remains — [sc-live-s2-second-cni-20260926.txt](benchmarks/evidence/sc-live-s2-second-cni-20260926.txt). Lab drop-in `/etc/fluxvm-second-cni.env` auto-sourced by the evidence script.
2. Live SC matrix + day-0 wow: [sc-live-wow-demo-20260926.txt](benchmarks/evidence/sc-live-wow-demo-20260926.txt) (`WOW DEMO: OK`, k8s + k8s-multi); full phase finish [sc-live-phases-post93-summary-20260926.txt](benchmarks/evidence/sc-live-phases-post93-summary-20260926.txt) (`pass=10 skip=1 fail=0`, post-#93; s2 soft-skip cleared with second-cluster kubeconfig — see item 1). Adoption packaging: [secure-containers-supported-profile.md](secure-containers-supported-profile.md), [secure-containers-15min-lab.md](secure-containers-15min-lab.md), [sentinel-wedge.md](sentinel-wedge.md).
3. S10 live multi-host fleet cleared 2026-09-26 — [sc-live-s10-fleet-20260926.txt](benchmarks/evidence/sc-live-s10-fleet-20260926.txt) (lab `175.110.122.71` ↔ `80.79.5.173`, canary approve/resume, both nodes healthy). S11 still needs a runnable FluxVM guest on the lab host.
4. H2 virtio-win guest boot is unproven; Cloud Hypervisor stays the production Windows VMM. H4 remains deferred.
5. Remote seccomp policy RPC remains explicitly out of scope (Set 11).

Portable CI maps each code-side use case to a test target in
[secure-containers-use-case-matrix.md](secure-containers-use-case-matrix.md)
(enforced by `scripts/check-use-case-matrix.sh` and
`.github/workflows/secure-containers-coverage.yml`). Live rows stay opt-in via
`FLUXVM_SECURE_CONTAINERS_LIVE_CI=1`.

Hypervisor work should stay Firecracker/CH-matched (no novel device models);
**H4** stays deferred.
