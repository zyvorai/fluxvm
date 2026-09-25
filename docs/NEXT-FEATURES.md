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
| **S1** | Live stateful conntrack-bypass proof under a real TCP handshake | **Done (depth)** — mid-flow kill + live SYN anti-replay under load: `scripts/e2e-networkpolicy-s1-depth.sh` (plus set16/set17 starters) | set14, set16, PRODUCTION |
| **S2** | Multi-node NetworkPolicy conformance | **Done** — `REQUIRE_MULTI_NODE=1` Set 17 + `scripts/evidence-networkpolicy-second-cni.sh` (second kubeconfig or nftables policy-engine stand-in) | set14 #4, set13 |
| **S3** | True per-direction counters + rule-hit identity | **Implemented by Set 17** with optional `fluxvm_prhit` (no schema-v8 ABI bump); live production scrape remains a gate | set14 #5, set15, set17 |
| **S4** | EndpointSlice-aware Service VIP policy | **Implemented by Set 18** (EndpointSlice routing proof for opt-in ClusterIP mode); live k8s gate remains optional evidence | set14 #3, set18 |
| **S5** | Indexed LPM/L4 (or verifier-budget raise) | **Implemented by Set 19** via `fluxvm_pridx` candidate bitmap over the existing 64 `fluxvm_prules` slots (`fluxvm_prules` remains authoritative) | set14 #1, set19 |
| **S6** | IPv6 extension-header walking | **Implemented by Set 19** (schema-v10 bounded walk in both TC directions; fragments never conntrack-learned) | set14 #2, set16, set19 |
| **S7** | Wire Set 8S guest cgroup policy from Pod Set 6S/14 | **Implemented by Set 19** (create-time + live CIDR/direction mirror; host TC remains protocol/port SoT) | PRODUCTION, set19 |
| **S8** | Policy Observer prod sizing + Prometheus scrape | **Done (code + evidence path)** — ServiceMonitor example, sizing model, `scripts/evidence-policy-observer-scrape.sh` + `deploy/prometheus/fluxvm-scrape.yaml`; archive a live RSS scrape into `docs/benchmarks/evidence/` | set15, set19 |
| **S9** | Kata P0/P1 gates (OCI fixtures, Multus, hostPath broker, NOTIF_ADDFD, TTY churn, warm-pool claim) | **Done (matrix)** — `scripts/evidence-kata-p0p1-matrix.sh` + `tests/oci-fixtures/`; hostPath allowlist broker; `SECCOMP_IOCTL_NOTIF_ADDFD` mode; RuntimeClass is GA vs full Kata product claim | secure-containers.md |
| **S10** | Real multi-node fleet rollout run | **Done (gate)** — `scripts/evidence-fleet-multihost.sh` (real SSH StrictHostKeyChecking, ≥2 hosts, canary/rollback); requires `FLUXVM_FLEET_E2E=1` + `/etc/fluxvm-fleet-lab` | set15e |
| **S11** | Migration orchestrator against a real attached VM | **Done (gate)** — `scripts/evidence-migration-attached-vm.sh` runs export/restore against a live VM via dataplane migration-* / orchestrator | set13e |
| **CNI** | Cilium-like CNI for Secure Containers | **Done (primary path)** — provider auto-detect, Multus-safe `netN` ignore, eth0 L2 handoff, `docs/cilium-cni.md` + `scripts/evidence-cilium-cni.sh`; Multus `netN` secondaries attach as extra guest NICs over bridge chains; Calico churn remains open | secure-containers P0 |
| **DP** | Direct (bridge-less) datapath: Cilium-style redirect between the Pod veth / host uplink and the guest tap | **Done, default `auto` for Secure Containers** — shim `FLUXVM_CONTAINER_CNI_DATAPATH=auto\|direct\|bridge` (default `auto`), daemon loader in the Pod netns (TCX + legacy tc), `l2-uplink` standalone mode (shared per-uplink maps, ARP steering, MicroVM CRD `networkMode: direct`), warm-pool hotplug via QMP fd-passing, Linux 7.x verifier fix, hop view, capability probe, bench + evidence scripts. Live Cilium + KVM evidence passed (`FLUXVM_DIRECT_LIVE=1`, [direct-datapath-live-20260919T202359Z.txt](benchmarks/evidence/direct-datapath-live-20260919T202359Z.txt)); real-guest run ([direct-datapath-live-realguest-20260920.txt](benchmarks/evidence/direct-datapath-live-realguest-20260920.txt)): default/auto fallback/`l2-uplink`/warm-pool hotplug verified, bridge-vs-direct shows no detectable guest-visible difference; Multus secondaries stay on the bridge chain and were not exercised live | [direct-datapath.md](direct-datapath.md) |

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

**S1–S2 / S8–S11 / F1–F2 / H1–H3 / H5** closed on the code + gate path.
Remaining honesty bounds:

1. S2 production still prefers a real second k8s CNI kubeconfig (`FLUXVM_SECOND_CNI_KUBECONFIG`); nftables stand-in plus `scripts/evidence-cni-churn.sh` are the portable default.
2. S9 RuntimeClass is GA (not a full Kata product claim). Warm-pool claim is `FLUXVM_CONTAINER_WARM_POOL=<name>` (template `network.mode=none`, then NIC hotplug).
3. S10 needs `FLUXVM_FLEET_E2E=1` + ≥2 SSH hosts; S11 needs a runnable FluxVM guest on the lab host.
4. H2 virtio-win guest boot is unproven; Cloud Hypervisor stays the production Windows VMM. H4 remains deferred.

Portable CI maps each code-side use case to a test target in
[secure-containers-use-case-matrix.md](secure-containers-use-case-matrix.md)
(enforced by `scripts/check-use-case-matrix.sh` and
`.github/workflows/secure-containers-coverage.yml`). Live rows stay opt-in via
`FLUXVM_SECURE_CONTAINERS_LIVE_CI=1`.

Hypervisor work should stay Firecracker/CH-matched (no novel device models);
**H4** stays deferred.
