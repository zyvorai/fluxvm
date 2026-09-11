# Roadmap: Cilium endpoints, CH Windows+QGA, KVM density

Three tracks deferred from the host-local production bar. Phase-1 foundations
ship in-tree; Phase 2b now enriches CEP views from the Cilium agent HTTP API
(no private-map writes). In-tree KVM memory snapshots use the lab-only
`FLUXKVM1` **v2** format (all vCPUs; not Firecracker-compatible).

## 1. Cilium-native VM endpoints / Hubble

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Coexistence `mode=cilium`; Fabric `network.hubble_ui_url` + Edge Dataplane **Open Hubble** link; FluxVM `/flows` observe | **Done** |
| **2a** | CiliumEndpoint-*shaped* objects per VM + Hubble-lite JSON/UI (`/v1/network/endpoints`, `/hubble/*`) | **Done** (no Cilium private maps) — [hubble-lite.md](hubble-lite.md) |
| **2b** | CiliumEndpoint + SecurityIdentity from Cilium agent — no private map hacks | **Done** (agent HTTP GET enrich; soft-fail → fluxvm-hash) |
| **3** | Hubble SID attribution for VM traffic; optional flow export bridge | **Not started** (Hubble-lite flows use Fabric CT samples; SID via 2b when agent matches) |

Non-goals forever-as-fake: embedding Hubble UI inside Fabric; writing Cilium private maps from FluxVM.

## 2. Cloud Hypervisor Windows + QGA

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | CH Windows **boot**: `hyperv: true` → `kvm_hyperv=on`, UEFI firmware, `examples/windows-ch.json` | **Done** |
| **2** | Host↔guest day-2 channel on CH (`--serial socket=qga.sock`) | **Done** (host path) — [ch-windows-qga.md](ch-windows-qga.md) |
| **3** | `fluxvm qga …` on CH when the guest speaks QGA on that serial | **Done** at host path; guest must run qemu-ga on COM/serial. Named virtio-serial `org.qemu.guest_agent.0` remains QEMU-only |

QEMU + `examples/windows-qga.json` remains the GA QGA path.

## 3. In-tree KVM density (`fluxvm_engine=kvm`)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Bench harness + docs: FC = prod density, kvm = lab | **Done** (`scripts/bench-sandbox.sh`, [benchmarks](benchmarks/README.md)) |
| **2** | Real virtio-blk MMIO + rootfs attach (`cfg.disk`); cmdline virtio_mmio.device slots | **Done** |
| **3a** | linux-loader + platform + virtio-blk + console stdin; lab userspace / stdin smoke | **Done** (`FLUXVM_USERSPACE_OK` / `FLUXVM_STDIN_OK`) |
| **3b** | Real in-tree KVM **pause/resume** (park vCPU; no `KVM_RUN` while paused) | **Done** (`scripts/test-kvm-pause-smoke.sh`) |
| **3c** | Memory snapshot / restore + warm-pool density claims on kvm | **Done** (lab `FLUXKVM1` **v2**: all vCPUs + watermark; not FC-compatible) — `scripts/test-kvm-snapshot-smoke.sh` |
| **3d** | `FLUXVM_KVM_LOCK_MEM=1` (MAP_POPULATE + mlock) | **Done** — [kvm-density.md](kvm-density.md) |
| **3e** | FC/CH parity: TSS/MSRs/FPU/LAPIC/serial irqfd; vsock/balloon/rng; ACPI; jailer; auto mmio cmdline | **Done** — guests reach `/sbin/init` |

Default `fluxvm_engine=firecracker` stays the production sandbox engine. In-tree
KVM pause + `FLUXKVM1` v2 memory snapshot restore support lab warm-pool packing;
Firecracker remains the production snapshot format.

Ranked follow-ups (virtio live-state, vhost bind, Sentinel Set 16 candidates,
Hubble SID): [NEXT-FEATURES.md](NEXT-FEATURES.md).
