# Roadmap: Cilium endpoints, CH Windows+QGA, KVM density

Three tracks deferred from the host-local production bar. Phase-1 foundations
ship in-tree; real Cilium-agent CEP identity and KVM memory snapshots stay
**Not started** / **FC-only** on purpose (no private-map fakes).

## 1. Cilium-native VM endpoints / Hubble

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Coexistence `mode=cilium`; Fabric `network.hubble_ui_url` + Edge Dataplane **Open Hubble** link; FluxVM `/flows` observe | **Done** |
| **2a** | CiliumEndpoint-*shaped* objects per VM + Hubble-lite JSON/UI (`/v1/network/endpoints`, `/hubble/*`) | **Done** (no Cilium private maps) — [hubble-lite.md](hubble-lite.md) |
| **2b** | CiliumEndpoint + SecurityIdentity from Cilium agent — no private map hacks | **Not started** (multi-sprint CNI/agent work) |
| **3** | Hubble SID attribution for VM traffic; optional flow export bridge | **Not started** (needs Phase-2b); Hubble-lite flows use Fabric CT samples only |

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
| **3c** | Memory snapshot / restore + warm-pool density claims on kvm | **FC-only** — kvm still `bail!("memory snapshots require fluxvm_engine=firecracker")` |
| **3d** | `FLUXVM_KVM_LOCK_MEM=1` (MAP_POPULATE + mlock) | **Done** — [kvm-density.md](kvm-density.md) |

Default `fluxvm_engine=firecracker` stays the production sandbox engine. In-tree
KVM pause lets AutoPause / pools park CPU honestly on the lab engine; full
memory snapshot restore remains Firecracker.
