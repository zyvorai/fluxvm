# Roadmap: Cilium endpoints, CH Windows+QGA, KVM density

Three tracks deferred from the host-local production bar. Phase-1 foundations
ship in-tree; Phase-2/3 product depth that would fake CEP / CH QGA / KVM
memory snapshots stays **Not started** or **Blocked** on purpose.

## 1. Cilium-native VM endpoints / Hubble

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Coexistence `mode=cilium`; Fabric `network.hubble_ui_url` + Edge Dataplane **Open Hubble** link; FluxVM `/flows` observe | **Done** |
| **2** | CiliumEndpoint (or equivalent) per VM + SecurityIdentity from Cilium agent — no private map hacks | **Not started** (multi-sprint CNI/agent work) |
| **3** | Hubble SID attribution for VM traffic; optional flow export bridge | **Not started** (needs Phase-2) |

Non-goals forever-as-fake: embedding Hubble UI inside Fabric; writing Cilium private maps from FluxVM.

## 2. Cloud Hypervisor Windows + QGA

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | CH Windows **boot**: `hyperv: true` → `kvm_hyperv=on`, UEFI firmware, `examples/windows-ch.json` | **Done** |
| **2** | Host↔guest day-2 channel on CH (virtio-serial or rewritten Windows agent) | **Blocked** on CH device model in FluxVM |
| **3** | `fluxvm qga …` parity on CH | **Blocked** (after Phase-2) |

QEMU + `examples/windows-qga.json` remains the GA QGA path.

## 3. In-tree KVM density (`fluxvm_engine=kvm`)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Bench harness + docs: FC = prod density, kvm = lab | **Done** (`scripts/bench-sandbox.sh`, [benchmarks](benchmarks/README.md)) |
| **2** | Real virtio-blk MMIO + rootfs attach (`cfg.disk`); cmdline virtio_mmio.device slots | **Done** |
| **3a** | linux-loader + platform + virtio-blk + console stdin; lab userspace / stdin smoke | **Done** (`FLUXVM_USERSPACE_OK` / `FLUXVM_STDIN_OK`) |
| **3b** | Real in-tree KVM **pause/resume** (park vCPU; no `KVM_RUN` while paused) | **Done** (`scripts/test-kvm-pause-smoke.sh`) |
| **3c** | Memory snapshot / restore + warm-pool density claims on kvm | **FC-only** — kvm still `bail!("memory snapshots require fluxvm_engine=firecracker")` |

Default `fluxvm_engine=firecracker` stays the production sandbox engine. In-tree
KVM pause lets AutoPause / pools park CPU honestly on the lab engine; full
memory snapshot restore remains Firecracker.
