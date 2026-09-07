# Roadmap: Cilium endpoints, CH Windows+QGA, KVM density

Three tracks deferred from the host-local production bar. Phase-1 foundations
ship in-tree; Phase-2/3 are multi-sprint product work.

## 1. Cilium-native VM endpoints / Hubble

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Coexistence `mode=cilium`; Fabric `network.hubble_ui_url` + Edge Dataplane **Open Hubble** link; FluxVM `/flows` observe | Done / in progress |
| **2** | CiliumEndpoint (or equivalent) per VM + SecurityIdentity from Cilium agent — no private map hacks | Not started |
| **3** | Hubble SID attribution for VM traffic; optional flow export bridge | Not started |

Non-goals forever-as-fake: embedding Hubble UI inside Fabric; writing Cilium private maps from FluxVM.

## 2. Cloud Hypervisor Windows + QGA

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | CH Windows **boot**: `hyperv: true` → `kvm_hyperv=on`, UEFI firmware, `examples/windows-ch.json` | Phase-1 |
| **2** | Host↔guest day-2 channel on CH (virtio-serial or rewritten Windows agent) | Blocked on CH device model |
| **3** | `fluxvm qga …` parity on CH | After Phase-2 |

QEMU + `examples/windows-qga.json` remains the GA QGA path.

## 3. In-tree KVM density (`fluxvm_engine=kvm`)

| Phase | Deliverable | Status |
|-------|-------------|--------|
| **1** | Published lab benches (FC vs kvm); docs: FC = prod density, kvm = lab | Phase-1 |
| **2** | Real virtio-blk + linux-loader boot; pause that works | Not started |
| **3** | Snapshots / warm pools / density marketing numbers | Not started |

Default `fluxvm_engine=firecracker` stays the production sandbox engine.
