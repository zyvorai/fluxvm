# Architecture

How the control plane, the four backends and the image path fit together, and how the workspace is laid out.

[Back to README](../README.md)

## Architecture at a glance

```text
                     +-------------------------+
 CLI / REST -------->| Rust VmManager          |
                     | state + TTL + sandboxes |
                     +------------+------------+
                                  |
     +-------------+--------------+--------------+--------------+
     |             |              |              |              |
 +---v---+   +-----v-----+  +-----v------+  +----v-------------+
 | QEMU  |   | Cloud     |  |Firecracker |  | FluxVM hypervisor|
 | qcow2 |   | Hypervisor|  | raw rootfs |  | (agent sandboxes)|
 +---+---+   +-----+-----+  +-----+------+  +----+-------------+
     |             |              |              |
     +------+------+--------------+--------------+
            |
     KVM + TAP/bridge + Linux host

On macOS the same control plane drives a fifth backend, `vz` (`fluxvm-apple`, Apple's Virtualization.framework through the
`fluxvm-vz-runner` helper); see [macos.md](macos.md). It has no KVM, TAP or eBPF and is not part of the Linux diagram above.

Image path:
base image -> SHA256 -> native VMDK-to-raw / qemu-img fallback -> customize -> reusable template
                                      |
VM launch: template -> CoW clone -> cloud-init -> VMM -> optional TTL delete

Secure Containers (GA):
Kubernetes/ctr -> containerd -> containerd-shim-fluxvm-v2
  -> FluxVM REST -> QEMU + virtiofs Pod share (+ Pod-UID write-through volumes)
  -> fluxvm-guest-agent :17777 -> fluxvm-container-agent :17778 / stdio :17779
```

For VMDK input, `fluxvm-image` natively imports uncompressed `monolithicSparse`
disks, descriptor-based flat and split sparse extents, stream-optimized zlib
grains, and monolithic sparse snapshot chains (including a flat or split base).
It verifies the parent CID before flattening a delta. Unsupported VMDK variants
use the configured `qemu-img` binary; malformed supported disks fail conversion.
For raw-only backends, `build-image` with `format: "raw"` creates a reusable
template; converting a VMDK on every VM launch still incurs the full import cost.

For example, save `{"source":"/images/vm/disk.vmdk","output":"/images/templates/vm.raw","format":"raw"}`
as `import.json` and run `fluxctl build-image --spec import.json`. Keep every
split extent beside its descriptor. A full image import should use a stopped
VM or an immutable source snapshot.

Network Fabric dataplane diagrams (packet decision and control-plane sequence):
[docs/network-fabric.md](network-fabric.md#packet-decision-and-control-plane-diagrams).

---

## Project layout

A Cargo workspace of **27 crates** (plus the [`python/`](../python/README.md) and [`go/`](../go/README.md) SDKs), structured for FluxVM's multi-node architecture.

<details>
<summary><b>Show the crate map</b></summary>

```text
crates/
├── fluxvm-core                 domain types, config, VmBackend trait
├── fluxvm-cgroup                cgroup v2 resource control (cpu/memory/io/freezer/pressure/cpuset)
├── fluxvm-storage               VM-record state persistence
├── fluxvm-network               TAP/bridge, netns, egress, nftables + TC/eBPF dataplane
│                                  (bpf/fluxvm_tc.bpf.c, Cilium coexistence)
├── fluxvm-image                 image build/clone + cloud-init seed + OCI→template
├── fluxvm-qemu                  QEMU/KVM backend
├── fluxvm-cloud-hypervisor      Cloud Hypervisor backend
├── fluxvm-firecracker           Firecracker backend
├── fluxvm-hypervisor            in-tree microVMM + `FluxVmBackend` (`fluxvm-hypervisor` binary)
├── fluxvm-apple                 macOS `vz` backend: supervises `fluxvm-vz-runner` (Virtualization.framework)
├── fluxvm-oci-init              PID 1 of container sandboxes on `vz` (boot an OCI rootfs) and the layer unpacker
├── fluxvm-vz-switch             `fluxvm-vz-switch`: serves one private network between `vz` guests (`apple.networks`)
├── fluxvm-guest-protocol        wire types shared by the guest agent and its host client
├── fluxvm-guest-agent           in-guest AF_VSOCK agent binary (ping/exec/shutdown)
├── fluxvm-vsock-client          host-side vsock dialing (native for QEMU, UDS proxy for CH/Firecracker)
├── fluxvm-procbox               rootless Landlock + seccomp process sandbox (CLI + library, profiles, `learn`)
├── fluxvm-scheduler             VmManager: VM lifecycle orchestration + TTL reaper
├── fluxvm-api                   REST API (axum)
├── fluxctl                      `fluxctl` CLI + `fluxctl serve` (composition root)
├── fluxvm-agent                 fleet registry + per-host node-agent daemon (multi-node)
├── fluxvm-kube                  DisposableVm CRD + node-local Kubernetes operator
├── fluxvm-microvm               MicroVM/Job/Pool/GuestImage, shadow-Pod scheduler, node agent
├── fluxvm-container-protocol    Secure Containers lifecycle wire types (VSOCK :17778)
├── fluxvm-container-agent       in-guest OCI process supervisor (`fluxvm-container-agent`)
├── fluxvm-container-client      host-side VSOCK client for the container agent
├── fluxvm-containerd-shim       containerd runtime-v2 shim (`containerd-shim-fluxvm-v2`)
└── fluxvm-intelligence          Sentinel: eBPF host+guest telemetry, drop-reason tracking, flight
                                   recorder, BPF-LSM VMM guard/QoS, XDP shield, topology steering
```

</details>

Deploy fragments for the containerd RuntimeClass path live under `deploy/containerd/`
(see [docs/secure-containers.md](secure-containers.md)). `fluxvm-agent` (the per-*host* node-agent —
distinct from the in-guest `fluxvm-guest-agent`) and `fluxvm-kube` are both verified against real multi-host
and cluster infrastructure. `fluxvm-image` depends on the sibling
[`guestkit`](https://github.com/zyvorai/guestkit) project for offline image customization.
