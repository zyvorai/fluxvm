<div align="center">

```text
███████╗██╗     ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ███╗
██╔════╝██║     ██║   ██║╚██╗██╔╝██║   ██║████╗ ████║
█████╗  ██║     ██║   ██║ ╚███╔╝ ██║   ██║██╔████╔██║
██╔══╝  ██║     ██║   ██║ ██╔██╗ ╚██╗ ██╔╝██║╚██╔╝██║
██║     ███████╗╚██████╔╝██╔╝ ██╗ ╚████╔╝ ██║ ╚═╝ ██║
╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝
```

### Disposable Compute Engine — secure, isolated, short-lived VMs via Firecracker, Cloud Hypervisor, QEMU/KVM, and the FluxVM hypervisor

<img src="docs/assets/social-preview.png" alt="FluxVM — Disposable Compute Engine" width="720">

[![CI](https://github.com/zyvorai/fluxvm/actions/workflows/ci.yml/badge.svg)](https://github.com/zyvorai/fluxvm/actions/workflows/ci.yml)
[![DevOps gates](https://github.com/zyvorai/fluxvm/actions/workflows/devops-gates.yml/badge.svg)](https://github.com/zyvorai/fluxvm/actions/workflows/devops-gates.yml)
[![License: Apache-2.0](https://img.shields.io/github/license/zyvorai/fluxvm)](LICENSE)
[![Release](https://img.shields.io/github/v/release/zyvorai/fluxvm?sort=semver)](https://github.com/zyvorai/fluxvm/releases)
[![Rust: stable](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

[Quick start](#quick-start) · [Is this for you?](#is-this-for-you) · [Use cases](#use-cases) · [Feature highlights](#feature-highlights) · [FAQ](#faq) · [Docs](#documentation-map) · [zyvor.dev/docs](https://zyvor.dev/docs?utm_source=github&utm_medium=fluxvm)

</div>

---

## What is FluxVM

**Disposable Compute Engine** — create secure, isolated, short-lived virtual machines using
Firecracker, Cloud Hypervisor, QEMU/KVM, and the in-tree FluxVM hypervisor, from one Rust-native
control plane. Repository: [github.com/zyvorai/fluxvm](https://github.com/zyvorai/fluxvm).

- **QEMU/KVM** — broad guest/device compatibility, qcow2 CoW overlays, QMP socket.
- **Cloud Hypervisor** — Rust VMM for modern cloud workloads, direct-kernel or firmware boot.
- **Firecracker** — microVM backend using a Linux kernel + raw root filesystem.
- **FluxVM hypervisor** (`backend: "flux-vm"`, binary `fluxvm-hypervisor`) — the agent-sandbox track:
  memory snapshots, `/v1/sandboxes`, guest HTTP proxy + AutoResume, L7 egress, AutoPause, `/console`,
  and an optional native TC/eBPF dataplane (nftables default; see [Network Fabric](docs/network-fabric.md)).

FluxVM runs standalone — as a host-local replacement for libvirt/virsh (see [below](#vs-libvirtvirsh))
— or as the VM engine underneath other Zyvor products. Either way it's the same binary and the same
REST API; nothing changes depending on who's calling it.

---

## Maturity: what's real today

**This repository is a complete MVP/control-plane skeleton, not a finished multi-tenant security
boundary.** Auth/RBAC, the Firecracker jailer (chroot + uid/gid isolation), cgroup v2 resource
control, and per-VM network namespaces are already implemented — before exposing it to untrusted
tenants, still add seccomp/AppArmor/SELinux policy, quotas, audit logging, and stronger image
provenance. Full checklist: [docs/PRODUCTION.md](docs/PRODUCTION.md).

Two subsystems are GA today; one is explicitly not:

| Subsystem | Status |
|---|---|
| Core VM lifecycle (QEMU/CH/Firecracker/FluxVM hypervisor backends, cgroups, jailer, netns) | Implemented, see caveat above before untrusted multi-tenant use |
| Network Fabric (TC/eBPF VM-edge dataplane, schema v4) | **GA** — [docs/network-fabric.md](docs/network-fabric.md) |
| Secure Containers (containerd runtime-v2 shim) | **Developer preview** — not a Kata Containers-equivalence claim yet, see [docs/secure-containers.md](docs/secure-containers.md) |

---

## vs. libvirt/virsh

FluxVM is the Zyvor **host-local** replacement for libvirt/virsh VM lifecycle and networking — it is
**not** a drop-in for KubeVirt/OpenShift (`virtctl` stays that ecosystem's tool; see [MicroVM vs.
KubeVirt](docs/microvm.md#vs-disposablevm-and-kubevirt) for where FluxVM's Kubernetes paths sit
relative to KubeVirt):

| libvirt/virsh | FluxVM | Same job? |
|---|---|---|
| `virsh define` + `virsh start` | `fluxvm create` | Yes |
| `virsh list` / `virsh dominfo` | `fluxvm list` / `fluxvm get` | Yes |
| `virsh suspend` / `virsh resume` | `fluxvm pause` / `fluxvm resume` | Yes |
| `virsh destroy` | `fluxvm delete` | Yes |
| XML domain definitions | JSON VM spec (`fluxvm create --spec vm.json`) | Different format, same purpose |
| No REST API | Full REST API (`fluxvm serve`) | FluxVM adds this |

No libvirtd, no XML domain definitions — FluxVM talks its own REST API and manages TAP/bridge/netns
networking directly via netlink.

---

## Use cases

Nine use cases map directly onto what's implemented today — nothing below is aspirational. Full detail
for each: [docs/use-cases.md](docs/use-cases.md).

| Use case | What it uses |
|---|---|
| **CI/CD build & test runners** | VM-per-job over vsock `exec` (no SSH, no network path needed), `ttl_seconds` guarantees cleanup even on a crashed job |
| **Golden-image pipeline** | Build once (`fluxvm build-image`), reuse via qcow2 CoW overlays; SHA-256 + optional Ed25519-signed image catalog |
| **Kubernetes-native disposable workloads** | `DisposableVm` CRD + node-local `fluxvm-kube` operator — verified end to end against a real k3s cluster |
| **Secure Containers (OCI in a FluxVM)** | Per-Pod guest kernel via `containerd-shim-fluxvm-v2` — **developer preview**, not production-ready yet |
| **Multi-host fleets without Kubernetes** | `fluxvm-agent` central fleet registry + load-aware placement — verified across two real, physically separate hosts |
| **Sandboxed / untrusted code execution** | Firecracker jailer + cgroup v2 + netns + vsock `exec` + TTL reaper, the same isolation shape as gVisor/Firecracker-based CI sandboxes |
| **Disposable dev/test environments** | Per-branch/PR VMs, cheap qcow2 CoW cloning, `pause`/`resume` to park instead of rebuild |
| **Bring-your-own storage backend** | LVM thin, NBD, Ceph RBD (RBD verified against a real Rook Ceph cluster) |
| **Networking that matches the environment** | QEMU user-mode NAT, TAP+bridge, or macvtap — all three SSH-verified end to end in this project's own regression tests |

---

## Is this for you?

FluxVM is a strong fit when:

- **You want VM lifecycle without a systemd/libvirtd dependency** — direct netlink networking, no XML domain definitions, a real REST API.
- **You need disposable, short-lived VMs at the core of the workflow** — CI runners, sandboxed execution, per-branch dev environments — where `ttl_seconds` and cheap CoW cloning matter more than long-lived VM management.
- **You're evaluating a Kubernetes-native VM path that isn't KubeVirt** — the `DisposableVm` CRD and `fluxvm-microvm` scheduler-native path are real alternatives, not a KubeVirt clone.
- **You want to adopt this standalone** — FluxVM doesn't require Fabric, Ragnarok, or any other Zyvor product. It's a complete, independently useful control plane on its own.

Look elsewhere (for now) when:

- **You need a finished multi-tenant security boundary today** — see the [maturity caveat](#maturity-whats-real-today) above; the primitives (jailer, cgroups, netns) are there, but seccomp/AppArmor/SELinux policy, quotas, audit logging, and stronger image provenance still need to be added before exposing this to untrusted tenants.
- **You need OCI/containerd workloads with Kata-equivalent isolation today** — Secure Containers is explicitly developer preview; PRODUCTION.md lists concrete gaps (hostPath hotplug, broader CNI/OCI conformance) still open.
- **You need KubeVirt/OpenShift compatibility** — FluxVM's Kubernetes paths (`DisposableVm`, MicroVM) are deliberately not KubeVirt-compatible; `virtctl` and the KubeVirt API surface aren't goals here.
- **You need published performance numbers for capacity planning** — boot latency, VM density, and throughput haven't been benchmarked and published yet (tracked as future work in [docs/NEXT-FEATURES.md](docs/NEXT-FEATURES.md)); don't expect a sizing guide today.

---

## Quick start

```bash
git clone https://github.com/zyvorai/fluxvm.git
cd fluxvm
```

`fluxvm-image` depends on a sibling [`guestkit`](https://github.com/zyvorai/guestkit) checkout
(clone it next to `fluxvm`, i.e. path `../../../guestkit` from `crates/fluxvm-image`).

```bash
# 1. Prepare the host once — packages, Cloud Hypervisor, Firecracker, a bridge.
sudo ./scripts/bootstrap-host.sh vmbr0
./scripts/preflight.sh                    # confirm every tool is on PATH

# 2. Build (current stable Rust toolchain) and install the CLI.
cargo build --release
sudo install -m 0755 target/release/fluxvm /usr/local/bin/fluxvm
sudo install -m 0755 target/release/fluxvm-hypervisor /usr/local/bin/fluxvm-hypervisor
sudo install -m 0644 config.example.toml /etc/fluxvm.toml

# 3. Run a VM — edit examples/qemu.json to point at your base image + SSH pubkey.
sudo fluxvm --config /etc/fluxvm.toml create --spec examples/qemu.json

# Day-2
fluxvm list
fluxvm get <id>                 # includes guest_ip for netns mode
fluxvm exec <id> -- hostname
fluxvm pause <id> && fluxvm resume <id>
fluxvm delete <id>              # or wait for ttl_seconds
```

`cargo build --release` also produces `fluxvm-kube`, `fluxvm-agent`, `containerd-shim-fluxvm-v2`,
and `fluxvm-container-agent` — see [Feature highlights](#feature-highlights) below for what each is.

**Pick a network mode:**

| Mode | Spec sketch | Guest IP |
|------|-------------|----------|
| Lab / SSH | `"network": {"mode":"user","forwards":[{"host_port":2222,"guest_port":22}]}` | QEMU SLIRP DHCP; SSH via `localhost:2222` |
| LAN DHCP | `"network": {"mode":"tap","bridge":"vmbr0","mac":"06:…"}` | Your bridge's DHCP |
| Known IP | `"network": {"mode":"tap","netns":true,"mac":"06:…"}` | FluxVM dnsmasq; see `fluxvm get` |
| L2 macvtap | `"network": {"mode":"macvtap","parent":"eth0","mac":"06:…"}` | Your L2 / static via cloud-init |

Full examples: [`examples/qemu.json`](examples/qemu.json) (user-mode lab),
[`examples/create-vm-prod.json`](examples/create-vm-prod.json) (tenant + tap/netns),
[`examples/guestkit-handoff.json`](examples/guestkit-handoff.json) (post-GuestKit netns + known IP),
[`examples/macvtap.json`](examples/macvtap.json). Full JSON contract:
[docs/api.md](docs/api.md#vm-json-contract). Verify your build end to end with
`sudo ./scripts/test-networking.sh` and `sudo ./scripts/test-lifecycle.sh` — see
[docs/operations.md](docs/operations.md#testing-networking-and-lifecycle-end-to-end). Deploying to a
remote host: [docs/operations.md](docs/operations.md#deploy-to-a-remote-host).

---

## Feature highlights

| Area | What's there | Docs |
|------|---------------|------|
| **Backends** | QEMU/KVM, Cloud Hypervisor, Firecracker, and the in-tree FluxVM hypervisor (agent sandboxes: snapshots, AutoPause, HTTP proxy) behind one `VmBackend` trait; `"backend":"auto"` resolution; vsock guest agent (`exec`, PTY console, file transfer) with no SSH required | [docs/agent-sandbox-gaps.md](docs/agent-sandbox-gaps.md) · [docs/operations.md](docs/operations.md#auto-backend-selection) |
| **Networking & Network Fabric** | TAP/bridge, macvtap, QEMU user-mode NAT, per-VM network namespaces; **Network Fabric** is GA (schema v4) — TC/eBPF or Cilium-coexistence dataplane with IPv4/IPv6 L3+L4 policy, rate limits, security groups, CNP, live reconfigure, and REST observability, falling back to nftables by default | [docs/network-fabric.md](docs/network-fabric.md) · [docs/ebpf-cilium.md](docs/ebpf-cilium.md) · [docs/network-policy.md](docs/network-policy.md) |
| **Service Fabric** | Node-local Maglev VIP load balancing — dual-stack NAT/DSR/SNAT, health-aware routing, incremental reconcile, per-service EDT, flow export | [docs/service-fabric.md](docs/service-fabric.md) |
| **Images** | virt-builder-style `build-image` (guestkit-based, never libguestfs), per-distro package install, an Ed25519-signed image catalog with REST CRUD, and Windows/Kryton golden-image customization + live QGA | [docs/build-image-tutorials.md](docs/build-image-tutorials.md) · [docs/operations.md](docs/operations.md#image-catalog--signing) · [docs/windows-golden.md](docs/windows-golden.md) |
| **Operations** | cgroup v2 resource control (limits, freeze/thaw, PSI), warm VM pools, the Firecracker jailer, alternative storage (LVM thin, NBD, Ceph RBD), admission policy limits, bearer-token auth/RBAC | [docs/operations.md](docs/operations.md) · [docs/api.md](docs/api.md#auth--rbac) |
| **Kubernetes & fleet** | `DisposableVm` CRD + node-local operator; `fluxvm-microvm` scheduler-native MicroVM path (no KubeVirt); `fluxvm-agent` distributed node-agent with a central fleet registry and load-aware placement across hosts | [Kubernetes CRD/operator](#kubernetes-crdoperator) below · [docs/microvm.md](docs/microvm.md) · [docs/operations.md](docs/operations.md#distributed-node-agent) |
| **Secure Containers** | Developer-preview containerd runtime-v2 shim (`containerd-shim-fluxvm-v2`) mapping a Pod/task group onto one QEMU FluxVM, with CNI L2, cgroup-v2 stats, VSOCK stdio/TTY, namespaces, device passthrough, and guest AppArmor/SELinux/seccomp enforcement | [docs/secure-containers.md](docs/secure-containers.md) |
| **Sentinel observability** | eBPF-based host + guest runtime intelligence — per-VM syscall/page-fault telemetry, drop-reason tracking, flight recorder, BPF-LSM VMM guard/QoS, XDP shield, topology steering | [docs/runtime-intelligence.md](docs/runtime-intelligence.md) · [docs/flight-recorder.md](docs/flight-recorder.md) |

---

## FAQ

**Is FluxVM production-ready?** For the core VM-lifecycle primitives (auth/RBAC, jailer, cgroups, netns), yes with the caveat in [Maturity](#maturity-whats-real-today) above — add seccomp/AppArmor/SELinux policy, quotas, audit logging, and stronger image provenance before exposing it to untrusted tenants. Secure Containers is separately still developer preview.

**How is this different from libvirt?** No libvirtd, no XML domain definitions — FluxVM has its own REST API and talks netlink directly for networking. See [vs. libvirt/virsh](#vs-libvirtvirsh) above for the command mapping.

**How is this different from KubeVirt?** Different model entirely — FluxVM's `DisposableVm` and MicroVM paths run the VMM on the host under `fluxvm serve`, not inside a virt-launcher Pod, and don't implement `virtctl`, live migration, or CDI. See [docs/microvm.md](docs/microvm.md#vs-disposablevm-and-kubevirt) for the full comparison.

**Do I need Fabric or Ragnarok to use FluxVM?** No. FluxVM is a complete, independently useful control plane — clone it, build it, run `fluxvm create`, and you have a working disposable-VM engine with no other Zyvor product involved. Fabric and Ragnarok are separate products that happen to use FluxVM as their VM engine; see [Ecosystem](#ecosystem) below.

**Is Secure Containers ready for production OCI workloads?** No — it's explicitly a developer preview. `hostPath` hotplug and broader CNI/OCI conformance are still open; see [docs/secure-containers.md](docs/secure-containers.md) and [docs/PRODUCTION.md](docs/PRODUCTION.md) for the itemized gap list.

**What storage backends are supported?** qcow2/raw by default, plus LVM thin snapshots, NBD-exported disks, and Ceph RBD (verified against a real Rook Ceph cluster) — see [Bring-your-own storage backend](docs/use-cases.md#bring-your-own-storage-backend).

**Are there published performance numbers (boot latency, VM density)?** Not yet — this is tracked as open future work in [docs/NEXT-FEATURES.md](docs/NEXT-FEATURES.md), not something we've benchmarked and published. Don't rely on unpublished figures for capacity planning.

**What license is this under?** Apache License 2.0, the entire repository, no dual licensing — see [License](#license) below.

---

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

Image path:
base image -> SHA256 -> qemu-img -> customize -> reusable template
                                      |
VM launch: template -> disposable clone -> cloud-init -> VMM -> TTL delete

Secure Containers (developer preview):
Kubernetes/ctr -> containerd -> containerd-shim-fluxvm-v2
  -> FluxVM REST -> QEMU + virtiofs Pod share (+ Pod-UID write-through volumes)
  -> fluxvm-guest-agent :17777 -> fluxvm-container-agent :17778 / stdio :17779
```

Full diagrams for the Network Fabric dataplane (packet-decision and control-plane sequence):
[docs/network-fabric.md](docs/network-fabric.md#packet-decision-and-control-plane-diagrams).

## Project layout

The MVP is a Cargo workspace, structured to match Zyvor FluxVM's longer-term
multi-node architecture — **23 crates**:

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
├── fluxvm-guest-protocol        wire types shared by the guest agent and its host client
├── fluxvm-guest-agent           in-guest AF_VSOCK agent binary (ping/exec/shutdown)
├── fluxvm-vsock-client          host-side vsock dialing (native for QEMU, UDS proxy for CH/Firecracker)
├── fluxvm-scheduler             VmManager: VM lifecycle orchestration + TTL reaper
├── fluxvm-api                   REST API (axum)
├── fluxvm-cli                   `fluxvm` CLI binary (composition root)
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

Deploy fragments for the containerd RuntimeClass path live under `deploy/containerd/`
(see [docs/secure-containers.md](docs/secure-containers.md)). `fluxvm-agent` (the per-*host*
node-agent for multi-node deployments — a distinct concept from `fluxvm-guest-agent` above) and
`fluxvm-kube` are both implemented and verified against real multi-host/cluster infrastructure — see
[docs/operations.md](docs/operations.md#distributed-node-agent) and
[Kubernetes CRD/operator](#kubernetes-crdoperator) below.

This project also depends on the sibling [`guestkit`](https://github.com/zyvorai/guestkit) project
(path dep from `fluxvm-image`) for offline image customization.

## Kubernetes CRD/operator

`fluxvm-kube` is a `DisposableVm` custom resource plus a node-local operator that reconciles them
against a *local* `fluxvm serve` instance's REST API — each node's operator instance only ever acts
on `DisposableVm` objects whose `spec.node` matches the node name it was started with, the same
shape as a real daemonset (see [`deploy/k8s/`](deploy/k8s/) for the Dockerfile + CRD/RBAC/DaemonSet
manifests). Verified end to end against a real k3s cluster (9/9 passing — the 9 checks span CRD
acceptance, real VM reconciliation, out-of-band-delete self-healing, and finalizer-blocked cleanup
with no leaked QEMU process; see [`scripts/test-kube-operator.sh`](scripts/test-kube-operator.sh)
for the exact checks):

```bash
fluxvm-kube --print-crd | kubectl apply -f -
NODE_NAME=$(hostname) FLUXVM_URL=http://127.0.0.1:7788 fluxvm-kube
```

**Declarative, not one-shot** — a real, tested property: if the underlying VM disappears on its own
(TTL expired, or deleted via the REST API directly) the operator notices on its next reconcile and
creates a *new* VM to replace it, the same "keep this existing" semantics a `Deployment` has for
Pods. `spec.networkMode` supports `none`/`user`/`tap`/`macvtap`. Placement: set `spec.node`
explicitly, or run one `fluxvm-kube --enable-placement` instance to pin to the least-loaded capable
node.

Related but separate: the [Secure Containers](docs/secure-containers.md) path uses containerd
RuntimeClass `fluxvm` for OCI workloads inside a FluxVM; it does not replace `DisposableVm`. The
scheduler-native alternative for Kubernetes-without-KubeVirt is `fluxvm-microvm` — see
[docs/microvm.md](docs/microvm.md).

---

## Ecosystem

FluxVM is complete and useful on its own (see [Is this for you?](#is-this-for-you) above). It's also
the VM engine underneath two other Zyvor products, which build orchestration/UX layers on top of the
same REST API rather than forking or wrapping FluxVM internals:

| Product | Role |
|---|---|
| **[zyvor-fabric](docs/zyvor-fabric.md)** | Private cloud control plane (CLI/Web/K8s operator/Terraform) — FluxVM handles VM execution, Fabric handles auth/RBAC/networking policy/UX on top |
| **[Ragnarok](docs/ragnarok.md)** | AI-powered KubeVirt VM management — creates `DisposableVm` CRs via its FluxVM Hub with OIDC/SSO and RBAC |
| **[h2kvm](https://github.com/zyvorai/h2kvm)** | Hypervisor → KVM convert + import, hands off a certified disk to FluxVM to run |
| **[GuestKit](https://github.com/zyvorai/guestkit)** | Offline disk scoring/repair — FluxVM boots and manages what GuestKit certifies, see [Who does what](#who-does-what-users) below |

Neither Fabric nor Ragnarok is required to use FluxVM directly — see the [Quick start](#quick-start) above.

### Who does what (users)

| You need… | Use |
|-----------|-----|
| Score / repair a disk **offline** (doctor, passport, fix plans) | **[GuestKit](https://github.com/zyvorai/guestkit)** |
| **Boot & manage** that qcow2 (network, SSH, TTL, pause/resume, fleets) | **This repo (FluxVM)** |
| Hypervisor → KVM convert + import | **[h2kvm](https://github.com/zyvorai/h2kvm)** |

**Certify with GuestKit → run & manage with FluxVM → convert/deploy with h2kvm.**
FluxVM already creates TAP/macvtap, optional per-VM **netns + DHCP** (known `guest_ip`), cloud-init
seeds, CoW overlays, and TTL reaping — GuestKit does **not** duplicate that; hand off after the disk
is certified.

---

## Documentation map

| Topic | Doc |
|-------|-----|
| Product positioning (who/why/when-not) | [docs/POSITIONING.md](docs/POSITIONING.md) |
| Product overview + metrics | [docs/PRODUCT_OVERVIEW.md](docs/PRODUCT_OVERVIEW.md) |
| Exhaustive feature checklist | [FEATURES.md](FEATURES.md) |
| Concrete use cases (CI runners, golden images, sandboxes, fleets) | [docs/use-cases.md](docs/use-cases.md) |
| Network Fabric (eBPF/Cilium dataplane, diagrams, why it's faster) | [docs/network-fabric.md](docs/network-fabric.md) |
| eBPF / Cilium coexistence detail | [docs/ebpf-cilium.md](docs/ebpf-cilium.md) |
| Security groups & CNP network policy | [docs/network-groups.md](docs/network-groups.md) · [docs/network-policy.md](docs/network-policy.md) |
| REST API reference, auth/RBAC, VM JSON contract | [docs/api.md](docs/api.md) |
| Day-2 operations (jailer, cgroups, pools, catalog, storage, fleet, state layout) | [docs/operations.md](docs/operations.md) |
| Building custom images (per-distro + Windows) | [docs/build-image-tutorials.md](docs/build-image-tutorials.md) |
| Secure Containers (containerd runtime-v2) | [docs/secure-containers.md](docs/secure-containers.md) |
| MicroVM (Kubernetes without KubeVirt) | [docs/microvm.md](docs/microvm.md) |
| Whole-project production checklist | [docs/PRODUCTION.md](docs/PRODUCTION.md) |
| DevOps / CI / readiness probes | [docs/DEVOPS.md](docs/DEVOPS.md) |
| Using FluxVM through zyvor-fabric | [docs/zyvor-fabric.md](docs/zyvor-fabric.md) |
| Using FluxVM through Ragnarok | [docs/ragnarok.md](docs/ragnarok.md) |
| AI-agent sandbox capability gaps | [docs/agent-sandbox-gaps.md](docs/agent-sandbox-gaps.md) |
| Ranked backlog / next features | [docs/NEXT-FEATURES.md](docs/NEXT-FEATURES.md) |

Hands-on tutorials: [network policy](docs/tutorials/network-policy/README.md) ·
[production readiness](docs/tutorials/production/README.md) ·
[MicroVM](docs/tutorials/microvm/README.md).

## Contributing & community

- **Contributing:** build/test commands, PR expectations, and repo layout — [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security:** the current hardening bar and how to report a vulnerability — [SECURITY.md](SECURITY.md).
- **Changelog:** [CHANGELOG.md](CHANGELOG.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Zyvor AI Labs. The
entire repository is under this one license; there is no dual-licensing or separately-licensed core
component.

Part of the Zyvor platform (see [Ecosystem](#ecosystem) above). More at
**[zyvor.dev](https://zyvor.dev?utm_source=github&utm_medium=fluxvm)**.
