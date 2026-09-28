# Documentation index

Every feature area and every document, in one place.

[Back to README](../README.md)

## Feature highlights

| Area | What's there | Docs |
|------|---------------|------|
| **Backends** | QEMU/KVM, Cloud Hypervisor, Firecracker and the in-tree FluxVM hypervisor behind one `VmBackend` trait; `"backend":"auto"`; vsock guest agent (`exec`, `ping`, PTY console with live resize, `copy-to`/`copy-from`) with no SSH | [docs/agent-sandbox-gaps.md](agent-sandbox-gaps.md) · [docs/operations.md](operations.md#auto-backend-selection) |
| **Networking & Network Fabric** | TAP/bridge, macvtap, user-mode NAT, per-VM netns. **Network Fabric is GA (schema v4):** TC/eBPF or Cilium-coexistence dataplane with IPv4/IPv6 L3+L4 policy, rate limits, security groups, CNP, live reconfigure and REST observability; nftables by default | [docs/network-fabric.md](network-fabric.md) · [docs/ebpf-cilium.md](ebpf-cilium.md) · [docs/network-policy.md](network-policy.md) |
| **Service Fabric** | Node-local Maglev VIP load balancing: dual-stack NAT/DSR/SNAT, health-aware routing, per-service EDT, flow export | [docs/service-fabric.md](service-fabric.md) |
| **Images** | virt-builder-style `build-image` (guestkit-based, never libguestfs), per-distro package install, Ed25519-signed catalog with REST CRUD, Windows golden-image customization | [docs/build-image-tutorials.md](build-image-tutorials.md) · [docs/operations.md](operations.md#image-catalog--signing) · [docs/windows-golden.md](windows-golden.md) |
| **Operations** | Day-2 VM verbs: restart, rename, labels + bulk selectors, clone, QEMU data disks (hot-add, live resize), serial console, live backups, scheduled snapshots with retention, VM templates, lifecycle events (SSE), remote `fluxctl` contexts, OpenAPI; cgroup v2 limits, freeze/thaw and PSI; warm VM pools; Firecracker jailer; LVM thin / NBD / Ceph RBD; admission limits; bearer-token auth/RBAC | [docs/operations.md](operations.md) · [docs/api.md](api.md#auth--rbac) |
| **Native KVM (no QEMU)** | In-tree KVM engine for Linux guests: SMP, pause/snapshot for every vCPU, restore preflight (no silent cold boot), atomic snapshot writes, raw-ext4 direct-kernel boot, static musl guest agent, and a golden Cloud-init template with a baked systemd-networkd config | [docs/native-kvm-no-qemu.md](native-kvm-no-qemu.md) · [crate README](../crates/fluxvm-hypervisor/README.md) |
| **Agent sandboxes** | Egress **HTTP ACL** (method/host/path rules, deny wins, path normalisation; HTTPS via opt-in interception) · guest file **change-set** (`baseline` / `changes`) · rootless **procbox** tier with profiles, a ptrace `learn` mode and a real-discard `dry-run` · stdlib-only **Python** and **Go** SDKs | [docs/http-acl.md](http-acl.md) · [docs/sandbox-changes.md](sandbox-changes.md) · [docs/procbox.md](procbox.md) · [`python/`](../python/README.md) · [`go/`](../go/README.md) |
| **Kubernetes & fleet** | `DisposableVm` CRD + node-local operator; `fluxvm-microvm` scheduler-native path (no KubeVirt); `fluxvm-agent` fleet registry with load-aware placement | [Kubernetes CRD/operator](kubernetes-operator.md#kubernetes-crdoperator) · [docs/microvm.md](microvm.md) · [docs/operations.md](operations.md#distributed-node-agent) |
| **Secure Containers** *(GA)* | containerd runtime-v2 shim mapping a Pod onto one microVM: CNI L2, Sentinel policy, cgroup-v2 stats, VSOCK stdio/TTY, guest AppArmor/SELinux/seccomp | [docs/secure-containers.md](secure-containers.md) · [supported profile](secure-containers-supported-profile.md) · [15-min lab](secure-containers-15min-lab.md) · [Sentinel wedge](sentinel-wedge.md) |
| **Security profiles (Phase 6)** | `standard` / `measured` / `confidential-snp` / `confidential-tdx`: measured software-test evidence on ordinary QEMU hosts; confidential control plane tested without claiming host-memory encryption until a hardware run | [docs/security-profiles.md](security-profiles.md) · [howto / CI](guides/security-profiles-howto.md) |
| **Sentinel observability** | eBPF host + guest runtime intelligence: per-VM syscall/page-fault telemetry, drop reasons, flight recorder, BPF-LSM VMM guard/QoS, XDP shield | [docs/runtime-intelligence.md](runtime-intelligence.md) · [docs/flight-recorder.md](flight-recorder.md) |

---

<a id="use-cases"></a>

## Use cases

Eleven use cases map onto what is implemented today — nothing below is aspirational. Detail:
[docs/use-cases.md](use-cases.md).

| Outcome you want | What it uses |
|---|---|
| **CI/CD runners that isolate every job** | VM-per-job over vsock `exec` (no SSH, no network path needed); `ttl_seconds` guarantees cleanup even if the job crashes |
| **A golden-image pipeline** | Build once (`fluxctl build-image`), reuse via qcow2 CoW overlays; SHA-256 plus an optional Ed25519-signed image catalog |
| **Kubernetes-native VM workloads without KubeVirt** | `DisposableVm` CRD + node-local `fluxvm-kube` operator, verified against a real k3s cluster |
| **OCI workloads with a per-Pod guest kernel** | `containerd-shim-fluxvm-v2` — **GA** (not Kata-equivalent; see GA boundaries in [docs/secure-containers.md](secure-containers.md)) |
| **A multi-host fleet without Kubernetes** | `fluxvm-agent` central registry + load-aware placement, verified across two physically separate hosts |
| **Sandboxed / untrusted code execution** | Firecracker jailer + cgroup v2 + netns + vsock `exec` + TTL reaper — the same isolation *shape* as gVisor/Firecracker-based CI sandboxes |
| **AI-agent sandboxes with guard rails** | `/v1/sandboxes` in two tiers (microVM, or rootless procbox), an egress ACL on **method + host + path** (HTTPS via opt-in TLS interception), a file **change-set** of what the agent touched, and Python and Go SDKs — [docs/http-acl.md](http-acl.md) · [docs/sandbox-changes.md](sandbox-changes.md) |
| **Linux VMs with no QEMU installed** | In-tree KVM engine + a golden Cloud-init/agent template: `fluxctl vm-template create native-agent <name>` — [docs/native-kvm-no-qemu.md](native-kvm-no-qemu.md) |
| **Per-branch dev and test environments** | Cheap qcow2 CoW cloning, optional `ttl_seconds`, `pause`/`resume` to park instead of rebuild |
| **Your own storage backend** | LVM thin, NBD or Ceph RBD |
| **Networking that matches your environment** | User-mode NAT, TAP+bridge or macvtap, plus an opt-in bridge-less direct tap (eBPF redirect; [docs/direct-datapath.md](direct-datapath.md)) |

---

## Documentation map

| Topic | Doc |
|-------|-----|
| Product positioning (who/why/when-not) | [docs/POSITIONING.md](POSITIONING.md) |
| Product overview + metrics | [docs/PRODUCT_OVERVIEW.md](PRODUCT_OVERVIEW.md) |
| Exhaustive feature checklist | [FEATURES.md](../FEATURES.md) |
| Concrete use cases (CI runners, golden images, sandboxes, fleets) | [docs/use-cases.md](use-cases.md) |
| Network Fabric (eBPF/Cilium dataplane, diagrams, why it's faster) | [docs/network-fabric.md](network-fabric.md) |
| eBPF / Cilium coexistence detail | [docs/ebpf-cilium.md](ebpf-cilium.md) |
| Cilium CNI (Secure Containers L2) | [docs/cilium-cni.md](cilium-cni.md) |
| Direct (bridge-less) datapath, with measurements | [docs/direct-datapath.md](direct-datapath.md) |
| Security groups & CNP network policy | [docs/network-groups.md](network-groups.md) · [docs/network-policy.md](network-policy.md) |
| REST API reference, auth/RBAC, VM JSON contract | [docs/api.md](api.md) |
| Day-2 operations (jailer, cgroups, pools, catalog, storage, fleet, state layout) | [docs/operations.md](operations.md) |
| Building custom images (per-distro + Windows) | [docs/build-image-tutorials.md](build-image-tutorials.md) |
| Secure Containers (containerd runtime-v2) | [docs/secure-containers.md](secure-containers.md) |
| Security profiles (Phase 6) — measured + confidential control plane | [docs/security-profiles.md](security-profiles.md) · [howto + how to test](guides/security-profiles-howto.md) · [CI](../.github/workflows/security-profiles.yml) |
| MicroVM (Kubernetes without KubeVirt) | [docs/microvm.md](microvm.md) |
| Whole-project production checklist | [docs/PRODUCTION.md](PRODUCTION.md) |
| DevOps / CI / readiness probes | [docs/DEVOPS.md](DEVOPS.md) |
| Using FluxVM through zyvor-fabric | [docs/zyvor-fabric.md](zyvor-fabric.md) |
| Using FluxVM through Ragnarok | [docs/ragnarok.md](ragnarok.md) |
| AI-agent sandbox capability gaps | [docs/agent-sandbox-gaps.md](agent-sandbox-gaps.md) |
| Native KVM, no QEMU (golden template, snapshots, SMP) | [docs/native-kvm-no-qemu.md](native-kvm-no-qemu.md) · [crates/fluxvm-hypervisor/README.md](../crates/fluxvm-hypervisor/README.md) |
| Egress HTTP method/path ACL and HTTPS interception | [docs/http-acl.md](http-acl.md) |
| Sandbox file change-set (baseline / changes) | [docs/sandbox-changes.md](sandbox-changes.md) |
| procbox: rootless Landlock + seccomp sandbox, and as a `/v1/sandboxes` kind | [docs/procbox.md](procbox.md) · [docs/procbox-backend.md](procbox-backend.md) |
| Python and Go SDKs | [python/README.md](../python/README.md) · [go/README.md](../go/README.md) |
| Ranked backlog / next features | [docs/NEXT-FEATURES.md](NEXT-FEATURES.md) |

Hands-on tutorials: [network policy](tutorials/network-policy/README.md) ·
[production readiness](tutorials/production/README.md) ·
[MicroVM](tutorials/microvm/README.md).
