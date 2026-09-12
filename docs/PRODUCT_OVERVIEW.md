# FluxVM — Product Overview

This doc is the capability tour and the one authoritative metrics table for FluxVM. For the pitch and quick start, see the [README](../README.md); for who this is (and isn't) for, see [POSITIONING.md](POSITIONING.md); for the exhaustive feature checklist, see [FEATURES.md](../FEATURES.md).

## The Problem

Teams that need short-lived, isolated VMs — CI runners, sandboxed code execution, per-branch dev environments, Kubernetes-native disposable workloads — are usually stuck choosing between:

- **Manual libvirt/virsh scripting** — XML domain definitions, no REST API, no built-in TTL cleanup, easy for orphaned VMs to accumulate
- **A full private-cloud platform** — adopting VMware/OpenStack/a KubeVirt cluster just to get disposable VMs is disproportionate overhead for a workload that's supposed to be lightweight and short-lived
- **Container-only isolation** — good enough until the workload needs a real kernel boundary (untrusted code, a kernel-dependent test, a legacy binary that needs its own kernel)

FluxVM fills the specific gap: a control plane built around VMs that are supposed to be short-lived, with a real API and without requiring a whole private-cloud stack to get there.

---

## What Is FluxVM?

FluxVM is a Rust-native disposable-VM control plane. It provides:

- **One binary, one REST API** — `fluxvm` CLI talks to `fluxvm serve`, no libvirtd, no XML
- **4 backends behind one trait** — QEMU/KVM, Cloud Hypervisor, Firecracker, and the in-tree FluxVM hypervisor, selectable per-VM or via `"backend":"auto"`
- **TTL-guaranteed cleanup** — `ttl_seconds` on any VM spec means a forgotten or crashed job still gets torn down
- **A vsock guest agent** — `exec`, PTY console, file transfer, with no SSH or network path required

---

## Capability Tour

The exhaustive, line-by-line checklist lives in **[FEATURES.md](../FEATURES.md)**. This section is the skim version.

**VM lifecycle** — create, list, get, pause, resume, delete across all 4 backends; `"backend":"auto"` resolution; vsock-based `exec`/console/file-transfer with no SSH required.

**Networking** — QEMU user-mode NAT, TAP+bridge, per-VM network namespaces, macvtap; **Network Fabric is GA (schema v4)** — a TC/eBPF or Cilium-coexistence dataplane with IPv4/IPv6 L3+L4 policy, rate limits, security groups, CNP, live reconfigure, and REST observability (nftables is the default fallback).

**Service Fabric** — node-local Maglev VIP load balancing: dual-stack NAT/DSR/SNAT, health-aware routing, incremental reconcile, per-service EDT, flow export.

**Images** — virt-builder-style `build-image` (guestkit-based, never libguestfs), per-distro package install, an Ed25519-signed image catalog with REST CRUD, Windows/Kryton golden-image customization with live QGA.

**Operations** — cgroup v2 resource control (limits, freeze/thaw, PSI), warm VM pools, the Firecracker jailer (chroot + uid/gid drop), alternative storage backends (LVM thin, NBD, Ceph RBD — RBD verified against a real Rook Ceph cluster), admission policy limits, bearer-token auth/RBAC.

**Kubernetes & fleet** — `DisposableVm` CRD + node-local operator (verified end to end against a real k3s cluster, 9/9 checks passing); `fluxvm-microvm` scheduler-native path as a KubeVirt alternative; `fluxvm-agent` distributed node-agent with a central fleet registry and load-aware placement, verified across two real, physically separate hosts.

**Secure Containers** *(developer preview)* — containerd runtime-v2 shim (`containerd-shim-fluxvm-v2`) mapping a Pod/task group onto one QEMU FluxVM, with CNI L2, cgroup-v2 stats, VSOCK stdio/TTY, namespaces, device passthrough, guest AppArmor/SELinux/seccomp enforcement. Not yet Kata-equivalent — see [docs/secure-containers.md](secure-containers.md) for the itemized gaps.

**Sentinel observability** — eBPF-based host + guest runtime intelligence: per-VM syscall/page-fault telemetry, drop-reason tracking, flight recorder, BPF-LSM VMM guard/QoS, XDP shield, topology steering.

---

## Architecture

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
```

Full diagrams (image pipeline, Secure Containers request flow, Network Fabric packet-decision and control-plane sequence): [README — Architecture at a glance](../README.md#architecture-at-a-glance) and [docs/network-fabric.md](network-fabric.md#packet-decision-and-control-plane-diagrams).

---

## Comparison

| Feature | FluxVM | libvirt/virsh | KubeVirt |
|---------|:--------:|:----------:|:---------:|
| REST API | Yes | No (XML-RPC-ish via libvirtd) | Yes (Kubernetes API) |
| VM spec format | JSON | XML domain definitions | Kubernetes CRD YAML |
| TTL-guaranteed cleanup | Yes (`ttl_seconds`) | No | No (Pod lifecycle only) |
| Backends | QEMU/KVM, Cloud Hypervisor, Firecracker, in-tree hypervisor | QEMU/KVM (broad hypervisor support via drivers) | KVM via virt-launcher |
| Where the VMM runs | Host, under `fluxvm serve` | Host, under `libvirtd` | Inside a virt-launcher Pod |
| Kubernetes-native | Yes (`DisposableVm` CRD, MicroVM) | No | Yes (native) |
| Live migration / CDI / `virtctl` | No | No (needs orchestration layer) | Yes |
| eBPF/TC dataplane | Yes — Network Fabric, GA schema v4 | No | Depends on CNI |
| Multi-host fleet management | Yes — `fluxvm-agent`, verified across 2 real hosts | No (needs external orchestration) | Via Kubernetes scheduler |
| OCI/containerd workload support | Developer preview (Secure Containers) | No | No (different workload model) |
| License | Apache-2.0 | LGPL | Apache-2.0 |

This table intentionally covers only what's verifiable today — no unpublished performance numbers, no forward-looking claims. See [POSITIONING.md](POSITIONING.md#competitive-frame) for the fuller competitive narrative, including the honest caveats (KubeVirt has live migration/CDI/`virtctl` and FluxVM doesn't; libvirt has broader hypervisor driver support).

---

## Deployment Models

### Single host, standalone

`fluxvm serve` on one Linux box with KVM. Suitable for CI runners, dev/test environments, and sandboxed execution on a single machine.

**Requirements:** Linux, KVM, current stable Rust toolchain to build.

### Multi-host fleet (no Kubernetes)

`fluxvm-agent` provides a central fleet registry plus per-host heartbeat clients, with load-aware placement — verified across two real, physically separate hosts.

**Requirements:** 2+ hosts, network connectivity between them for the fleet registry.

### Kubernetes-native

`fluxvm-kube` operator reconciling `DisposableVm` CRs against a local `fluxvm serve` instance per node, or `fluxvm-microvm` for scheduler-driven placement via shadow Pods.

**Requirements:** A Kubernetes cluster (verified against k3s), nodes with `/dev/kvm`.

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | Rust |
| VMM backends | QEMU/KVM, Cloud Hypervisor, Firecracker, in-tree `fluxvm-hypervisor` |
| Networking | netlink (direct), TC/eBPF (Network Fabric), nftables (fallback) |
| Guest agent transport | AF_VSOCK |
| Kubernetes integration | Custom Resource Definitions (`DisposableVm`, MicroVM), controller-runtime-style operators |
| Image tooling | guestkit-based (no libguestfs dependency) |

---

## Project Statistics

Every figure below is counted directly from source, not estimated.

| Metric | Value | Method |
|--------|-------|--------|
| Crates | 23 | `ls crates/` |
| Backends | 4 | QEMU/KVM, Cloud Hypervisor, Firecracker, in-tree FluxVM hypervisor |
| Kubernetes CRD operator validation | 9/9 checks passing | Real k3s cluster; see [`scripts/test-kube-operator.sh`](../scripts/test-kube-operator.sh) — covers CRD acceptance, live reconciliation to a real running VM, out-of-band-delete self-healing, and finalizer-blocked cleanup with no leaked QEMU process |
| Multi-host fleet validation | Verified across 2 real, physically separate hosts | [docs/operations.md](operations.md#distributed-node-agent) |
| Storage backends | 4 | qcow2/raw (default), LVM thin, NBD, Ceph RBD (RBD verified against a real Rook Ceph cluster) |
| Network modes | 4 | user-mode NAT, TAP+bridge, netns+DHCP, macvtap — all 4 SSH-verified end to end in regression tests |
| Boot latency / VM density / throughput | **Not yet published** | Tracked as open work in [docs/NEXT-FEATURES.md](NEXT-FEATURES.md) — we don't cite a number here because none has been benchmarked with a documented method |

Unlike some of the figures in this table, we deliberately don't include a lines-of-code count or an aggregate REST-endpoint count — neither is currently asserted anywhere in this project's own docs, and inventing one here would just create the kind of stale, unverifiable claim this whole document is trying to avoid.

---

## License

Apache License 2.0 — free for commercial use, modification, and distribution, for the entire repository. See [README.md — License](../README.md#license) and [NOTICE](../NOTICE).

---

*For technical details, see [docs/api.md](api.md), [docs/operations.md](operations.md), and [docs/PRODUCTION.md](PRODUCTION.md).*
