# FluxVM — Product Overview

**A host-local VM API — without the platform rewrite.** Secure Containers add
Kubernetes RuntimeClass `fluxvm`: a Pod with its own guest kernel, plus
**Sentinel** host↔guest policy ([sentinel-wedge.md](sentinel-wedge.md)) — not
Kata-equivalent packaging ([secure-containers-supported-profile.md](secure-containers-supported-profile.md)).

This doc is the capability tour and the one authoritative metrics table for FluxVM. For the pitch and quick start, see the [README](../README.md); for who this is (and isn't) for, see [POSITIONING.md](POSITIONING.md); for the exhaustive feature checklist, see [FEATURES.md](../FEATURES.md).

## The Problem

Teams that need a host-local VM control plane — CI runners, sandboxed code execution, per-branch environments, Kubernetes VM workloads, or longer-lived guests — are usually stuck choosing between:

- **Manual libvirt/virsh scripting** — XML domain definitions, no REST API, no optional TTL cleanup, easy for orphaned VMs to accumulate
- **A full private-cloud platform** — adopting VMware/OpenStack/a KubeVirt cluster just to get a solid VM API is disproportionate overhead for many teams
- **Container-only isolation** — good enough until the workload needs a real kernel boundary (untrusted code, a kernel-dependent test, a legacy binary that needs its own kernel)

FluxVM fills that gap: a control plane with a real API, without requiring a whole private-cloud stack. Disposable / short-lived patterns (TTL, CoW) are available when you want them.

---

## What Is FluxVM?

FluxVM is a Rust-native VM control plane. It provides:

- **One binary, one REST API** — `fluxvm` CLI talks to `fluxctl serve`, no libvirtd, no XML
- **4 backends behind one trait** — QEMU/KVM, Cloud Hypervisor, Firecracker, and the in-tree FluxVM hypervisor, selectable per-VM or via `"backend":"auto"`
- **Optional TTL cleanup** — `ttl_seconds` on a VM spec means a forgotten or crashed job still gets torn down when you opt in
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

**Secure Containers** *(GA)* — containerd runtime-v2 shim (`containerd-shim-fluxvm-v2`) mapping a Pod/task group onto one FluxVM microVM, with CNI L2, cgroup-v2 stats, VSOCK stdio/TTY, namespaces, device passthrough, guest AppArmor/SELinux/seccomp, and Sentinel NetworkPolicy. Supported profile + flip runbook: [secure-containers-supported-profile.md](secure-containers-supported-profile.md), [secure-containers-flip-runtimeclass.md](secure-containers-flip-runtimeclass.md). Not Kata-equivalent — see [secure-containers.md](secure-containers.md).

**Sentinel** — eBPF host + guest policy/observability for Secure Containers and the Network Fabric edge; buyer wedge: [sentinel-wedge.md](sentinel-wedge.md).

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
| Where the VMM runs | Host, under `fluxctl serve` | Host, under `libvirtd` | Inside a virt-launcher Pod |
| Kubernetes-native | Yes (`DisposableVm` CRD, MicroVM) | No | Yes (native) |
| Live migration / CDI / `virtctl` | QEMU source + receiver (not KubeVirt parity); no CDI/`virtctl` | No (needs orchestration layer) | Yes |
| eBPF/TC dataplane | Yes — Network Fabric, GA schema v4 | No | Depends on CNI |
| Multi-host fleet management | Yes — `fluxvm-agent`, verified across 2 real hosts | No (needs external orchestration) | Via Kubernetes scheduler |
| OCI/containerd workload support | GA (Secure Containers; not Kata-equivalent) | No | No (different workload model) |
| License | Apache-2.0 | LGPL | Apache-2.0 |

This table intentionally covers only what's verifiable today — no unpublished performance numbers, no forward-looking claims. See [POSITIONING.md](POSITIONING.md#competitive-frame) for the fuller competitive narrative, including the honest caveats (KubeVirt still owns CDI/`virtctl` and full cluster migration orchestration; FluxVM's QEMU migration path is host-API + Fabric, not KubeVirt parity; libvirt has broader hypervisor driver support).

---

## Deployment Models

### Single host, standalone

`fluxctl serve` on one Linux box with KVM. Suitable for CI runners, dev/test environments, and sandboxed execution on a single machine.

**Requirements:** Linux, KVM, current stable Rust toolchain to build.

### Multi-host fleet (no Kubernetes)

`fluxvm-agent` provides a central fleet registry plus per-host heartbeat clients, with load-aware placement — verified across two real, physically separate hosts.

**Requirements:** 2+ hosts, network connectivity between them for the fleet registry.

### Kubernetes-native

`fluxvm-kube` operator reconciling `DisposableVm` CRs against a local `fluxctl serve` instance per node, or `fluxvm-microvm` for scheduler-driven placement via shadow Pods.

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
| Network modes | 4 (+1 opt-in) | user-mode NAT, TAP+bridge, netns+DHCP, macvtap — all 4 SSH-verified end to end in regression tests; bridge-less `direct` is GA for Secure Containers (`FLUXVM_CONTAINER_CNI_DATAPATH=auto\|direct\|bridge`, live Cilium/KVM evidence in [direct-datapath.md](direct-datapath.md)) |
| Boot latency / VM density / migration downtime | **Method published; archived sample numbers below — not a sizing SLA** | `scripts/record-baseline.sh` + [benchmarks/evidence/sc-hotcake-bundle-20260926.txt](benchmarks/evidence/sc-hotcake-bundle-20260926.txt). Firecracker’s 125 ms / 5-per-core figures in [capability-figures.md](capability-figures.md) are not FluxVM SLAs. |

### Capacity table (archived evidence only)

Every row cites a file under `docs/benchmarks/evidence/`. Do not treat these as
product SLAs — they are lab archives for planning conversations.

| Metric | Archived value | Evidence |
|---|---|---|
| Warm-pool claim (API, QEMU) | 24 ms to running member | [direct-datapath-live-realguest-20260920.txt](benchmarks/evidence/direct-datapath-live-realguest-20260920.txt) §5 |
| Bridge vs direct pod↔pod RTT (real guest) | p50 ~0.53 ms vs ~0.46 ms (inside run noise) | same file §3 |
| Bridge vs direct TCP (1 GiB nc) | ~0.34 vs ~0.37 Gbit/s (no clear guest-visible win) | same file §3 |
| flux-vm sandbox cold create (N=4, 256 MiB) | avg ~28.5 s; VMM RSS ~5.5 MiB | [density-20260918-80.79.5.173.txt](benchmarks/evidence/density-20260918-80.79.5.173.txt) Run B |
| flux-vm sandbox cold create (N=8) | avg ~65 s | same file Run A |
| Policy Observer RSS (idle scrape) | VmRSS ~8.8 MiB | [policy-observer-scrape-20260918T035554Z.txt](benchmarks/evidence/policy-observer-scrape-20260918T035554Z.txt) |
| SC k8s userns | Succeeded, distinct_user_ns=1 | [sc-live-userns-k8s-20260926.txt](benchmarks/evidence/sc-live-userns-k8s-20260926.txt) |
| SC in-VM distinct userns | distinct_user_ns=2 | [sc-live-userns-k8s-multi-20260926.txt](benchmarks/evidence/sc-live-userns-k8s-multi-20260926.txt) |
| SC live finish pass (lab) | pass=7 skip=3 fail=0 | [sc-live-phases-summary-20260926.txt](benchmarks/evidence/sc-live-phases-summary-20260926.txt) |

Bundle index + SHA-256 of members: [sc-hotcake-bundle-20260926.txt](benchmarks/evidence/sc-hotcake-bundle-20260926.txt).

Unlike some of the figures in this table, we deliberately don't include a lines-of-code count or an aggregate REST-endpoint count — neither is currently asserted anywhere in this project's own docs, and inventing one here would just create the kind of stale, unverifiable claim this whole document is trying to avoid.

---

## License

Apache License 2.0 — free for commercial use, modification, and distribution, for the entire repository. See [README.md — License](../README.md#license) and [NOTICE](../NOTICE).

---

*For technical details, see [docs/api.md](api.md), [docs/operations.md](operations.md), and [docs/PRODUCTION.md](PRODUCTION.md).*
