# FluxVM — Product Overview

Capability tour for FluxVM. Pitch: [README](../README.md). Who it’s for: [POSITIONING.md](POSITIONING.md). Checklist: [FEATURES.md](../FEATURES.md).

## The problem

Teams that need a host-local VM API usually choose between hand-rolled `virsh` XML, a full private-cloud stack, or containers that share the host kernel.

FluxVM fills the gap: a real control plane without the platform rewrite.

## What is FluxVM?

- **One binary, one REST API** — no libvirtd, no XML
- **Four backends** — QEMU/KVM, Cloud Hypervisor, Firecracker, FluxVM hypervisor
- **Optional TTL** — cleanup after crash or forget
- **Vsock guest agent** — exec, console, copy with no SSH

## Capability tour

Skim version. Full checklist: [FEATURES.md](../FEATURES.md).

**Lifecycle** — create, list, pause, resume, delete; `"backend":"auto"`; vsock exec.

**Networking** — user NAT, TAP, netns, macvtap; **Network Fabric (GA)** — [network-fabric.md](network-fabric.md).

**Service Fabric** — node-local Maglev VIP load balancing.

**Images** — `build-image`, signed catalog, Windows goldens via GuestKit.

**Operations** — cgroups, warm pools, jailer, LVM/NBD/Ceph, admission policy, token auth.

**Kubernetes & fleet** — DisposableVm · MicroVM · fluxvm-agent — [microvm.md](microvm.md).

**Secure Containers** *(preview)* — containerd shim → one QEMU per Pod — [secure-containers.md](secure-containers.md).

**Sentinel** — eBPF runtime intelligence (syscall, drop reasons, flight recorder, topology).

## Architecture

```text
CLI / REST ──► VmManager ──► QEMU | Cloud Hypervisor | Firecracker | FluxVM HV
                                    └────────── KVM + TAP / bridge / netns ──┘
```

One `VmBackend` trait. Schedulers and APIs never branch on the VMM.

## Next

- [Quick start](../README.md#quick-start)
- [Use cases](use-cases.md)
- [Getting started](user/getting-started.md)
- [PRODUCTION.md](PRODUCTION.md)
