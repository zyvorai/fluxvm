# FluxVM — Product Positioning

**One control plane. Four backends. A real API.**

**FluxVM** is a Rust-native control plane for creating and managing secure, isolated
virtual machines on Linux via Firecracker, Cloud Hypervisor, QEMU/KVM, or the in-tree
FluxVM hypervisor. Short-lived and disposable workloads (TTL cleanup, cheap CoW clones)
are a first-class *use* of FluxVM — not the product’s identity.

It is **not** positioned as "the VM engine under Fabric" first and a standalone product second — that gets the emphasis backwards. FluxVM is a complete, independently useful control plane on its own. It's also the VM engine other Zyvor products (Fabric, Ragnarok) build on, the same way a database is both usable directly and the thing an ORM sits on top of.

Part of the [Zyvor](https://zyvor.dev) product family from Zyvor AI Labs.

---

## Elevator pitch

> FluxVM manages secure, isolated virtual machines — via Firecracker, Cloud Hypervisor, QEMU/KVM, or its own in-tree hypervisor — from one Rust-native control plane with a real REST API. Run it standalone as a libvirt replacement, or as the VM engine under another Zyvor product; it's the same binary and the same API either way. Use TTL and CoW when you want disposable compute; leave them off for longer-lived guests.

The strongest concrete hook here is the first one: **a real REST API where you'd otherwise be
hand-rolling XML for `virsh`.** Everything else in this doc builds on that.

---

## Who this is for

| Persona | Role | What they care about | Where FluxVM fits |
|---------|------|----------------------|--------------------|
| **Platform/infra engineer evaluating a libvirt replacement** | Owns host-local VM lifecycle tooling | A real API instead of XML + `virsh`, without adopting a whole private-cloud platform | Drop-in command mapping (`fluxctl create` ≈ `virsh define`+`start`, etc.) — see [README: vs. libvirt/virsh](../README.md#vs-libvirtvirsh) |
| **CI/platform engineer building ephemeral infra** | Needs VM-per-job isolation that actually cleans up | TTL-guaranteed cleanup, no network path for untrusted code, cheap CoW cloning | Optional `ttl_seconds`, `network.mode: "none"` + vsock `exec`, qcow2 overlays — see [Use cases](../README.md#use-cases) |
| **Kubernetes platform engineer wanting VMs without KubeVirt** | Runs a K8s cluster, needs real VMs for some workloads | A lighter-weight, non-KubeVirt path that still feels Kubernetes-native | `DisposableVm` CRD + `fluxvm-kube` operator, or `fluxvm-microvm` for scheduler-driven placement — see [docs/microvm.md](../docs/microvm.md) |
| **Economic buyer evaluating build-vs-adopt for a host-local VM layer** | Deciding whether to build this in-house or adopt FluxVM | Whether the maturity level matches the use case, whether it's a maintained open project or a dead end | Apache-2.0, actively developed, but read the [maturity caveat](../README.md#maturity-whats-real-today) honestly before committing — this is not yet a finished multi-tenant security boundary |

The economic-buyer row matters here specifically because FluxVM is explicit about *not* being finished in one dimension (multi-tenant security hardening) while being solid in others (core VM lifecycle, Network Fabric GA, k3s-verified Kubernetes operator). A buyer should read the [maturity caveat](../README.md#maturity-whats-real-today) as the actual scoping tool, not a boilerplate disclaimer.

---

## What FluxVM Is

| Dimension | Positioning |
|-----------|-------------|
| **Category** | Host-local VM control plane / libvirt replacement |
| **Analogy** | `virsh` with a REST API instead of XML — also strong for short-lived VMs when you opt into TTL/CoW |
| **Runtime** | `fluxvm` CLI + `fluxctl serve` daemon — one binary, direct netlink networking, no libvirtd |
| **Scope** | VM lifecycle across 4 backends, image build/catalog, per-VM networking (incl. eBPF dataplane), Kubernetes CRDs, multi-host fleets |
| **Interfaces** | CLI (`fluxvm`), REST API, Kubernetes CRDs (`DisposableVm`, MicroVM) |

---

## Standalone vs. via another Zyvor product

FluxVM is designed to be adopted **standalone** first. The two other Zyvor products that use it as their VM engine — [zyvor-fabric](../docs/zyvor-fabric.md) and [Ragnarok](../docs/ragnarok.md) — are optional orchestration/UX layers on top of the same REST API, not a requirement for using FluxVM.

| | Run FluxVM directly | Run it via Fabric | Run it via Ragnarok |
|---|---|---|---|
| What you get | `fluxvm` CLI + REST API, full control over VM JSON specs | Fabric's CLI/Web/K8s-operator/Terraform UX, plus auth/RBAC/network-policy layered on top | AI-assisted KubeVirt-style VM management, OIDC/SSO, RBAC via Ragnarok's FluxVM Hub |
| When to pick it | You want the smallest possible footprint, or you're building your own orchestration on top | You want a private-cloud control plane with multi-tenant auth and a web console | You want `DisposableVm` CRs created and managed through an AI-assisted hub with enterprise SSO |
| Does it require the others? | No — this is the base layer | Fabric talks to a local `fluxctl serve` over REST; it doesn't fork or vendor FluxVM | Ragnarok creates `DisposableVm` CRs against `fluxvm-kube`; same relationship |

If you're not sure which layer you need: start with FluxVM directly. Both Fabric and Ragnarok are additive — adopting FluxVM standalone never locks you out of adding either later, since they talk to the same unmodified API.

---

## Competitive Frame

### vs. libvirt/virsh

FluxVM's most concrete, already-shipping differentiation. No libvirtd, no XML domain definitions — a direct command mapping exists today (`fluxctl create` ≈ `virsh define`+`start`, `fluxctl list`/`get` ≈ `virsh list`/`dominfo`, `fluxctl pause`/`resume` ≈ `virsh suspend`/`resume`, `fluxctl delete` ≈ `virsh destroy`), plus a real REST API libvirt doesn't have. See [README](../README.md#vs-libvirtvirsh) for the full table.

### vs. KubeVirt/OpenShift

Explicitly **not** a replacement — `virtctl`, live migration, and CDI stay KubeVirt's job. FluxVM's Kubernetes-native paths (`DisposableVm`, `fluxvm-microvm`) run the VMM on the host under `fluxctl serve` rather than inside a virt-launcher Pod — a different model, including short-lived workloads when you want them, not a general-purpose KubeVirt alternative. Full comparison: [docs/microvm.md](../docs/microvm.md#vs-disposablevm-and-kubevirt).

### vs. gVisor / Kata Containers (isolation-shape analogies only)

FluxVM's sandboxed-execution use case (Firecracker jailer + cgroups + netns + vsock + TTL reaper) produces **the same isolation shape** as gVisor- or Firecracker-based CI sandboxes — this is an analogy about the security properties, not a feature-parity claim. Similarly, Secure Containers aims for "the same security shape users expect from Kata Containers," plus **Sentinel** (host↔guest eBPF NetworkPolicy — see [sentinel-wedge.md](sentinel-wedge.md)). It is **not** Kata-equivalent packaging: see the supported profile and flip runbook ([secure-containers-supported-profile.md](secure-containers-supported-profile.md), [secure-containers-flip-runtimeclass.md](secure-containers-flip-runtimeclass.md)). Don't market either as matching gVisor or Kata feature-for-feature — the honest claim is isolation-shape similarity built on FluxVM's own primitives, not a compatibility layer.

### When to look elsewhere

- **You need a finished multi-tenant security boundary today** — see the [maturity caveat](../README.md#maturity-whats-real-today).
- **You need full Kata / CDI / non-QEMU Secure Containers VMM parity** — Secure Containers is GA with documented scope boundaries; see [secure-containers.md](secure-containers.md).
- **You need KubeVirt/OpenShift API compatibility** — not a goal here; see the vs. KubeVirt section above.
- **You need published boot-latency/density/throughput numbers for capacity planning** — measure with [capability-figures.md](capability-figures.md) / benches; don't cite unpublished SPECs as product claims.

---

## Messaging Guidelines

### Say

- "FluxVM — Rust-native VM control plane, standalone or as another product's VM backend"
- "Host-local libvirt replacement with a real REST API"
- "The same binary and API whether you run it directly or through Fabric/Ragnarok"
- **Supports disposable / short-lived workloads via TTL and CoW when you need them**
- "Firecracker isolation layering for production hosts; density figures optional for microVM packing" ([capability-figures.md](capability-figures.md))

### Avoid

- Leading with "Disposable Compute Engine" or defining FluxVM *as* disposable-only — disposable is a use pattern, not the category
- Leading with "FluxVM is the engine under Fabric" — that undersells it as standalone-adoptable and buries the libvirt-replacement pitch, which is the strongest concrete differentiator this project has
- Claiming feature parity with Kata Containers or gVisor — the honest claim is isolation-shape similarity, not compatibility
- Citing unpublished boot-latency, density, or throughput numbers — measure first; see [capability-figures.md](capability-figures.md)
- Softening the MVP/multi-tenant-security-boundary caveat to sound more finished than it is
- Presenting Secure Containers as Kata-equivalent or claiming unrestricted hostPath — GA with documented scope boundaries

---

## License

Apache License 2.0, applied to the entire repository — see [README.md — License](../README.md#license) and [NOTICE](../NOTICE). No dual licensing, no separately-licensed core component, no commercial tier for FluxVM itself (Fabric and Ragnarok, which use FluxVM as their engine, are separate products with their own licensing).

---

## Links

- Product: [zyvor.dev](https://zyvor.dev)
- Repository: [github.com/zyvorai/fluxvm](https://github.com/zyvorai/fluxvm)
- Product overview + metrics: [PRODUCT_OVERVIEW.md](PRODUCT_OVERVIEW.md)
- Exhaustive feature checklist: [../FEATURES.md](../FEATURES.md)
- Use cases: [../docs/use-cases.md](../docs/use-cases.md)
- Documentation map: [../README.md#documentation-map](../README.md#documentation-map)
