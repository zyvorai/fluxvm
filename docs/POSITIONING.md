# FluxVM — Product Positioning

**FluxVM** manages secure, isolated virtual machines from one control plane — Firecracker, Cloud Hypervisor, QEMU/KVM, or the FluxVM hypervisor.

A complete product on its own. Also the VM engine under Zyvor Fabric and Ragnarok — same binary, same API.

Part of [Zyvor](https://zyvor.dev).

---

## Elevator pitch

> Run real VMs with a real API. JSON and REST where you’d otherwise hand-write XML for `virsh`. Four backends. One contract. Optional TTL and CoW when you want disposable compute.

---

## Who this is for

- **Platform engineers** replacing libvirt — a real API, not a private-cloud rewrite.
- **CI teams** needing VM-per-job isolation that cleans up.
- **Kubernetes operators** who want VMs without KubeVirt.
- **Buyers sizing maturity** — read [Proof & status](../README.md#maturity-whats-real-today) before you commit.

---

## What FluxVM is

| | |
|---|---|
| **Category** | Host-local VM control plane / libvirt replacement |
| **Runtime** | `fluxctl` + `fluxctl serve` — no libvirtd |
| **Scope** | Lifecycle, images, networking (incl. Network Fabric GA), Kubernetes CRDs, fleets |
| **Interfaces** | CLI · REST · Kubernetes CRDs |

---

## Standalone first

Start with FluxVM alone. [Zyvor Fabric](zyvor-fabric.md) and [Ragnarok](ragnarok.md) are optional layers on the same API — never required for day one.

| | FluxVM alone | Via Fabric | Via Ragnarok |
|---|---|---|---|
| You get | CLI + REST | Console, auth, private-cloud UX | AI-assisted hub, SSO |
| Pick when | Smallest footprint | Multi-tenant console | Enterprise Kubernetes UX |

---

## Competitive frame

### vs. libvirt/virsh

Closest shipping foil. No libvirtd, no XML — `fluxctl create` ≈ `virsh define`+`start`. Full map: [README](../README.md#vs-libvirtvirsh).

### vs. KubeVirt/OpenShift

Different model — host VMM under `fluxctl serve`, not virt-launcher. Not API-compatible. See [microvm.md](microvm.md).

### vs. gVisor / Kata

Isolation-*shape* analogies for sandboxes and Secure Containers — not feature parity. Secure Containers is developer preview.

### Look elsewhere when

- You need a finished multi-tenant public-cloud boundary today.
- You need production OCI/containerd workloads today (Secure Containers is preview).
- You need KubeVirt API compatibility.

---

## Further reading

- [README](../README.md) — product front door
- [PRODUCT_OVERVIEW.md](PRODUCT_OVERVIEW.md) — capability tour
- [use-cases.md](use-cases.md) — scenarios
- [PRODUCTION.md](PRODUCTION.md) — operator checklist
