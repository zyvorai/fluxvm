# Ecosystem

How FluxVM relates to zyvor-fabric, Ragnarok, h2kvm and GuestKit, and how to talk to Zyvor.

[Back to README](../README.md)

## Ecosystem

FluxVM is complete and useful on its own. It is also the VM engine under two other Zyvor products, which add
orchestration and UX on the same REST API rather than forking FluxVM:

| Product | Role |
|---|---|
| **[zyvor-fabric](zyvor-fabric.md)** | Private cloud control plane (CLI/Web/K8s operator/Terraform) — FluxVM runs the VMs, Fabric adds auth/RBAC, network policy and UX |
| **[Ragnarok](ragnarok.md)** | AI-powered KubeVirt-style VM management — creates `DisposableVm` CRs through its FluxVM Hub with OIDC/SSO and RBAC |
| **[h2kvm](https://github.com/zyvorai/h2kvm)** | Hypervisor → KVM convert + import; hands a certified disk to FluxVM to run |
| **[GuestKit](https://github.com/zyvorai/guestkit)** | Offline disk scoring/repair — FluxVM boots and manages what GuestKit certifies |

**Certify with GuestKit → run and manage with FluxVM → convert/deploy with h2kvm.** Neither Fabric nor Ragnarok
is required to use FluxVM directly.

<a id="who-does-what-users"></a>

| You need… | Use |
|-----------|-----|
| Score / repair a disk **offline** (doctor, passport, fix plans) | **[GuestKit](https://github.com/zyvorai/guestkit)** |
| **Boot & manage** that qcow2 (network, SSH, TTL, pause/resume, fleets) | **This repo (FluxVM)** |
| Hypervisor → KVM convert + import | **[h2kvm](https://github.com/zyvorai/h2kvm)** |

### Evaluating FluxVM for your team?

FluxVM is Apache-2.0 — free to use, modify and ship commercially. If you are weighing build-vs-adopt for a
host-local VM layer, want a pilot, or need help scoping the [production checklist](PRODUCTION.md) against your
threat model, **[talk to Zyvor](https://zyvor.dev?utm_source=github&utm_medium=fluxvm)**. Fabric and Ragnarok
(separate products with their own licensing) are the managed-experience path when you outgrow a CLI and an API.
