<div align="center">

<img src="docs/social/fluxvm-hero-dark.jpg" alt="FluxVM - Run real VMs. With a real API." width="100%">

# FluxVM

### Run real VMs with a real API.

One Rust control plane for Firecracker, Cloud Hypervisor, QEMU/KVM and the in-tree FluxVM hypervisor.<br>
No libvirtd. No XML. A REST API and a CLI that do the same thing on every backend.

[![CI](https://img.shields.io/github/actions/workflow/status/zyvorai/zyvor-fluxvm/ci.yml?branch=main&style=flat-square&labelColor=1d1d1f&label=CI)](https://github.com/zyvorai/zyvor-fluxvm/actions/workflows/ci.yml)
[![Security profiles](https://img.shields.io/github/actions/workflow/status/zyvorai/zyvor-fluxvm/security-profiles.yml?branch=main&style=flat-square&labelColor=1d1d1f&label=security%20profiles)](https://github.com/zyvorai/zyvor-fluxvm/actions/workflows/security-profiles.yml)
[![DevOps gates](https://img.shields.io/github/actions/workflow/status/zyvorai/zyvor-fluxvm/devops-gates.yml?branch=main&style=flat-square&labelColor=1d1d1f&label=devops%20gates)](https://github.com/zyvorai/zyvor-fluxvm/actions/workflows/devops-gates.yml)
[![License: Apache-2.0](https://img.shields.io/github/license/zyvorai/zyvor-fluxvm?style=flat-square&color=0071e3&labelColor=1d1d1f)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/zyvorai/zyvor-fluxvm/main?style=flat-square&color=0071e3&labelColor=1d1d1f)](https://github.com/zyvorai/zyvor-fluxvm/commits/main)
[![Rust: stable](https://img.shields.io/badge/rust-stable-0071e3?style=flat-square&labelColor=1d1d1f&logo=rust&logoColor=white)](https://www.rust-lang.org)

[**Quick start**](#quick-start) · [**Proof**](#maturity-whats-real-today) · [**Docs**](docs/index.md) · [**API**](docs/api.md) · [**Talk to Zyvor**](https://zyvor.dev/?utm_source=github&utm_medium=fluxvm&utm_campaign=readme_hero)

[![Book a demo](https://img.shields.io/badge/Book_a_demo-0071e3?style=for-the-badge)](https://zyvor.dev/schedule?utm_source=github&utm_medium=fluxvm&utm_campaign=readme_hero)
[![30-day PoC](https://img.shields.io/badge/30--day_PoC-1d1d1f?style=for-the-badge)](https://zyvor.dev/poc?utm_source=github&utm_medium=fluxvm&utm_campaign=readme_hero)

</div>

---

## One API. Every hypervisor.

A JSON spec in, a running VM out. The same `fluxctl` verbs and the same REST API on every backend, with a vsock guest agent instead of SSH.

```bash
sudo fluxctl create --spec examples/qemu.json     # boot a VM from a JSON spec
fluxctl list                                      # every VM, every backend
fluxctl exec <id> -- hostname                     # run a command over vsock — no SSH
fluxctl pause <id> && fluxctl resume <id>         # park it instead of rebuilding it
fluxctl delete <id>                               # or set ttl_seconds and walk away
```

<table>
<tr>
<td valign="top" width="33%">
<b>Four backends</b><br>
QEMU/KVM, Cloud Hypervisor, Firecracker and the in-tree FluxVM hypervisor behind one trait. <code>"backend":"auto"</code> picks for you.<br>
<a href="docs/vs-libvirt.md#backends">Backends</a>
</td>
<td valign="top" width="33%">
<b>Native KVM, no QEMU</b><br>
A pure in-tree KVM engine: SMP verified at 2, 4 and 8 vCPUs, pause and snapshot across every vCPU, and a golden Cloud-init template.<br>
<a href="docs/native-kvm-no-qemu.md">Native KVM</a>
</td>
<td valign="top" width="33%">
<b>Agent sandboxes</b><br>
An egress ACL on method, host and path (HTTPS via opt-in interception), a file change-set, a rootless procbox tier, GPUs for QEMU sandboxes (`gpus: N`), and Python, Go and TypeScript SDKs.<br>
<a href="docs/agent-sandbox-gaps.md">Agent sandboxes</a>
</td>
</tr>
<tr>
<td valign="top" width="33%">
<b>Network Fabric <sub>GA</sub></b><br>
A TC/eBPF VM-edge dataplane with L3/L4 policy, rate limits, security groups and live reconfigure. nftables stays the default.<br>
<a href="docs/network-fabric.md">Network Fabric</a>
</td>
<td valign="top" width="33%">
<b>Secure Containers <sub>GA</sub></b><br>
A Pod gets its own guest kernel through containerd runtime-v2, with Sentinel NetworkPolicy. Not a Kata-equivalence claim.<br>
<a href="docs/secure-containers.md">Secure Containers</a>
</td>
<td valign="top" width="33%">
<b>Kubernetes</b><br>
A <code>DisposableVm</code> CRD and a node-local operator, verified on a real k3s cluster, plus a scheduler-native path without KubeVirt.<br>
<a href="docs/kubernetes-operator.md">Operator</a>
</td>
</tr>
</table>

---

<a id="maturity-whats-real-today"></a>

## Proof, not promises

We only claim what has been run. Every line links to how it was verified.

- **Kubernetes operator:** 9/9 checks on a real k3s cluster, including self-healing and no leaked QEMU. [Details](docs/proof-and-status.md)
- **Multi-host fleet:** a central registry with load-aware placement across two physically separate hosts. [Details](docs/proof-and-status.md)
- **Storage and networking:** qcow2/raw, LVM thin, NBD and Ceph RBD (against a real Rook cluster); NAT, TAP+bridge, netns+DHCP and macvtap, SSH-verified end to end. [Details](docs/proof-and-status.md)
- **Bridge-less direct datapath:** measured −31% latency and +60% 64 B packet rate in the Pod case, on a veth stand-in with no real guest. [Method and data](docs/direct-datapath.md#-measured-forwarding-cost)
- **Native KVM:** 2, 4 and 8-vCPU guests boot, pause and snapshot across every vCPU, and a real `fluxctl create` passes the agent and NoCloud gate. [Details](docs/native-kvm-no-qemu.md)
- **The boundaries, up front:** multi-tenant controls are opt-in, not a public-cloud boundary, and boot numbers are a method, not a sizing SLA. [Read them](docs/proof-and-status.md)

---

## Quick start

```bash
git clone https://github.com/zyvorai/zyvor-fluxvm.git && cd fluxvm   # needs a sibling guestkit checkout
sudo ./scripts/bootstrap-host.sh vmbr0 && ./scripts/preflight.sh
cargo build --release
sudo install -m 0755 target/release/fluxctl /usr/local/bin/fluxctl
sudo install -m 0644 config.example.toml /etc/fluxvm.toml
sudo fluxctl --config /etc/fluxvm.toml create --spec examples/qemu.json
```

Day-2 verbs, network modes and remote daemons: [Getting started](docs/getting-started.md).

<a id="vs-libvirtvirsh"></a>

## vs. libvirt/virsh

FluxVM is the Zyvor **host-local** replacement for libvirt/virsh VM lifecycle and networking. It is **not** a drop-in for KubeVirt/OpenShift.

| libvirt/virsh | FluxVM |
|---|---|
| `virsh define` + `virsh start` | `fluxctl create` |
| `virsh list` / `virsh suspend` / `virsh resume` | `fluxctl list` / `pause` / `resume` |
| `virsh console` | `fluxctl serial` (websocket over REST too) |
| XML domain definitions | A JSON VM spec (`fluxctl create --spec vm.json`) |
| No REST API | A full REST API (`fluxctl serve`) |

The [full command mapping](docs/vs-libvirt.md) covers disks, snapshots, backups, clone and events.

<a id="use-cases"></a>

## Use cases

Every one maps onto what is implemented today. [All eleven](docs/index.md#use-cases) and [docs/use-cases.md](docs/use-cases.md).

- **CI runners that isolate every job:** a VM per job over vsock `exec`, with `ttl_seconds` cleanup.
- **AI-agent sandboxes with guard rails:** a microVM or a rootless procbox, an egress ACL and a change-set.
- **Linux VMs with no QEMU installed:** the in-tree KVM engine and a golden template, `fluxctl vm-template create native-agent <name>`.
- **A golden-image pipeline:** build once with `fluxctl build-image`, reuse through CoW overlays and a signed catalog.
- **Kubernetes-native VMs without KubeVirt** and **OCI workloads with a per-Pod guest kernel.**

## Documentation map

| Topic | Doc |
|---|---|
| Every feature area and document | [docs/index.md](docs/index.md) |
| Positioning, overview and the exhaustive feature list | [docs/POSITIONING.md](docs/POSITIONING.md) · [docs/PRODUCT_OVERVIEW.md](docs/PRODUCT_OVERVIEW.md) · [FEATURES.md](FEATURES.md) |
| REST API, auth/RBAC and the VM JSON contract | [docs/api.md](docs/api.md) |
| Day-2 operations | [docs/operations.md](docs/operations.md) |
| Native KVM, no QEMU | [docs/native-kvm-no-qemu.md](docs/native-kvm-no-qemu.md) |
| Agent sandboxes, procbox and the SDKs | [docs/agent-sandbox-gaps.md](docs/agent-sandbox-gaps.md) · [python/](python/README.md) · [go/](go/README.md) · [typescript/](typescript/README.md) |
| Network Fabric and Service Fabric | [docs/network-fabric.md](docs/network-fabric.md) · [docs/service-fabric.md](docs/service-fabric.md) |
| Secure Containers and MicroVM | [docs/secure-containers.md](docs/secure-containers.md) · [docs/microvm.md](docs/microvm.md) |
| Production checklist and DevOps gates | [docs/PRODUCTION.md](docs/PRODUCTION.md) · [docs/DEVOPS.md](docs/DEVOPS.md) |
| Architecture, FAQ and ecosystem | [docs/architecture.md](docs/architecture.md) · [docs/faq.md](docs/faq.md) · [docs/ecosystem.md](docs/ecosystem.md) |
| Ranked backlog | [docs/NEXT-FEATURES.md](docs/NEXT-FEATURES.md) |

## Go deeper

- <a id="architecture-at-a-glance"></a>**Architecture:** the control plane, the four backends and the image path — [docs/architecture.md](docs/architecture.md).
- <a id="feature-highlights"></a>**Feature highlights:** every area in one table, with its docs — [docs/index.md](docs/index.md#feature-highlights).
- <a id="kubernetes-crdoperator"></a>**Kubernetes:** `DisposableVm` and the node-local operator — [docs/kubernetes-operator.md](docs/kubernetes-operator.md).
- <a id="faq"></a>**FAQ:** is it for you, and the questions people ask first — [docs/faq.md](docs/faq.md).
- <a id="ecosystem"></a><a id="who-does-what-users"></a>**Ecosystem:** how FluxVM relates to zyvor-fabric, Ragnarok, h2kvm and GuestKit — [docs/ecosystem.md](docs/ecosystem.md).
- <a id="using-fluxvm-through-ragnarok"></a>**Using FluxVM through Ragnarok:** [docs/ragnarok.md](docs/ragnarok.md), and [zyvor-fabric](docs/zyvor-fabric.md) for the private-cloud control plane.

## Contributing & community

- **Contributing:** build and test commands, PR expectations and repo layout, in [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security:** the current hardening bar and how to report a vulnerability, in [SECURITY.md](SECURITY.md).
- **Changelog:** [CHANGELOG.md](CHANGELOG.md).

## License

Commercial subscriptions and support: see [docs/SUBSCRIPTION-MODEL.md](docs/SUBSCRIPTION-MODEL.md).

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Zyvor AI Labs. The entire repository is under this one license; there is no dual-licensing or separately-licensed core component.

<div align="center">

Part of the Zyvor platform ([Ecosystem](docs/ecosystem.md)). More at **[zyvor.dev](https://zyvor.dev/?utm_source=github&utm_medium=fluxvm&utm_campaign=readme_footer)**.

[Book a demo](https://zyvor.dev/schedule?utm_source=github&utm_medium=fluxvm&utm_campaign=readme_footer) · [30-day PoC](https://zyvor.dev/poc?utm_source=github&utm_medium=fluxvm&utm_campaign=readme_footer) · fallback: [sales@zyvor.dev](mailto:sales@zyvor.dev)

</div>
