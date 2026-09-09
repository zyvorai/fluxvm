# FluxVM — User Documentation

A standalone, minimal-dependency disposable-VM control plane — QEMU/KVM, Cloud Hypervisor, and Firecracker behind one API.

| You want to… | Open |
|--------------|------|
| Install and boot your first VM | [Getting Started](getting-started.md) |
| Day-to-day recipes | [Workflows](workflows.md) |
| Production readiness (`/readyz`, tenant) | [PRODUCTION.md](../PRODUCTION.md) · [tutorials](../tutorials/production/README.md) |
| Configure backends, storage, auth | [Configuration](configuration.md) |
| Deploy, systemd, ports | [Admin basics](admin-basics.md) |
| CLI & REST map | [Using the CLI & API](using-the-dashboard.md) |
| Run as a Kubernetes DaemonSet | [Kubernetes deployment](kubernetes-deployment.md) |
| Use with Ragnarok (UI + SSO) | [Ragnarok integration](ragnarok-integration.md) |
| Build a custom OS image | [Building custom OS images](build-image-tutorial.md) · [Windows Kryton goldens](../windows-golden.md) |
| Network Fabric policy labs | [network-policy tutorials](../tutorials/network-policy/README.md) |
| Service Fabric Maglev VIP | [service-fabric tutorial](../tutorials/service-fabric/README.md) · [operator](../service-fabric.md) |
| MicroVM CRDs | [microvm tutorials](../tutorials/microvm/README.md) |
| Secure Containers (containerd RuntimeClass, preview; Set 3) | [secure-containers.md](../secure-containers.md) · [Set 3](../secure-containers-set3.md) |
| See what it's actually used for | [Use cases](use-cases.md) |
| Full topic index | [PAGE_INDEX.md](PAGE_INDEX.md) |

## Printable PDFs

```bash
node scripts/user-docs/build-user-pdfs.mjs
```

Output lands in [`pdf/`](pdf/):

- `FluxVM-User-README.pdf`
- `FluxVM-Getting-Started.pdf`
- `FluxVM-Page-by-Page.pdf`
- `FluxVM-Admin-Basics.pdf`

Also available: [using the CLI & API](using-the-dashboard.md).

**→ Product page:** https://zyvor.dev/fluxvm · **GitHub:** https://github.com/zyvorai/fluxvm
