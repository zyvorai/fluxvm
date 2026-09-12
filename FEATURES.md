# FluxVM Feature Reference

Exhaustive checklist. For the pitch, see [README.md](README.md); for who this is for, see [docs/POSITIONING.md](docs/POSITIONING.md); for the capability tour and metrics, see [docs/PRODUCT_OVERVIEW.md](docs/PRODUCT_OVERVIEW.md); for concrete scenarios, see [docs/use-cases.md](docs/use-cases.md).

## Project Statistics

- 23 crates (`ls crates/`)
- 4 VMM backends (QEMU/KVM, Cloud Hypervisor, Firecracker, in-tree FluxVM hypervisor)
- 4 storage backends (qcow2/raw default, LVM thin, NBD, Ceph RBD)
- 4 network modes (user-mode NAT, TAP+bridge, netns+DHCP, macvtap)
- 1 REST API (`fluxvm serve`), 1 CLI (`fluxvm`)
- Kubernetes: 2 CRD paths (`DisposableVm` via `fluxvm-kube`, MicroVM via `fluxvm-microvm`)

---

## VM Lifecycle

- Create, list, get, pause, resume, delete across all 4 backends
- `"backend":"auto"` resolution (picks a backend based on spec/host capability)
- `ttl_seconds` — guaranteed cleanup of a VM even if the creating job crashes or disappears
- vsock guest agent: `exec`, PTY console, file transfer — no SSH or network path required
- qcow2 copy-on-write overlays for cheap disposable clones from a golden image
- Direct-kernel or firmware boot (Cloud Hypervisor)

## Backends

- **QEMU/KVM** — broad guest/device compatibility, qcow2 CoW overlays, QMP socket
- **Cloud Hypervisor** — Rust VMM, direct-kernel or firmware boot
- **Firecracker** — microVM backend, Linux kernel + raw root filesystem, includes the **Firecracker jailer** (chroot + uid/gid isolation, see [docs/operations.md](docs/operations.md#firecracker-jailer-chroot-uidgid-isolation-cgroups))
- **FluxVM hypervisor** (`backend: "flux-vm"`, binary `fluxvm-hypervisor`) — agent-sandbox track: memory snapshots, `/v1/sandboxes`, guest HTTP proxy + AutoResume, L7 egress, AutoPause, `/console`

## Networking

- QEMU user-mode NAT (SLIRP) — zero host config
- TAP + Linux bridge — VM on the host's L2
- Per-VM network namespace + dnsmasq DHCP (known `guest_ip`)
- macvtap — VM's own MAC directly on a parent link
- All 4 modes SSH-verified end to end in this project's own regression tests

### Network Fabric (GA, schema v4)

- TC/eBPF VM-edge dataplane, or Cilium-coexistence mode (never mutates Cilium's own maps)
- IPv4/IPv6 dual-stack L3+L4 policy
- Per-VM rate limits (Mbps/PPS)
- Security groups / CNP (Cloud Network Policy)
- Live policy reconfigure without VM restart
- REST observability: status, policy, stats, flows
- nftables is the default fallback when eBPF mode isn't enabled
- Per-VM eBPF rule cap: 64 (kernel BPF verifier limit)

### Service Fabric

- Node-local Maglev VIP load balancing
- Dual-stack NAT/DSR/SNAT
- Health-aware routing
- Incremental reconcile
- Per-service EDT (Earliest Departure Time pacing)
- Flow export

## Images

- `build-image` — virt-builder-style pipeline, guestkit-based (never libguestfs)
- Per-distro package install (Debian/Ubuntu, RHEL-family, Arch, Windows via GuestKit agent)
- SHA-256 verification on every source image
- Ed25519-signed image catalog with REST CRUD (`allowed_image_dirs`, `trusted_signers`)
- Windows/Kryton golden-image customization with live QGA

## Operations

- **cgroup v2 resource control** — CPU/memory/IO limits, freeze/thaw, PSI (pressure stall information)
- **Warm VM pools** — pre-started VMs for lower cold-start latency
- **Firecracker jailer** — chroot + uid/gid drop per VM
- **Admission policy limits** — caps on what a request is allowed to provision
- **Bearer-token auth/RBAC** — on the REST API
- **State layout** — durable per-VM state under a documented path structure, see [docs/operations.md — State layout](docs/operations.md#state-layout)

## Storage

- **Default**: qcow2 (CoW overlays), raw
- **LVM thin** — thin-provisioned snapshots
- **NBD** — network block device-exported disks
- **Ceph RBD** — verified against a real Rook Ceph cluster

## Kubernetes & Fleet

### `DisposableVm` CRD (`fluxvm-kube`)

- Node-local operator, one instance per node, reconciles only CRs whose `spec.node` matches
- Verified end to end against a real k3s cluster — 9/9 checks passing (CRD acceptance; `fluxvm serve` reachability; operator running; CR reconciles to a real running VM with live PID; out-of-band VM delete triggers self-healing replacement; CR delete blocks on finalizer until the real VM is actually gone with no leaked QEMU process — see [`scripts/test-kube-operator.sh`](scripts/test-kube-operator.sh))
- Declarative, not one-shot — a TTL-expired or externally-deleted VM gets replaced automatically on next reconcile, `Deployment`-style semantics
- `spec.networkMode`: `none` / `user` / `tap` / `macvtap`
- Placement: explicit `spec.node`, or `fluxvm-kube --enable-placement` to pin to the least-loaded capable node

### MicroVM (`fluxvm-microvm`)

- Scheduler-native alternative — kube-scheduler places a shadow Pod (capacity ticket only), VMM still runs on the host under `fluxvm serve`
- `MicroVMJob`, `MicroVMPool` CRs for job/pool patterns
- Not KubeVirt — no live migration, CDI, or `virtctl`; see [docs/microvm.md](docs/microvm.md#vs-disposablevm-and-kubevirt) for the full comparison table against `DisposableVm` and KubeVirt

### `fluxvm-agent` (multi-host fleet, no Kubernetes)

- Central fleet registry + per-host heartbeat client
- Load-aware placement across hosts
- Verified across two real, physically separate hosts

## Secure Containers (developer preview — not production-ready)

- Containerd runtime-v2 shim `containerd-shim-fluxvm-v2`, RuntimeClass handler `fluxvm`
- Maps a Pod/task group onto one QEMU FluxVM (`io.containerd.fluxvm.v2`)
- CNI L2 — guest gets the real Pod IP when a CRI netns exists
- Guest cgroup-v2 stats and resource updates
- Containerd task events, guest OCI process hardening
- Pod-UID write-through volumes, guest RO/masked paths/devices/sysctls/libseccomp
- VSOCK stdio streaming, real guest PTY / `ResizePty`
- Guest AppArmor/SELinux/seccomp enforcement
- **Known gaps before "production-ready" or "Kata-equivalent"**: `hostPath` hotplug, broader CNI/OCI conformance — see [docs/secure-containers.md](docs/secure-containers.md) and [docs/PRODUCTION.md](docs/PRODUCTION.md)

## Sentinel Observability

- eBPF-based host + guest runtime intelligence
- Per-VM syscall/page-fault telemetry
- Drop-reason tracking
- Flight recorder
- BPF-LSM VMM guard/QoS
- XDP shield
- Topology steering
- Implemented in the `fluxvm-intelligence` crate — see [docs/runtime-intelligence.md](docs/runtime-intelligence.md), [docs/flight-recorder.md](docs/flight-recorder.md)

## Security Posture (what's implemented vs. what's still open)

This mirrors the [maturity caveat](README.md#maturity-whats-real-today) in the README rather than contradicting it — read both together.

| Implemented today | Still open before untrusted multi-tenant use |
|---|---|
| Firecracker jailer (chroot + uid/gid isolation) | seccomp/AppArmor/SELinux policy beyond what Secure Containers guests get |
| cgroup v2 resource control | Stronger resource quotas at the admission-policy layer |
| Per-VM network namespaces | — |
| Bearer-token auth/RBAC on the REST API | Audit logging |
| SHA-256 verification + Ed25519-signed image catalog | Stronger image provenance beyond catalog signing |
| `network.mode: "none"` for zero network path out of a guest | — |

## Build and Development

- Cargo workspace, 23 crates, current stable Rust toolchain
- `scripts/bootstrap-host.sh` — one-time host prep (packages, Cloud Hypervisor, Firecracker, a bridge)
- `scripts/preflight.sh` — confirm every required tool is on `PATH`
- `scripts/test-networking.sh`, `scripts/test-lifecycle.sh` — end-to-end verification scripts
- `scripts/test-kube-operator.sh` — the 9-check k3s CRD/operator verification
- GitHub Actions CI + a separate DevOps-gates workflow
- Depends on sibling [`guestkit`](https://github.com/zyvorai/guestkit) checkout for `fluxvm-image` (offline image customization, no libguestfs)

## Deployment

- Single binary + config file (`config.example.toml` → `/etc/fluxvm.toml`)
- Remote host deploy — see [docs/operations.md — Deploy to a remote host](docs/operations.md#deploy-to-a-remote-host)
- Kubernetes manifests under [`deploy/k8s/`](deploy/k8s/) (Dockerfile + CRD/RBAC/DaemonSet)
- Containerd RuntimeClass deploy fragments under [`deploy/containerd/`](deploy/containerd/) (Secure Containers path)

## License

Apache License 2.0, entire repository, no dual licensing. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
