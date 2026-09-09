# Use cases

FluxVM is a disposable-VM control plane: create a short-lived, isolated
virtual machine backed by QEMU/KVM, Cloud Hypervisor, or Firecracker, use it,
and let a TTL reaper clean it up. This doc walks through the use cases that
map directly onto what's actually implemented (see the main
[README](../README.md#what-is-implemented) for the full feature list) —
nothing here is aspirational.

## FluxVMl CI/CD build and test runners

Spin up a real VM per job, run the job inside it over vsock `exec` (no SSH,
no network path needed at all), and let `ttl_seconds` guarantee cleanup even
if the job crashes or the runner disappears mid-job.

```bash
cat > ci-job.json <<'JSON'
{
  "name": "ci-job-4821",
  "backend": "firecracker",
  "image": "/var/lib/fluxvm/images/ci-runner.raw",
  "vcpus": 2,
  "memory_mib": 2048,
  "network": {"mode": "none"},
  "ttl_seconds": 900,
  "agent": {"enabled": true, "port": 5000}
}
JSON

id=$(fluxvm create --spec ci-job.json | jq -r .id)
fluxvm exec "$id" -- ./run-tests.sh
```

Firecracker's jailer (chroot + uid/gid drop, see "Firecracker jailer" in the
README) gives each job its own privilege-dropped sandbox, and cgroup v2
resource control caps what a single job can consume on a shared runner host.
`network.mode: "none"` plus vsock `exec` means a compromised or malicious
test suite has no network path out at all — the same isolation shape as
gVisor/Firecracker-based CI sandboxes, built on this project's own control
plane instead of a hosted service.

## Golden-image pipeline

Build a customized, versioned base image once — package installs, hostname,
SSH keys, a baked-in agent binary — and reuse it across every VM you create
from it, instead of provisioning each VM from scratch at boot time.

```bash
cat > golden-image.json <<'JSON'
{
  "source": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
  "sha256": "...",
  "output": "/var/lib/fluxvm/images/team-golden-v12.qcow2",
  "packages": ["docker.io", "jq", "qemu-guest-agent"],
  "commands": ["systemctl enable docker"],
  "enable_services": ["qemu-guest-agent"]
}
JSON

sudo fluxvm build-image --spec golden-image.json
```

See [`docs/build-image-tutorials.md`](build-image-tutorials.md) for the same
walkthrough across Debian/Ubuntu, RHEL-family, Arch, and Windows
(`windows{}` + Zyvor GuestKit agent) base images. Pair it
with the image catalog (SHA-256 + optional Ed25519 signing, see "Image
catalog & signing" in the README) to give every VM a provenance guarantee —
`allowed_image_dirs` and `trusted_signers` mean a tenant can reference an
image by name and have the daemon refuse anything that isn't a known,
signed entry.

## Kubernetes-native disposable workloads

For teams already running Kubernetes who want a real VM (not a container)
for a specific workload — untrusted code, a kernel-dependent test, a legacy
binary — the `DisposableVm` CRD plus the node-local `fluxvm-kube` operator
lets a VM be requested the same way any other Kubernetes resource is.

**Product path:** [Ragnarok](https://zyvor.dev/docs/ragnarok) creates those CRs from its
FluxVM Hub (with OIDC/SSO and RBAC). Install FluxVM first, then Ragnarok — see
[docs/ragnarok.md](ragnarok.md).


```yaml
apiVersion: fluxvm.zyvor.io/v1
kind: DisposableVm
metadata:
  name: untrusted-job-7
spec:
  node: worker-3
  backend: firecracker
  image: /var/lib/fluxvm/images/sandbox.raw
  vcpus: 1
  memoryMib: 1024
  networkMode: none
  ttlSeconds: 600
```

`kubectl delete disposablevm` blocks on a finalizer until the real VM is
actually gone (no leaked QEMU/Firecracker process), and the operator
self-heals — if the underlying VM disappears out-of-band, it gets replaced
automatically without touching the CR. This is verified against a real k3s
cluster, not just unit-tested against a fake API server (see "Kubernetes
CRD/operator" in the README).

## Secure Containers (OCI in a FluxVM)

For workloads that still look like containers to Kubernetes/`ctr`, but need a
**per-Pod guest kernel** instead of sharing the node kernel, FluxVM Secure
Containers maps a containerd task group onto one QEMU FluxVM
(runtime `io.containerd.fluxvm.v2`, RuntimeClass handler `fluxvm`).

Set 2 adds optional CNI L2 (guest gets the real Pod IP when a CRI netns exists)
and guest cgroup-v2 stats/resource updates. Set 3 adds containerd task events and
guest OCI process hardening. This remains a **developer preview**: PVC
write-through and TTY are not production-ready yet. Full design:
[docs/secure-containers.md](secure-containers.md),
[Set 3 notes](secure-containers-set3.md). Deploy fragment:
[`deploy/containerd/`](../deploy/containerd/).

```bash
sudo ./scripts/install-secure-containers.sh
# merge deploy/containerd/fluxvm-runtime.toml into containerd config, then:
ctr run --rm --runtime io.containerd.fluxvm.v2 docker.io/library/busybox:1.36 smoke /bin/echo ok
```

## Multi-host fleets without Kubernetes

Not every team wants a Kubernetes control plane just to spread disposable
VMs across a handful of bare-metal or edge hosts. `fluxvm-agent` is a
lighter-weight alternative: a central fleet registry plus a per-host
heartbeat client, with load-aware placement deciding which host a new VM
request lands on — verified across two real, physically separate hosts.
This fits edge deployments, colo racks, or any fleet where standing up a
full Kubernetes cluster is disproportionate to the actual workload.

## Sandboxed / untrusted code execution

The combination that makes FluxVM suitable for running code you don't
trust:

- **Firecracker jailer** — chroot + uid/gid drop, so even a Firecracker
  process compromise doesn't hand over root on the host.
- **cgroup v2 resource control** — hard caps on CPU/memory/IO per VM.
- **Network namespaces** and `network.mode: "none"` — no network path out of
  the guest at all when the workload doesn't need one.
- **vsock exec** — get output back from the guest without opening any
  network port, SSH included.
- **TTL reaper** — a VM that's forgotten about (crashed harness, orphaned
  job) gets torn down anyway.

This is the same isolation shape used for malware analysis sandboxes, "run
this untrusted PR's code" CI steps, and multi-tenant code-execution products
— built from primitives this project already has, not a separate product.

For how that compares to a full AI-agent sandbox product (tens-of-ms snapshot
boot, egress vault, AutoPause), see
[docs/agent-sandbox-gaps.md](agent-sandbox-gaps.md). The FluxVm backend
(`backend: "flux-vm"`) is the agent-sandbox track: memory snapshots, `/v1/sandboxes`,
guest HTTP proxy with AutoResume, L7 egress, `/console`, and an optional native
TC/eBPF Network Fabric (GA; dataplane schema v4) (nftables default; IPv4/IPv6 L3+L4, rate
limits, security groups / CNP, Cilium coexistence without mutating Cilium
maps — [docs/network-fabric.md](network-fabric.md),
[docs/network-groups.md](network-groups.md),
[docs/network-policy.md](network-policy.md),
[docs/production-dataplane.md](production-dataplane.md),
[docs/ebpf-cilium.md](ebpf-cilium.md)).

## Disposable dev/test environments

Give every branch, PR, or engineer their own real VM — not a shared
staging box — with automatic cleanup via `ttl_seconds` so nothing lingers
past its usefulness. QEMU's qcow2 copy-on-write overlays mean spinning up a
new VM from a golden image is cheap (no full disk copy), and `pause`/`resume`
let you park an environment instead of destroying and rebuilding it if
someone steps away mid-session.

## Bring-your-own storage backend

Beyond the default qcow2/raw overlay, FluxVM supports LVM thin snapshots,
NBD-exported disks, and Ceph RBD as storage backends for VM disks — Ceph RBD
verified against a real Rook Ceph cluster. This matters if you're deploying
into infrastructure that already standardized on one of these (a SAN
exposed over NBD, an existing Ceph cluster, LVM thin pools on local NVMe)
instead of adopting a new storage layer just for VM disks.

## Networking that matches the environment, not a fixed default

- **QEMU user-mode NAT** — zero host config, good for a single dev machine.
- **TAP + Linux bridge** — a VM on the same L2 as the host, for lab/test
  networks that need real bridged connectivity.
- **macvtap** — a VM's own MAC address directly on a parent link (no
  bridge), for environments where the VM needs to look like an independent
  host on the physical network.

All three are SSH-verified end-to-end in this project's own regression
tests, not just configured-and-hoped-for.
