# Use Cases

## Purpose

Concrete scenarios — CI runners, golden images, fleets, sandboxes.

## How to get there

- Topic id: `use-cases`
- Section: **Onboarding → Use Cases**

## Guide

FluxVM is a disposable-VM control plane: create a short-lived, isolated
virtual machine backed by QEMU/KVM, Cloud Hypervisor, or Firecracker, use
it, and let a TTL reaper clean it up. Every use case below maps directly
onto what's implemented today — see the
[technical docs](/docs/fluxvm) or the project's
[README](https://github.com/zyvorai/fluxvm#what-is-implemented) for the
full feature list.

## FluxVMl CI/CD build and test runners

Spin up a real VM per job, run the job inside it over vsock `exec` (no SSH,
no network path needed at all), and let `ttl_seconds` guarantee cleanup
even if the job crashes or the runner disappears mid-job.

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

Firecracker's jailer (chroot + uid/gid drop) gives each job its own
privilege-dropped sandbox, and cgroup v2 resource control caps what a
single job can consume on a shared runner host. `network.mode: "none"` plus
vsock `exec` means a compromised or malicious test suite has no network
path out at all.

## Golden-image pipeline

Build a customized, versioned base image once — package installs,
hostname, SSH keys, a baked-in agent binary — and reuse it across every VM
you create from it, instead of provisioning each VM from scratch at boot
time. See [Building custom OS images](../images/build-image-tutorial.md) for the full
walkthrough across Debian/Ubuntu, RHEL-family, Arch, and Windows (`windows{}`
+ Zyvor GuestKit agent).

Pair it with the image catalog (SHA-256 + optional Ed25519 signing) to give
every VM a provenance guarantee — a tenant references an image by name, and
the daemon refuses anything that isn't a known, signed entry.

## Kubernetes-native disposable workloads

For teams already running Kubernetes who want a real VM (not a container)
for a specific workload — untrusted code, a kernel-dependent test, a legacy
binary — the `DisposableVm` CRD plus the node-local `fluxvm-kube`
operator lets a VM be requested the same way any other Kubernetes resource
is:

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
actually gone, and the operator self-heals — if the underlying VM
disappears out-of-band, it gets replaced automatically without touching the
CR. Verified against a real k3s cluster.

## Multi-host fleets without Kubernetes

Not every team wants a Kubernetes control plane just to spread disposable
VMs across a handful of bare-metal or edge hosts. `fluxvm-agent` is a
lighter-weight alternative: a central fleet registry plus a per-host
heartbeat client, with load-aware placement deciding which host a new VM
request lands on — verified across two real, physically separate hosts.
This fits edge deployments, colo racks, or any fleet where standing up a
full Kubernetes cluster is disproportionate to the workload.

## Sandboxed / untrusted code execution

The combination that makes FluxVM suitable for running code you don't
trust:

- **Firecracker jailer** — chroot + uid/gid drop, so even a process
  compromise doesn't hand over root on the host.
- **cgroup v2 resource control** — hard caps on CPU/memory/IO per VM.
- **Network namespaces** and `network.mode: "none"` — no network path out
  of the guest when the workload doesn't need one.
- **vsock exec** — get output back from the guest without opening any
  network port, SSH included.
- **TTL reaper** — a VM that's forgotten about gets torn down anyway.

This is the same isolation shape used for malware-analysis sandboxes and
"run this untrusted PR's code" CI steps, built from primitives this project
already has. For the FluxVm agent-sandbox track (snapshots, `/v1/sandboxes`,
egress, AutoPause, optional TC/eBPF Network Fabric v3 dataplane), see
[AI-agent sandbox gaps](../../../agent-sandbox-gaps.md),
[Network Fabric](../../../network-fabric.md), and
[eBPF / Cilium](../../../ebpf-cilium.md).

## Disposable dev/test environments

Give every branch, PR, or engineer their own real VM — not a shared
staging box — with automatic cleanup via `ttl_seconds`. QEMU's qcow2
copy-on-write overlays mean spinning up a new VM from a golden image is
cheap (no full disk copy), and `pause`/`resume` let you park an environment
instead of destroying and rebuilding it.

## Bring-your-own storage backend

Beyond the default qcow2/raw overlay, FluxVM supports LVM thin
snapshots, NBD-exported disks, and Ceph RBD as storage backends — Ceph RBD
verified against a real Rook Ceph cluster. This matters if you're deploying
into infrastructure that already standardized on one of these instead of
adopting a new storage layer just for VM disks.

## Networking that matches the environment

- **QEMU user-mode NAT** — zero host config, good for a single dev machine.
- **TAP + Linux bridge** — a VM on the same L2 as the host.
- **macvtap** — a VM's own MAC address directly on a parent link (no
  bridge).

All three are SSH-verified end-to-end in the project's own regression
tests.

## Next steps

- [Getting started](getting-started.md)
- [Building custom OS images](../images/build-image-tutorial.md)
- [Common workflows](../operations/workflows.md)

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

## Related pages

- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
