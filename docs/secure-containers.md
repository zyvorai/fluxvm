# FluxVM Secure Containers — containerd runtime v2

FluxVM Secure Containers is the first container-runtime layer on top of the
existing FluxVM VM lifecycle, VSOCK guest agent and QEMU virtiofs support.
The goal is the same security shape users expect from Kata Containers: a Pod
or container group gets its own guest kernel instead of sharing the node's
host kernel — plus, starting with Set 6, **FluxVM Sentinel**: an eBPF-based
policy substrate spanning the host VMM edge and (in later Sets) the guest
kernel with one shared schema and identity model, which Kata's namespace +
seccomp + static-policy-file model does not attempt.

## Architecture

```text
Kubernetes / ctr
      |
 containerd CRI
      |
containerd-shim-fluxvm-v2
      |
      +---- (optional) CNI L2 bridge prep on Pod netns
      +---- FluxVM REST API ----> QEMU/KVM microVM
      |                              |
      |                              +-- virtiofs Pod share (+ Pod-UID volumes)
      |                              +-- TAP on host CNI bridge (when netns present)
      |                              +-- fluxvm-guest-agent :17777
      |                              +-- fluxvm-container-agent :17778 (lifecycle)
      |                              +-- stdio streams :17779 (TTY/pipes)
      |                                         |
      +---------------- VSOCK ------------------+
                                                |
                                      OCI processes + guest cgroup v2
```

The shim groups tasks using the same annotations containerd uses for a
Kubernetes Pod (`io.containerd.runc.v2.group` first, then
`io.kubernetes.cri.sandbox-id`). The first task creates one QEMU FluxVM with a
Pod-scoped virtiofs directory. Later tasks in the group reuse the same VM.

## Why a separate container agent?

FluxVM's existing `fluxvm-guest-agent` is a stable VM-management interface for
ping, command execution, file transfer, console and shutdown. Secure
Containers does not expand that stable protocol. Instead the shim uploads a
small `fluxvm-container-agent` into the guest through the existing authenticated
agent, launches it on VSOCK port 17778, and uses a dedicated lifecycle protocol.

That makes the feature removable and independently versionable while reusing
the VM's existing per-instance authentication token.

## Implemented through Set 10

- containerd runtime-v2 binary: `containerd-shim-fluxvm-v2`
- one Kubernetes Pod/containerd shim group -> one FluxVM QEMU VM
- CNI L2 Pod IP/MAC handoff into the guest
- Pod/sandbox and per-container guest cgroup-v2 limits, stats, pids and updates
- containerd task events + asynchronous exit publication
- OCI create/start/state/wait/kill/pause/resume/delete and exec lifecycle
- uid/gid, supplementary groups, cwd, argv, PATH, environment, umask and rlimits
- Linux capability sets, noNewPrivileges, seccomp syscall + argument-comparator rules
- read-only rootfs, masked/read-only paths, device nodes and Pod-VM sysctls
- containerd snapshot rootfs staging into the VM-visible virtiofs share
- Pod-UID-scoped write-through Kubernetes `volumes` / `volume-subpaths`
- authenticated VSOCK lifecycle RPC on port 17778
- authenticated raw stdin/stdout/stderr streaming on port 17779
- real guest PTY for terminal init/exec processes
- containerd `ResizePty` and `CloseIO` forwarding
- legacy regular-file virtiofs stdio fallback for non-TTY debugging
- RuntimeClass/containerd examples, source/unit gates and KVM smoke scripts
- per-container PID/mount/IPC/UTS namespace isolation (`pivot_root`, not
  `chroot`); containers in a Pod no longer rely on the VM boundary alone
- sandbox/pause-container convention: the CRI sandbox container's IPC/UTS
  (and PID, when `shareProcessNamespace: true`) are joined by sibling
  containers, matching runc/Kata's "join the pause container" model
- opt-in `CLONE_NEWUSER` per container (`FLUXVM_CONTAINER_USERNS=1`, off by
  default) for an additional capability-scoping boundary
- **Sentinel**: identity-aware, Kubernetes-NetworkPolicy-*shaped* Pod network
  policy on the VM edge (`bpf/fluxvm_pod_policy.bpf.h`, additive on top of the
  existing CIDR/L4 dataplane), with a stable per-Pod identity and an
  independent policy-content API (`/v1/vms/{id}/network/pod-policy`) — see
  [docs/secure-containers-set6s.md](secure-containers-set6s.md). Populating
  it automatically from live Kubernetes `NetworkPolicy` objects is not yet
  implemented (needs a selector-resolving watcher/controller).
- restart-safe runtime ownership journal and IPv4/IPv6 dual-stack CNI replay
  on the primary interface — see
  [docs/secure-containers-set6.md](secure-containers-set6.md)
- **Sentinel**: per-VM QEMU process hardening — a `BPF_CGROUP_DEVICE`
  allowlist (only `/dev/kvm`/`/dev/vhost-vsock`/`/dev/net/tun`/configured
  VFIO devices) and a `cgroup_skb` egress filter (loopback-only outbound IP)
  on the same `fluxvm.slice/{id}.scope` cgroup every VM already gets — see
  [docs/secure-containers-set7s.md](secure-containers-set7s.md). Applies to
  every VM, not only Secure Containers Pods.
- containerd `TaskOOM` publication from guest cgroup-v2 `memory.events`, CPU
  throttling + detailed memory/swap/fault task metrics, OCI memory
  reservation/swap translation, allowlisted cgroup-v2 `unified` updates, and
  fail-closed raw block/special-device handling — see
  [docs/secure-containers-set7.md](secure-containers-set7.md)
- VM boot pipelined with the host-side rootfs mount+copy instead of strictly
  sequential — see [docs/secure-containers-set7r.md](secure-containers-set7r.md).
- Pod-scoped raw block QMP hotplug and allowlisted VFIO PCI passthrough,
  reference-counted per container with QEMU `DEVICE_DELETED`-confirmed
  hot-unplug — see [docs/secure-containers-set9.md](secure-containers-set9.md)
- fail-closed AppArmor/SELinux process labels and generated per-container
  cgroup-v2 `BPF_PROG_TYPE_CGROUP_DEVICE` policy from OCI
  `linux.resources.devices` — see
  [docs/secure-containers-set10.md](secure-containers-set10.md)

## Current limitations

This remains a **developer-preview runtime**, not a claim of full Kata
Containers compatibility.

1. **QEMU is the supported Secure Containers VMM.** Cloud Hypervisor and
   Firecracker still need equivalent shared-rootfs/volume plumbing.
2. **CNI coverage is not yet broad conformance.** The L2 handoff now replays
   IPv4/IPv6 dual-stack on the primary interface and rejects extra routable
   interfaces by default; real Multus/secondary-NIC hotplug and unusual CNI
   layouts remain open.
3. **Arbitrary hostPath passthrough is not enabled by default.** Kubernetes
   Pod volume roots are scoped by sandbox UID; other binds remain copied unless
   an explicit broker/hotplug model is added.
4. **Device-cgroup enforcement landed in Set 10.** PID/mount/IPC/UTS
   namespace isolation landed in Set 6 (see
   [docs/secure-containers-set6r.md](secure-containers-set6r.md)), and user
   namespace isolation is available opt-in. Per-container device access
   control is now a real `BPF_PROG_TYPE_CGROUP_DEVICE` program compiled from
   OCI `linux.resources.devices` and attached to the per-container guest
   cgroup, not just the existing static device-node bind mounts.
5. **Seccomp argument comparators are implemented; notify is not.** All OCI
   comparison operators (`SCMP_CMP_*`) are enforced via
   `seccomp_rule_add_array`. `SCMP_ACT_NOTIFY` requires a persistent userspace
   broker FluxVM does not implement yet and fails closed instead of silently
   dropping policy.
6. **TTY streaming is new in Set 5 and requires real KVM/containerd churn and
   resize testing on self-hosted nodes before production claims.**
7. **`CLONE_NEWUSER` is opt-in and unproven under load.** Default identity
   uid/gid mapping avoids virtiofs ACL shifting but has not yet been validated
   against real multi-container Pods on self-hosted KVM nodes.
8. **Raw block/device-plugin passthrough is scoped, not general.** Pod-scoped
   raw block volumes are hotplugged over QMP from the owning Pod's
   `volumeDevices` tree (or an explicit operator allowlist prefix); VFIO PCI
   character-device passthrough requires an exact BDF allowlist and a device
   already bound to `vfio-pci`. Anything outside those allowlists still fails
   closed instead of silently `mknod`-ing an unrelated node.

## Next gates to production Kata-style Kubernetes support

### P0 — OCI conformance fixtures

PID/mount/IPC/UTS namespace isolation (opt-in `CLONE_NEWUSER`) and
per-container device-cgroup enforcement (`BPF_PROG_TYPE_CGROUP_DEVICE`) have
both landed. Remaining: broader OCI runtime-spec conformance test fixtures
covering the full matrix of these controls together.

### P0 — CNI conformance

Exercise Cilium/Calico bridge/veth paths under churn, then add IPv6, dual-stack
and multi-interface/Multus coverage.

### P0 — volume broker / explicit hostPath

Keep Pod-scoped kubelet volume exports as the safe default. Add a narrowly
allowlisted broker/hotplug path for operators that intentionally need arbitrary
hostPath or non-kubelet mounts.

### P1 — seccomp notification broker

Argument comparators are implemented (Set 10). Add a persistent
`SCMP_ACT_NOTIFY` listener and broker lifecycle while retaining fail-closed
behavior when the guest cannot service a requested notification profile.

### P1 — streaming/TTY conformance

Run repeated init + exec terminal resize, stdin close, high-volume stdout/stderr
and abrupt-exit tests on self-hosted KVM/containerd nodes.

### P1 — performance

Set 7 (Runtime) pipelines VM boot with the host-side rootfs copy (no longer
strictly sequential) — see
[docs/secure-containers-set7r.md](secure-containers-set7r.md). Full warm-pool
integration (claim/resume a prepared sandbox instead of cold-booting every
Pod group) remains open.

### P1 — additional VMMs

Enable Cloud Hypervisor first, then a restricted Firecracker profile once their
shared-rootfs and device models are integrated.

## Installation

```bash
sudo ./scripts/install-secure-containers.sh
```

Set the guest image explicitly when needed:

```bash
export FLUXVM_CONTAINER_GUEST_IMAGE=/var/lib/fluxvm/images/secure-container.qcow2
export FLUXVM_API_URL=http://127.0.0.1:7788
# export FLUXVM_API_TOKEN=...   # if FluxVM API auth is enabled
```

Merge `deploy/containerd/fluxvm-runtime.toml` into containerd configuration,
restart containerd, and install `deploy/containerd/runtimeclass.yaml` only on a
development cluster until the CNI gate above lands.

## Test levels

### Level 1 — host-independent

```bash
./scripts/test-secure-containers.sh
```

This builds both binaries and runs all new unit tests.

### Level 2 — KVM/containerd host

Set `FLUXVM_SECURE_CONTAINERS_E2E=1`; the script validates KVM, containerd and
FluxVM API prerequisites and runs `scripts/e2e-secure-containers-ctr.sh`. Run
`scripts/e2e-secure-containers-volume.sh` for write-through PVC coverage,
`scripts/e2e-secure-containers-tty.sh` for VSOCK stdio + init/exec PTY/resize,
and `scripts/e2e-secure-containers-namespaces.sh` for Set 6 PID/mount/IPC/UTS
isolation (both need a Kubernetes cluster with the `fluxvm` RuntimeClass
applied, not just bare `ctr`).

The GitHub-hosted CI job intentionally does not claim KVM end-to-end coverage,
because ordinary hosted runners do not provide the nested virtualization and
node configuration needed for an honest containerd+FluxVM test.

## Set 4 addendum — write-through Pod volumes + OCI security

Set 4 adds Pod-UID-scoped virtiofs exports for kubelet `volumes/` and
`volume-subpaths/`, so matching Kubernetes volume bind mounts are write-through
instead of copied. Arbitrary host binds remain snapshot-based by default.

The guest agent also enforces read-only rootfs, masked/read-only paths, OCI
device nodes, Pod-VM sysctls and libseccomp syscall-name rules. Seccomp profiles
using unsupported argument comparators fail closed. See
`docs/secure-containers-set4.md` for the exact support boundary and test gates.


## Set 5 addendum — VSOCK stdio + TTY/PTY

Set 5 moves normal runtime stdio off virtiofs polling files. Lifecycle RPC stays
on port 17778 while raw process streams attach on authenticated VSOCK port
17779. Non-TTY tasks use guest pipes; terminal tasks use a real guest PTY and
containerd `ResizePty` maps to `TIOCSWINSZ`. See
`docs/secure-containers-set5.md` for protocol, fallback and test details.

## Runtime recovery + dual-stack CNI addendum

Persists an atomic versioned sandbox/task/exec ownership journal (including
`ready=false` provisional VM ownership), validates it against the live FluxVM
before reuse, and fails closed rather than risking a duplicate Pod VM when
recovery cannot be proven safe. Restores task/exec exit watchers and attempts
VSOCK stdio reattachment after a replacement shim launches. The primary CNI
interface now captures/replays IPv4 + IPv6 addresses and family-specific
routes; additional routable interfaces are rejected by default
(`FLUXVM_CONTAINER_CNI_STRICT_MULTI_INTERFACE=0` to relax in controlled labs
only). See `docs/secure-containers-set6.md`.

## OOM + cgroup metrics + cleanup-safety addendum

Publishes containerd `TaskOOM` from guest cgroup-v2 `memory.events` with a
journaled `oom_kill` cursor that survives replacement-shim recovery. `StatsTask`
gains CPU throttling and detailed memory/swap/fault/pids statistics. OCI
`memory.reservation` maps to `memory.low`, OCI memory+swap is converted to
cgroup-v2 swap-only `memory.swap.max`, and `LinuxResources.unified` updates are
restricted to a small explicit allowlist. Raw block and special host-device
binds are rejected instead of copied, and character devices are validated
against the guest's actual attached major/minor. Sandbox teardown retains
journal/CNI ownership state when FluxVM VM deletion fails, so cleanup can be
retried safely. See `docs/secure-containers-set7.md`.

## Set 8 addendum — raw block + VFIO devices

Set 8 replaces the prior raw/special-device fail-closed placeholder with real
QEMU hotplug for Pod-scoped raw block volumes and explicitly allowlisted VFIO
PCI devices. Raw block sources are resolved only from the owning Pod's
`volumeDevices` tree (or an explicit operator prefix), attached as SCSI devices,
and rediscovered inside the guest by stable serial. VFIO character-device
passthrough requires an exact BDF allowlist and a device already bound to
`vfio-pci`; host drivers are never detached automatically. See
`docs/secure-containers-set8.md`.

## Set 9 addendum — passthrough device lifecycle

Set 9 reference-counts raw-block/VFIO attachments by container, waits for QEMU `DEVICE_DELETED` before final backend cleanup, journals delayed unplug for retry, validates raw-block identity and complete VFIO IOMMU groups on recovery, and supports guest-driver GPU companion nodes without copying host major/minor numbers. See [secure-containers-set9.md](secure-containers-set9.md).

## Set 10 addendum — guest security enforcement

Set 10 adds all OCI/libseccomp argument comparison operators, fail-closed
AppArmor and SELinux process labels, and generated per-container cgroup-v2
device eBPF (`BPF_PROG_TYPE_CGROUP_DEVICE`). Unsupported seccomp notify and
SELinux mount labels remain explicit fail-closed boundaries. See
[secure-containers-set10.md](secure-containers-set10.md).
