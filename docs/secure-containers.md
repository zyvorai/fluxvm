# FluxVM Secure Containers — containerd runtime v2

FluxVM Secure Containers is the first container-runtime layer on top of the
existing FluxVM VM lifecycle, VSOCK guest agent and QEMU virtiofs support.
The goal is the same security shape users expect from Kata Containers: a Pod
or container group gets its own guest kernel instead of sharing the node's
host kernel.

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

## Implemented through Set 5

- containerd runtime-v2 binary: `containerd-shim-fluxvm-v2`
- one Kubernetes Pod/containerd shim group -> one FluxVM QEMU VM
- CNI L2 Pod IP/MAC handoff into the guest
- Pod/sandbox and per-container guest cgroup-v2 limits, stats, pids and updates
- containerd task events + asynchronous exit publication
- OCI create/start/state/wait/kill/pause/resume/delete and exec lifecycle
- uid/gid, supplementary groups, cwd, argv, PATH, environment, umask and rlimits
- Linux capability sets, noNewPrivileges, seccomp syscall-name rules
- read-only rootfs, masked/read-only paths, device nodes and Pod-VM sysctls
- containerd snapshot rootfs staging into the VM-visible virtiofs share
- Pod-UID-scoped write-through Kubernetes `volumes` / `volume-subpaths`
- authenticated VSOCK lifecycle RPC on port 17778
- authenticated raw stdin/stdout/stderr streaming on port 17779
- real guest PTY for terminal init/exec processes
- containerd `ResizePty` and `CloseIO` forwarding
- legacy regular-file virtiofs stdio fallback for non-TTY debugging
- RuntimeClass/containerd examples, source/unit gates and KVM smoke scripts

## Current limitations

This remains a **developer-preview runtime**, not a claim of full Kata
Containers compatibility.

1. **QEMU is the supported Secure Containers VMM.** Cloud Hypervisor and
   Firecracker still need equivalent shared-rootfs/volume plumbing.
2. **CNI coverage is not yet broad conformance.** The current L2 handoff is
   IPv4/primary-interface oriented; dual-stack, Multus and unusual CNI layouts
   need dedicated validation.
3. **Arbitrary hostPath passthrough is not enabled by default.** Kubernetes
   Pod volume roots are scoped by sandbox UID; other binds remain copied unless
   an explicit broker/hotplug model is added.
4. **OCI namespace/device-cgroup parity is incomplete.** The VM remains the
   primary host isolation boundary.
5. **Seccomp argument comparators / notify are not implemented.** Unsupported
   profiles fail closed instead of silently dropping policy.
6. **TTY streaming is new in Set 5 and requires real KVM/containerd churn and
   resize testing on self-hosted nodes before production claims.**

## Next gates to production Kata-style Kubernetes support

### P0 — OCI namespace + device-cgroup parity

Add PID/mount/IPC/UTS/user namespace handling inside the Pod VM where OCI
semantics require it, plus device-cgroup enforcement and broader conformance
fixtures.

### P0 — CNI conformance

Exercise Cilium/Calico bridge/veth paths under churn, then add IPv6, dual-stack
and multi-interface/Multus coverage.

### P0 — volume broker / explicit hostPath

Keep Pod-scoped kubelet volume exports as the safe default. Add a narrowly
allowlisted broker/hotplug path for operators that intentionally need arbitrary
hostPath or non-kubelet mounts.

### P1 — seccomp completeness

Add argument comparators and notification handling while retaining fail-closed
behavior for profiles the guest cannot enforce.

### P1 — streaming/TTY conformance

Run repeated init + exec terminal resize, stdin close, high-volume stdout/stderr
and abrupt-exit tests on self-hosted KVM/containerd nodes.

### P1 — performance

Use FluxVM warm pools/snapshots so Pod VM startup can claim/resume a prepared
sandbox instead of cold-booting every group.

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
`scripts/e2e-secure-containers-volume.sh` for write-through PVC coverage and
`scripts/e2e-secure-containers-tty.sh` for VSOCK stdio + init/exec PTY/resize.

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
