# FluxVM Secure Containers — containerd runtime v2

FluxVM Secure Containers is the container-runtime layer on top of the existing
FluxVM VM lifecycle, VSOCK guest agent and QEMU virtiofs support. The goal is
the same security shape users expect from Kata Containers: a Pod or container
group gets its own guest kernel instead of sharing the node's host kernel.

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
      |                              +-- virtiofs Pod share
      |                              +-- TAP on host CNI bridge (when netns present)
      |                              +-- fluxvm-guest-agent :17777
      |                              +-- fluxvm-container-agent :17778
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

## Implemented

### v0.1 foundation

- containerd runtime-v2 binary: `containerd-shim-fluxvm-v2`
- one shim group -> one FluxVM QEMU VM
- Kubernetes Pod grouping annotation recognition
- authenticated VSOCK container protocol
- OCI process lifecycle: create, start, state, wait, kill, pause, resume, delete
- exec lifecycle (non-TTY)
- uid/gid, cwd, argv, PATH resolution and environment inside a chrooted container rootfs
- guest-side OCI bind/proc/tmpfs/sysfs/devpts/mqueue/cgroup mount application and cleanup
- containerd snapshot rootfs staging into the VM-visible virtiofs share
- bind-mount snapshot staging for ConfigMap/Secret-style inputs
- stdin/stdout/stderr FIFO relay
- FluxVM guest-agent bootstrap of the dedicated container agent
- RuntimeClass and containerd configuration examples
- unit tests for protocol, OCI parsing, grouping and mount staging
- a dedicated GitHub Actions build/test/clippy gate

### Set 2 — CNI L2 + guest cgroup resources

- **CNI Pod IP in the guest (opt-in, default on).** When the CRI sandbox provides
  a Pod network namespace path, the shim prepares a transparent L2 attachment:
  the host bridge receives a FluxVM QEMU TAP, and the guest is configured with
  the **actual CNI Pod IP + MAC + routes**. Without a netns path (plain `ctr`),
  networking stays FluxVM user-mode. Disable with `FLUXVM_CONTAINER_CNI=0`.
- **Guest cgroup v2** under `/sys/fs/cgroup/fluxvm-containers`:
  per-container create/update for CPU quota/period/shares, cpuset, memory, pids;
  Pod-wide `ConfigureSandboxResources`; freeze/thaw for pause/resume;
  kill-all via cgroup; `Pids` / `Stats` / `UpdateResources` on the wire protocol.
- Shim maps containerd `Stats` / `Update` / `Pids` to the guest agent.
- VM shape (`vcpus` / `memory_mib`) derived from sandbox resource hints plus
  `FLUXVM_CONTAINER_VM_OVERHEAD_MIB` (default 256).

## Explicit limitations

This remains a **developer-preview** runtime, not a claim of full Kata
Containers compatibility.

1. **QEMU only.** FluxVM currently implements `SharedFolder`/virtiofs on QEMU.
   Cloud Hypervisor and Firecracker need equivalent shared-rootfs plumbing
   before they can be enabled safely.
2. **CNI L2 is best-effort for common bridge/veth topologies.** Exotic CNI
   setups, dual-stack-only paths, or plugins that do not leave a usable
   interface/MAC/routes in the Pod netns may still fall back or fail closed.
   Validate against your CNI (Cilium/Calico/etc.) before production.
3. **PVC writes are not write-through.** Bind mounts are snapshotted into the
   Pod share. This is correct for read-mostly ConfigMaps/Secrets but is not a
   persistent-volume implementation.
4. **TTY/resize is rejected**, not silently emulated.
5. **OCI namespace/capability/seccomp/device parity inside the guest is
   incomplete.** Guest cgroup v2 covers a portable resource subset; the VM is
   still the primary isolation boundary.
6. **Stdio over virtiofs uses regular log files** (not FIFOs), with a polling
   host relay. Interactive/blocking stdin semantics are weaker than true pipes;
   vsock stdio remains a follow-up for production streaming.

These constraints are intentional: unsupported behavior returns an explicit
error instead of appearing to work while weakening isolation or data
correctness.

## Next gates

### P0 — volume model

Add virtiofs hotplug or a stable shared-fs broker so CSI/PVC mounts can be
passed through without copying. Enforce read-only/read-write semantics and
propagation explicitly.

### P0 — OCI hardening inside guest

Implement namespaces, capabilities, seccomp, masked/readonly paths, rlimits,
NoNewPrivileges and devices. Add conformance fixtures from the OCI runtime
spec.

### P0 — stdio without virtiofs FIFOs

Replace FIFO-over-virtiofs with a relay that works reliably through the share
or over VSOCK.

### P1 — CNI hardening

Broader CNI conformance, IPv6, multi-interface, and teardown races under
frequent Pod churn.

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
# export FLUXVM_CONTAINER_CNI=0 # disable CNI L2; force user-mode networking
```

Merge `deploy/containerd/fluxvm-runtime.toml` into containerd configuration,
restart containerd, and install `deploy/containerd/runtimeclass.yaml` on a
lab cluster once guest-image + virtiofs + CNI L2 have been smoke-tested.

## Test levels

### Level 1 — host-independent

```bash
./scripts/test-secure-containers.sh
```

This builds both binaries and runs all new unit tests.

### Level 2 — KVM/containerd host

Set `FLUXVM_SECURE_CONTAINERS_E2E=1`; the script validates KVM, containerd and
FluxVM API prerequisites and runs `scripts/e2e-secure-containers-ctr.sh`, which
pulls BusyBox and executes it with `io.containerd.fluxvm.v2`. Plain `ctr` has
no Pod netns, so CNI L2 stays inactive for that smoke.

The GitHub-hosted CI job intentionally does not claim KVM end-to-end coverage,
because ordinary hosted runners do not provide the nested virtualization and
node configuration needed for an honest containerd+FluxVM test.
