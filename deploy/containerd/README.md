# FluxVM containerd runtime v2

Runtime id: `io.containerd.fluxvm.v2`  
Shim binary: `containerd-shim-fluxvm-v2`  
Kubernetes RuntimeClass handler: `fluxvm`

`fluxvm-runtime.toml` is a merge fragment, not a complete containerd config.
Use `scripts/install-secure-containers.sh` to install the host binaries, then
merge the runtime fragment and restart containerd.

## Set 2 notes

- **CNI L2** (default on): when the CRI sandbox provides a Pod netns, the shim
  attaches a QEMU TAP to a prepared host bridge and configures the guest with
  the real CNI Pod IP/MAC/routes. Plain `ctr` has no netns → user-mode networking.
  Disable with `FLUXVM_CONTAINER_CNI=0`.
- **Guest cgroup v2** stats / resource updates are wired through the container
  agent (`Stats`, `Update`, `Pids`).

## Set 3 notes

- Publishes containerd task lifecycle events (create/start/exec/pause/resume/
  exit/delete) with async exit watching.
- Guest OCI process hardening: supplementary GIDs, umask, rlimits,
  `noNewPrivileges`, and capability sets.
- Detail: [docs/secure-containers-set3.md](../../docs/secure-containers-set3.md).

## Set 4 notes

- Kubernetes Pod volumes under the current sandbox UID are exported write-through
  into the guest (PVC/CSI/emptyDir/`volume-subpaths`). Keep arbitrary hostPath
  passthrough disabled unless a later allowlisted broker/hotplug implementation
  is installed.
- Guest OCI security: read-only rootfs, masked/read-only paths, device nodes,
  sysctls, and libseccomp by syscall name (fail closed). Guest images using OCI
  seccomp profiles must include `libseccomp.so.2`.
- Detail: [docs/secure-containers-set4.md](../../docs/secure-containers-set4.md).

## Set 5 notes

- Lifecycle RPC remains on VSOCK **17778**; streaming stdin/stdout/stderr uses
  authenticated VSOCK **17779** (default `FLUXVM_CONTAINER_STREAMING_STDIO=1`).
- Set `FLUXVM_CONTAINER_STREAMING_STDIO=0` only for legacy non-TTY regular-file
  virtiofs stdio debugging. TTY requires streaming mode.
- Terminal containers/execs use a real guest PTY with `ResizePty` / `CloseIO`.
- Detail: [docs/secure-containers-set5.md](../../docs/secure-containers-set5.md).

## Set 6 recovery and dual-stack

Recovery is enabled by default and journals ownership under
`FLUXVM_CONTAINERD_STATE_DIR` (default `/run/fluxvm/containerd`). A corrupt
journal fails closed to avoid duplicate Pod VMs.

The primary CNI interface now supports IPv4/IPv6 dual-stack replay. Extra
routable interfaces are rejected by default; use
`FLUXVM_CONTAINER_CNI_STRICT_MULTI_INTERFACE=0` only in controlled labs.

Set 6 does not change containerd dead-shim supervision policy. It provides
safe recovery when a replacement shim is launched.
- Detail: [docs/secure-containers-set6.md](../../docs/secure-containers-set6.md).

## Set 9 device lifecycle

Set 9 makes Set 8 raw-block/VFIO passthrough reference-counted by container and hot-unplugs a device after its last owner is deleted. QEMU `DEVICE_DELETED` is required before a raw block backend is removed; failed or delayed unplug remains journaled for retry.

VFIO defaults to full IOMMU-group validation (`FLUXVM_CONTAINER_VFIO_REQUIRE_IOMMU_GROUP=1`). Every group member must be explicitly present in `FLUXVM_CONTAINER_VFIO_ALLOW` and bound to `vfio-pci`. `FLUXVM_CONTAINER_GUEST_DEVICE_ALLOW` adds exact guest-driver companion character nodes, and `FLUXVM_CONTAINER_DEVICE_UNPLUG_TIMEOUT_SECS` controls the QMP completion wait.

Use `scripts/inspect-secure-container-devices.sh` for journal/device telemetry and `scripts/e2e-secure-containers-device-lifecycle.sh` with a disposable raw-block PVC for the node lifecycle gate.

## Set 10 guest security

OCI seccomp argument filters now use guest `libseccomp.so.2`
`seccomp_rule_add_array`. AppArmor and SELinux process labels are applied
fail-closed when requested. OCI `linux.resources.devices` rules are compiled
into a `BPF_PROG_TYPE_CGROUP_DEVICE` program and attached to the per-container
guest cgroup; the guest therefore needs cgroup v2 + `CONFIG_CGROUP_BPF` when a
device policy is present. `SCMP_ACT_NOTIFY` and SELinux `mountLabel` remain
unsupported and are rejected rather than ignored.

Run `scripts/e2e-secure-containers-security.sh` on the target node/guest image.

> Developer-preview. Validate VSOCK stdio/TTY, CNI, and PVC behavior on your
> KVM/containerd/Kubernetes node image before production. See
> [docs/secure-containers.md](../../docs/secure-containers.md). Do not advertise
> this RuntimeClass as full Kata-compatible production yet.
