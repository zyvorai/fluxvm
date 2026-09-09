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

> Developer-preview. Validate VSOCK stdio/TTY, CNI, and PVC behavior on your
> KVM/containerd/Kubernetes node image before production. See
> [docs/secure-containers.md](../../docs/secure-containers.md). Do not advertise
> this RuntimeClass as full Kata-compatible production yet.
