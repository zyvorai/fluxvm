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

> Developer-preview. PVC write-through, TTY, and FIFO-over-virtiofs stdio remain
> follow-ups. See [docs/secure-containers.md](../../docs/secure-containers.md).
  Do not advertise this RuntimeClass as full Kata-compatible production yet.
