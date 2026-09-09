# FluxVM containerd runtime v2

Runtime id: `io.containerd.fluxvm.v2`  
Shim binary: `containerd-shim-fluxvm-v2`  
Kubernetes RuntimeClass handler: `fluxvm`

`fluxvm-runtime.toml` is a merge fragment, not a complete containerd config.
Use `scripts/install-secure-containers.sh` to install the host binaries, then
merge the runtime fragment and restart containerd.

> v0.1 is a developer-preview runtime. QEMU/virtiofs process isolation works;
> Kubernetes CNI/PVC write-through and TTY are explicit follow-up gates. Do
> not advertise this RuntimeClass as Kata-compatible production networking yet.
