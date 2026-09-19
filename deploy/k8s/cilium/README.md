# FluxVM + Cilium (Kubernetes)

Secure Containers on Cilium nodes: Cilium remains the Pod CNI; FluxVM hands
`eth0` into the guest. See [docs/cilium-cni.md](../../../docs/cilium-cni.md).

## Mounts / coexistence

The main FluxVM DaemonSet already mounts:

- host `/sys/fs/bpf` (bpffs)
- read-only `/var/run/cilium` (for `mode=cilium` Fabric coexistence)

See [deploy/k8s/daemonset.yaml](../daemonset.yaml) and
[docs/ebpf-cilium.md](../../../docs/ebpf-cilium.md).

## Shim environment

Merge [runtime-env.env](runtime-env.env) into the containerd/shim environment
on each Cilium node (systemd drop-in or kubelet RuntimeClass wrapper), then
restart containerd and clear leaked shims:

```bash
sudo systemctl restart containerd
sudo pkill -f containerd-shim-fluxvm-v2 || true
```

Optional bridge-less datapath (`FLUXVM_CONTAINER_CNI_DATAPATH=bridge|direct|auto`, default
`bridge`; [docs/direct-datapath.md](../../../docs/direct-datapath.md)): the daemon's dataplane
mode must be `ebpf` or `cilium`, and `/usr/lib/fluxvm/bpf` needs `fluxvm_direct.bpf.o` next to
`fluxvm_tc.bpf.o`. Prove it on a node with
`FLUXVM_DIRECT_LIVE=1 FLUXVM_CONTAINER_CNI_DATAPATH=direct ./scripts/evidence-direct-datapath.sh`.

Optional Fabric coexistence profile:

```bash
sudo ./scripts/enable-network-fabric-ga.sh --cilium --restart
# or merge configs/cilium-cni.toml
```

## Evidence

```bash
./scripts/evidence-cilium-cni.sh
FLUXVM_CILIUM_CNI_LIVE=1 ./scripts/evidence-cilium-cni.sh
```
