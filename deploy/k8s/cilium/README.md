# FluxVM + Cilium (Kubernetes)

Secure Containers on Cilium nodes: Cilium remains the Pod CNI; FluxVM hands
`eth0` into the guest. See [docs/cilium-cni.md](../../docs/cilium-cni.md).

## Mounts / coexistence

The main FluxVM DaemonSet already mounts:

- host `/sys/fs/bpf` (bpffs)
- read-only `/var/run/cilium` (for `mode=cilium` Fabric coexistence)

See [deploy/k8s/daemonset.yaml](../daemonset.yaml) and
[docs/ebpf-cilium.md](../../docs/ebpf-cilium.md).

## Shim environment

Merge [runtime-env.env](runtime-env.env) into the containerd/shim environment
on each Cilium node (systemd drop-in or kubelet RuntimeClass wrapper), then
restart containerd and clear leaked shims:

```bash
sudo systemctl restart containerd
sudo pkill -f containerd-shim-fluxvm-v2 || true
```

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
