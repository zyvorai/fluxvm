# FluxVM MicroVM

Kubernetes-native disposable compute for FluxVM. Not KubeVirt.

The VMM process lives on the host under FluxVM. The Pod is a capacity ticket
(`registry.k8s.io/pause` + CPU/memory requests). One privileged surface remains
the existing `fluxvm-kube` DaemonSet that already runs `fluxvm serve`.

API group: `microvm.fluxvm.zyvor.io`. Namespace for controllers: `fluxvm-system`.

## Objects

| Kind | Purpose |
|---|---|
| `MicroVM` | Guest. `persist: false` (default) means TTL expiry is success. |
| `MicroVMJob` | Run-to-completion. Child MicroVMs + optional vsock `command`. |
| `MicroVMPool` | Node-local FluxVM warm pool (`POST /v1/pools`). |
| `GuestImage` | Catalog stub. Images are still host-staged / GuestKit. |

## Binaries

```bash
fluxvm-microvm --print-crd
fluxvm-microvm controller --convert
NODE_NAME=$(hostname) FLUXVM_URL=http://127.0.0.1:7788 fluxvm-microvm node-agent
```

`--convert` watches `DisposableVm` and projects a same-name `MicroVM`.

## Not in v1

virt-launcher, virtctl, CDI, live migration, a second privileged VMM DaemonSet.
