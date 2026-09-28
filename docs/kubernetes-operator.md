# Kubernetes CRD and operator

`fluxvm-kube`: the `DisposableVm` resource and its node-local operator.

[Back to README](../README.md)

## Kubernetes CRD/operator

`fluxvm-kube` is a `DisposableVm` custom resource plus a node-local operator that reconciles them against a
*local* `fluxctl serve` instance — each node's operator only acts on objects whose `spec.node` matches the
node it was started with, the same shape as a real DaemonSet (see [`deploy/k8s/`](../deploy/k8s/) for the
Dockerfile and CRD/RBAC/DaemonSet manifests). Verified end to end against a real k3s cluster (9/9 checks:
CRD acceptance, real VM reconciliation, out-of-band-delete self-healing, and finalizer-blocked cleanup with no
leaked QEMU process — see [`scripts/test-kube-operator.sh`](../scripts/test-kube-operator.sh)):

```bash
fluxvm-kube --print-crd | kubectl apply -f -
NODE_NAME=$(hostname) FLUXVM_URL=http://127.0.0.1:7788 fluxvm-kube
```

**Declarative, not one-shot.** If the underlying VM disappears (TTL expired, or deleted through the REST API)
the operator notices on its next reconcile and creates a replacement — the same "keep this existing" semantics a
`Deployment` gives Pods. `spec.networkMode` supports `none`/`user`/`tap`/`macvtap`, plus opt-in `direct`
(bridge-less; `parent` = the uplink NIC — [docs/direct-datapath.md](direct-datapath.md)). Placement: set
`spec.node`, or run one `fluxvm-kube --enable-placement` instance to pin to the least-loaded capable node.

Related but separate: [Secure Containers](secure-containers.md) uses containerd RuntimeClass `fluxvm` for OCI
workloads and does not replace `DisposableVm`. The scheduler-native alternative to KubeVirt is `fluxvm-microvm` —
see [docs/microvm.md](microvm.md).
