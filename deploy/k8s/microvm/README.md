# Deploying FluxVM MicroVM

Apply the existing FluxVM DaemonSet first so `fluxvm serve` is on
`127.0.0.1:7788` (see [../README.md](../README.md)). Then:

```bash
kubectl apply -f crd.yaml
kubectl apply -f rbac.yaml
kubectl apply -f controller.yaml
kubectl apply -f node-agent.yaml
```

Or `fluxvm-microvm --print-crd | kubectl apply -f -`.

**Defaults:** controller runs **without** `--convert`. Shadow Pods request
`10m`/`32Mi` only. Converted MicroVMs (when you opt in) get
`microvm.fluxvm.zyvor.io/driven-by=fluxvm-kube` so the node agent does not
double-create VMs. `GuestImage` becomes Ready when `spec.source` exists on the
node; MicroVM `spec.image` may name that GuestImage.

Guide: [docs/microvm.md](../../../docs/microvm.md) ·
tutorials: [docs/tutorials/microvm/](../../../docs/tutorials/microvm/README.md).
