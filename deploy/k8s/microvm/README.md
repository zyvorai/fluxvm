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

Guide: [docs/microvm.md](../../../docs/microvm.md) ·
tutorials: [docs/tutorials/microvm/](../../../docs/tutorials/microvm/README.md).
