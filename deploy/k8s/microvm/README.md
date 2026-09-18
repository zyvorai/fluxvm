# Deploying FluxVM MicroVM

Apply the existing FluxVM DaemonSet first so `fluxctl serve` is on
`127.0.0.1:7788` (see [../README.md](../README.md)). Then:

```bash
# Token for node-agent → local fluxctl serve (required when [[auth.tokens]] is set)
kubectl create ns fluxvm-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n fluxvm-system create secret generic fluxvm-microvm-token \
  --from-literal=token="$FLUXVM_TOKEN" --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f crd.yaml
kubectl apply -f rbac.yaml
kubectl apply -f controller.yaml
kubectl apply -f node-agent.yaml
# Optional Prometheus Operator scrape of MICROVM_METRICS_ADDR (:9108):
# kubectl apply -f servicemonitor.yaml
# Or vanilla Prometheus: include deploy/prometheus/fluxvm-scrape.yaml
```

Or `fluxvm-microvm --print-crd | kubectl apply -f -` for CRDs (includes printer
columns). `deploy-remote.sh` installs `fluxvm-microvm` + `fluxvm-kube` to
`/usr/local/bin`. Container image: `ghcr.io/zyvorai/fluxvm` (publish via
`.github/workflows/publish-image.yml`).

**Defaults:** controller runs **without** `--convert`. Shadow Pods request
`10m`/`32Mi` only. Converted MicroVMs (when you opt in) get
`microvm.fluxvm.zyvor.io/driven-by=fluxvm-kube` so the node agent does not
double-create VMs. `GuestImage` becomes Ready when `spec.source` exists on the
node; MicroVM `spec.image` may name that GuestImage. Node-agent reads
`FLUXVM_TOKEN` from Secret `fluxvm-microvm-token` (optional key).

Guide: [docs/microvm.md](../../../docs/microvm.md) ·
tutorials: [docs/tutorials/microvm/](../../../docs/tutorials/microvm/README.md).
