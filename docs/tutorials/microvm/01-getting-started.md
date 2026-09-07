# 01 — Getting started (MicroVM)

**Goal:** Install MicroVM CRDs and controllers, create a guest, and watch
`status.phase` through Scheduled → Running.

**You will use:** `fluxvm-microvm --print-crd`, `deploy/k8s/microvm/`,
`examples/microvm/microvm.yaml`.

## 1. Confirm fluxvm serve on the node

The MicroVM node-agent only talks to a **local** API:

```bash
curl -sf http://127.0.0.1:7788/healthz && echo LIVENESS_OK
curl -sf http://127.0.0.1:7788/readyz | jq .
kubectl -n fluxvm-system get pods -o wide
```

If the DaemonSet is missing, deploy `deploy/k8s/` first
([deploy/k8s/README.md](../../../deploy/k8s/README.md)).

## 2. Apply MicroVM CRDs

```bash
fluxvm-microvm --print-crd | kubectl apply -f -
# or
kubectl apply -f deploy/k8s/microvm/crd.yaml
kubectl get crd | grep microvm.fluxvm.zyvor.io
```

**Expect:** `microvms`, `microvmjobs`, `microvmpools`, `guestimages` under
`microvm.fluxvm.zyvor.io`.

## 3. Deploy controller + node-agent

```bash
kubectl apply -f deploy/k8s/microvm/rbac.yaml
kubectl apply -f deploy/k8s/microvm/controller.yaml
kubectl apply -f deploy/k8s/microvm/node-agent.yaml
# or: kubectl apply -f deploy/k8s/microvm/

kubectl -n fluxvm-system get deploy,ds | grep microvm
```

**Expect:** `fluxvm-microvm-controller` Ready; `fluxvm-microvm-node` pods on
capable nodes.

## 4. Create a MicroVM

Edit `examples/microvm/microvm.yaml` so `spec.image` exists on the node. For a
minimal smoke test, set `networkMode: user` (or `none`) if TAP/bridge is not
ready:

```bash
kubectl apply -f examples/microvm/microvm.yaml
kubectl get mvm sandbox-42 -o wide
kubectl get mvm sandbox-42 -w
```

**Expect:** phase moves `Pending` → `Scheduled` → `Provisioning` → `Running`.
A shadow Pod named like `mvm-sandbox-42` (or the controller’s shadow naming)
appears in the same namespace.

```bash
kubectl get pods -l microvm.fluxvm.zyvor.io/microvm=sandbox-42
# shadow Pod name:
kubectl get pod mvm-sandbox-42
```

## 5. Inspect status

```bash
kubectl get mvm sandbox-42 -o yaml | sed -n '/^status:/,$p'
```

**Expect:** `status.runtime.node`, `status.runtime.uuid` (FluxVM VM id), and
optionally `status.guestIP` when networking is up.

## 6. Cleanup

```bash
kubectl delete mvm sandbox-42
```

Finalizers keep the object until the node-agent deletes the underlying VM (and
the shadow Pod is removed).

## Next

- [02 — MicroVMJob](02-job.md)
- [03 — MicroVMPool](03-pool.md)
- Design: [microvm.md](../../microvm.md)
