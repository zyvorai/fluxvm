# 04 — Convert DisposableVm → MicroVM

**Goal:** Dual-run with `fluxvm-microvm controller --convert` so each
`DisposableVm` projects a same-name `MicroVM`.

## 1. Prerequisites

- `fluxvm-kube` + `DisposableVm` CRD installed (`deploy/k8s/`).
- MicroVM CRDs installed ([01 — Getting started](01-getting-started.md)).
- Controller with `--convert` (default in `deploy/k8s/microvm/controller.yaml`).

Confirm:

```bash
kubectl -n fluxvm-system get deploy fluxvm-microvm-controller -o yaml \
  | grep -A2 'command:'
# expect: fluxvm-microvm controller --convert
```

Lab without the Deployment:

```bash
fluxvm-microvm controller --convert
```

## 2. Create a DisposableVm

```bash
kubectl apply -f - <<'EOF'
apiVersion: fluxvm.zyvor.io/v1
kind: DisposableVm
metadata:
  name: bridge-demo
  namespace: default
spec:
  node: <node-name>
  backend: qemu
  image: /var/lib/fluxvm/images/ubuntu.qcow2
  vcpus: 1
  memoryMib: 1024
  networkMode: user
  ttlSeconds: 300
EOF
```

Replace `<node-name>` with a capable node.

## 3. Watch the projected MicroVM

```bash
kubectl get dvm bridge-demo
kubectl get mvm bridge-demo
kubectl get mvm bridge-demo -o yaml | grep -A2 converted-from
```

**Expect:** a `MicroVM` named `bridge-demo` with annotation
`microvm.fluxvm.zyvor.io/converted-from: disposablevm`, `persist: true`, and
`nodeName` copied from the DisposableVm.

## 4. Notes

- Conversion is a **bridge** for dual-running; prefer creating MicroVMs
  directly for new workloads that need scheduler placement.
- Deleting one side does not always delete the other — tear down both if you
  created both for a demo.
- Ragnarok and other DisposableVm clients keep working; MicroVM is additive.

## 5. Cleanup

```bash
kubectl delete dvm bridge-demo
kubectl delete mvm bridge-demo --ignore-not-found
```

## Next

- Design: [microvm.md](../../microvm.md)
- Index: [README.md](README.md)
