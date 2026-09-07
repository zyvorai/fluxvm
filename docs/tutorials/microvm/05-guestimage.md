# 05 — GuestImage catalog

**Goal:** Mark a host-staged disk Ready via `GuestImage`, then create a
`MicroVM` that names it (`spec.image: <gimg-name>`).

## 1. Prerequisites

- MicroVM stack running ([01 — Getting started](01-getting-started.md)).
- A disk already on the node (GuestKit / ops), e.g.
  `/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2`.

There is **no CDI / importer Pod**. HTTP `spec.source` stays not-Ready until
the file exists on that host.

## 2. Create a GuestImage

```bash
IMG=/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2   # adjust

kubectl apply -f - <<EOF
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: GuestImage
metadata:
  name: lab-ubuntu
  namespace: default
spec:
  source: ${IMG}
EOF

kubectl get gimg lab-ubuntu -w
```

**Expect:** `status.ready=true` and `status.path` equal to the host path once
the node-agent reconciler sees the file.

```bash
kubectl get gimg lab-ubuntu -o jsonpath='{.status.ready} {.status.path}{"\n"}'
```

## 3. MicroVM by catalog name

```bash
kubectl apply -f - <<'EOF'
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVM
metadata:
  name: from-catalog
  namespace: default
spec:
  backend: qemu
  image: lab-ubuntu
  vcpus: 1
  memoryMib: 1024
  networkMode: user
  ttlSeconds: 300
  persist: false
EOF

kubectl get mvm from-catalog -w
```

**Expect:** `Running` with a `status.runtime.uuid`. The node agent resolves
`lab-ubuntu` → GuestImage `status.path` before `POST /v1/vms`.

Direct paths still work (`image: /var/lib/fluxvm/images/...`, `*.qcow2`, URLs).

## 4. Cleanup

```bash
kubectl delete mvm from-catalog --ignore-not-found
kubectl delete gimg lab-ubuntu --ignore-not-found
```

## Next

- Design: [microvm.md](../../microvm.md) · Index: [README.md](README.md)
- Lab smoke: `./scripts/test-microvm-k8s-smoke.sh`
