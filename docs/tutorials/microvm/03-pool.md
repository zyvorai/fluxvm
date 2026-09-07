# 03 — MicroVMPool

**Goal:** Declare a warm pool and claim a guest from it with `claimFrom`.

**You will use:** `examples/microvm/pool.yaml` and a MicroVM (or Job template)
with `spec.claimFrom`.

## 1. Prerequisites

[01 — Getting started](01-getting-started.md). The node-agent calls FluxVM
`POST /v1/pools` on the local node — confirm:

```bash
curl -sf http://127.0.0.1:7788/readyz | jq .
```

## 2. Create a pool

```bash
kubectl apply -f examples/microvm/pool.yaml
kubectl get mvmp ci-warm -w
```

```yaml
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVMPool
metadata:
  name: ci-warm
spec:
  replicas: 4
  template:
    backend: firecracker
    image: /var/lib/fluxvm/images/ci-rootfs.ext4
    vcpus: 4
    memoryMib: 4096
    networkMode: tap
    bridge: vmbr0
    netns: true
    persist: true
```

**Expect:** `status.ready` approaches `replicas` as the node-agent warms guests
via FluxVM.

Optional: pin with `spec.nodeName` when you want a specific capable node.

## 3. Claim from the pool

Create a MicroVM (or Job template) with `claimFrom: ci-warm`:

```bash
kubectl apply -f - <<'EOF'
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVM
metadata:
  name: from-pool
spec:
  backend: firecracker
  image: /var/lib/fluxvm/images/ci-rootfs.ext4
  vcpus: 4
  memoryMib: 4096
  claimFrom: ci-warm
  ttlSeconds: 600
  persist: false
EOF

kubectl get mvm from-pool -w
```

**Expect:** faster path to `Running` than a cold create (resume/claim from the
warm pool). Pool `status.claimed` increases.

## 4. Cleanup

```bash
kubectl delete mvm from-pool
kubectl delete mvmp ci-warm
```

## Next

- [02 — MicroVMJob](02-job.md) — Job template with `claimFrom`
- [04 — Convert DisposableVm](04-convert-disposablevm.md)
