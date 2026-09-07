# 02 — MicroVMJob

**Goal:** Run a completion-oriented workload as a `MicroVMJob` that owns child
MicroVMs and optionally runs a vsock command.

**You will use:** `examples/microvm/microvmjob.yaml`.

## 1. Prerequisites

Complete [01 — Getting started](01-getting-started.md) so CRDs, controller, and
node-agent are healthy. Stage the Job template image on capable nodes.

## 2. Apply a Job

```bash
kubectl apply -f examples/microvm/microvmjob.yaml
kubectl get mvmj compile-main -w
```

Example shape:

```yaml
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVMJob
metadata:
  name: compile-main
spec:
  completions: 1
  parallelism: 1
  backoffLimit: 2
  template:
    backend: firecracker
    image: /var/lib/fluxvm/images/ci-rootfs.ext4
    vcpus: 4
    memoryMib: 4096
    networkMode: tap
    bridge: vmbr0
    netns: true
    claimFrom: ci-warm   # optional; see 03-pool
    command: "/usr/local/bin/run-ci"
    persist: false
```

## 3. Watch children and status

```bash
kubectl get mvm -l microvm.fluxvm.zyvor.io/job=compile-main
# labels may vary; also:
kubectl get mvm | grep compile-main
kubectl get mvmj compile-main -o yaml | sed -n '/^status:/,$p'
```

**Expect:** `status.active` / `succeeded` / `failed` move toward
`completions`. With `persist: false` and `command` set, the child finishes
after vsock exec and the Job counts a success or failure from the exit code.

## 4. Tune completions

Raise `spec.completions` and `spec.parallelism` for fan-out. Failed children
retry up to `backoffLimit`.

## 5. Cleanup

```bash
kubectl delete mvmj compile-main
```

Child MicroVMs are removed with the Job (controller-owned).

## Next

- [03 — MicroVMPool](03-pool.md) — warm `claimFrom`
- [04 — Convert DisposableVm](04-convert-disposablevm.md)
