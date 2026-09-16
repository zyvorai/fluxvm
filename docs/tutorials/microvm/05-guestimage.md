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

## 3. Optional: verify the staged file's digest

Set `spec.sha256` to have the node agent check the staged file's digest
before it flips `status.ready`:

```bash
SHA=$(sha256sum "$IMG" | cut -d' ' -f1)

kubectl apply -f - <<EOF
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: GuestImage
metadata:
  name: lab-ubuntu-verified
  namespace: default
spec:
  source: ${IMG}
  sha256: ${SHA}
EOF

kubectl get gimg lab-ubuntu-verified -o jsonpath='{.status.ready} {.status.message}{"\n"}'
```

**Expect:** `true host file present, sha256 verified`. Edit `spec.sha256` to a
wrong value and the next reconcile flips `status.ready=false` with
`status.message: "sha256 mismatch: expected ..., got ..."` — `status.path` is
cleared too, so a `MicroVM` naming this catalog entry never resolves against
an unverified file. The digest is only recomputed when the staged file's
size/mtime changes (`status.verifiedSignature` is the cache key), so a large
image is not re-hashed on every reconcile.

## 4. Optional: catalog a direct-kernel-boot image

Set `spec.kernel` to a host `vmlinux` path when this catalog entry is meant
for Firecracker's direct-kernel boot. It's verified present the same way as
`spec.source`/`spec.sha256` before `status.ready` flips true:

```bash
KERNEL=/var/lib/fluxvm/kernels/vmlinux-fc   # adjust; must exist on the node

kubectl apply -f - <<EOF
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: GuestImage
metadata:
  name: lab-firecracker
  namespace: default
spec:
  source: ${IMG}
  kernel: ${KERNEL}
EOF

kubectl get gimg lab-firecracker -o jsonpath='{.status.ready} {.status.kernelPath}{"\n"}'
```

**Expect:** `true /var/lib/fluxvm/kernels/vmlinux-fc`. A `MicroVM` naming
`lab-firecracker` gets `status.kernelPath` forwarded automatically as
`kernel` on the `POST /v1/vms` request — nothing to set on the `MicroVM`
itself. If `spec.kernel` names a file that isn't actually on the node,
`status.ready` stays `false` with `status.message: "kernel file not found on
node: <path>"`, the same fail-closed contract as a `spec.sha256` mismatch: a
`MicroVM` must never silently launch on Firecracker with no kernel at all.

## 5. MicroVM by catalog name

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

## 6. Cleanup

```bash
kubectl delete mvm from-catalog --ignore-not-found
kubectl delete gimg lab-ubuntu lab-ubuntu-verified lab-firecracker --ignore-not-found
```

## Next

- Design: [microvm.md](../../microvm.md) · Index: [README.md](README.md)
- Lab smoke: `./scripts/test-microvm-k8s-smoke.sh`
