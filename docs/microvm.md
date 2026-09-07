# FluxVM MicroVM

Kubernetes-native disposable compute for FluxVM — **without KubeVirt**.

The VMM process lives on the host under `fluxvm serve`. The Pod is only a
**capacity ticket** (`registry.k8s.io/pause` plus CPU/memory requests). The one
privileged surface stays the existing `fluxvm-kube` DaemonSet that already runs
`fluxvm serve` on capable nodes.

| | |
|---|---|
| **Binary** | `fluxvm-microvm` |
| **API group** | `microvm.fluxvm.zyvor.io` / `v1alpha1` |
| **Controllers** | Namespace `fluxvm-system` |
| **Manifests** | [`deploy/k8s/microvm/`](../deploy/k8s/microvm/) |
| **Examples** | [`examples/microvm/`](../examples/microvm/) |
| **Tutorials** | [`docs/tutorials/microvm/`](tutorials/microvm/README.md) |

## Vs DisposableVm and KubeVirt

| | **DisposableVm** (`fluxvm-kube`) | **MicroVM** (`fluxvm-microvm`) | **KubeVirt** |
|---|---|---|---|
| API group | `fluxvm.zyvor.io` | `microvm.fluxvm.zyvor.io` | `kubevirt.io` |
| Placement | Explicit `spec.node` (or optional placer) | kube-scheduler via shadow Pod | virt-launcher Pod |
| Where QEMU/CH/FC runs | Host under `fluxvm serve` | Host under `fluxvm serve` | Inside virt-launcher container |
| Privileged surface | `fluxvm-kube` DaemonSet | Same DaemonSet + thin node-agent | virt-handler / launcher |
| Capacity accounting | Operator / placer heuristics | Pod requests (CPU/memory) | Pod + CDI |
| Jobs / pools | Warm pools via REST | `MicroVMJob`, `MicroVMPool` CRs | Jobs / DataVolumes (different model) |
| Live migration / CDI / virtctl | No | No (v1) | Yes |

Use **DisposableVm** when Ragnarok (or another controller) already pins `spec.node`.
Use **MicroVM** when you want scheduler-driven placement and Job/Pool CRs on the
same host VMM. Both talk to local `fluxvm serve` — neither is KubeVirt.

## Architecture

```text
MicroVM CR
    │
    ▼
cluster controller ──► creates shadow Pod (pause + requests)
    │                     kube-scheduler binds Pod → node
    ▼
status.phase=Scheduled, status.runtime.node=<node>
    │
    ▼
node-agent (DaemonSet, hostNetwork)
    │  FLUXVM_URL=http://127.0.0.1:7788
    ▼
fluxvm serve ──► QEMU / Cloud Hypervisor / Firecracker on the host
```

Phases (typical): `Pending` → `Scheduled` → `Provisioning` → `Running`
(then `Succeeded` / `Failed` when `persist: false` and TTL or command finishes).

Optional: `spec.service: true` publishes an EndpointSlice once `status.guestIP`
is set.

## CRDs

| Kind | Short | Purpose |
|---|---|---|
| `MicroVM` | `mvm` | Guest. Default `persist: false` — TTL expiry is success. |
| `MicroVMJob` | `mvmj` | Run-to-completion: child MicroVMs + optional vsock `command`. |
| `MicroVMPool` | `mvmp` | Node-local warm pool via FluxVM `POST /v1/pools`. |
| `GuestImage` | `gimg` | Catalog: node agent marks Ready when `spec.source` is a host file; MicroVM `spec.image` may name a GuestImage. |

All kinds: `apiVersion: microvm.fluxvm.zyvor.io/v1alpha1`.

Print or apply CRDs:

```bash
fluxvm-microvm --print-crd | kubectl apply -f -
# or
kubectl apply -f deploy/k8s/microvm/crd.yaml
```

## Deploy

**1. DaemonSet `fluxvm-kube` first** so `fluxvm serve` listens on
`127.0.0.1:7788` on capable nodes:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/crd.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl label node <node> ragnarok.io/fluxvm-capable=true
kubectl apply -f deploy/k8s/daemonset.yaml
```

See [deploy/k8s/README.md](../deploy/k8s/README.md) and
[user/kubernetes-deployment.md](user/kubernetes-deployment.md).

**2. Then MicroVM controllers:**

```bash
kubectl apply -f deploy/k8s/microvm/
# crd.yaml → rbac.yaml → controller.yaml → node-agent.yaml
```

The controller Deployment runs `fluxvm-microvm controller` **without**
`--convert` by default (opt-in dual-run bridge). The node-agent DaemonSet
selects `ragnarok.io/fluxvm-capable=true` and uses `NODE_NAME` + `FLUXVM_URL`.

Shadow Pods request a tiny pause budget (`10m` CPU / `32Mi` RAM), not the
guest’s vCPU/memory — guest resources live under the host VMM cgroup.

Local / lab without the full DaemonSet image:

```bash
fluxvm-microvm --print-crd | kubectl apply -f -
fluxvm-microvm controller &
NODE_NAME=$(hostname) FLUXVM_URL=http://127.0.0.1:7788 fluxvm-microvm node-agent
```

## First MicroVM

Stage an image on the node (same path you would use for DisposableVm), then:

```bash
kubectl apply -f examples/microvm/microvm.yaml
kubectl get mvm sandbox-42 -w
```

Example (`examples/microvm/microvm.yaml`):

```yaml
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVM
metadata:
  name: sandbox-42
spec:
  backend: qemu
  image: /var/lib/fluxvm/images/ubuntu.qcow2
  vcpus: 2
  memoryMib: 2048
  networkMode: tap
  bridge: vmbr0
  netns: true
  service: true
  servicePort: 22
  ttlSeconds: 900
  persist: false
```

Adjust `image`, `bridge`, and `backend` to match the node. Prefer
`networkMode: user` or `none` for a first smoke test if TAP/bridge is not ready.

## MicroVMJob

Run-to-completion: creates child MicroVMs from `spec.template`, tracks
`completions` / `parallelism` / `backoffLimit`. Optional `template.command` runs
over vsock once Running; with `persist: false` the guest is deleted after the
command.

```bash
kubectl apply -f examples/microvm/microvmjob.yaml
kubectl get mvmj compile-main -w
```

Tutorial: [tutorials/microvm/02-job.md](tutorials/microvm/02-job.md).

## MicroVMPool

Maps to FluxVM warm pools (`POST /v1/pools`). Claim with
`spec.claimFrom: <pool-name>` on a MicroVM (or Job template).

```bash
kubectl apply -f examples/microvm/pool.yaml
kubectl get mvmp ci-warm -w
```

Tutorial: [tutorials/microvm/03-pool.md](tutorials/microvm/03-pool.md).

## GuestImage

`GuestImage` catalogs a disk (`spec.source`, optional `sha256` / `backend` /
`kernel`). **No CDI / importer Pod** — GuestKit (or ops) stages the file on the
node. The node-agent reconciler sets `status.ready` + `status.path` when
`spec.source` is an absolute path that exists on that host.

`MicroVM.spec.image` may be:

- a direct path / URL / `*.qcow2|raw|ext4|img` name (used as-is), or
- a GuestImage name in the same namespace (resolved to `status.path` once Ready)

```bash
kubectl apply -f - <<'EOF'
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: GuestImage
metadata: {name: ubuntu-lab}
spec: {source: /var/lib/fluxvm/images/ubuntu.qcow2}
EOF
# MicroVM.spec.image: ubuntu-lab
```

## DisposableVm bridge (`--convert`, opt-in)

```bash
fluxvm-microvm controller --convert
```

Watches `DisposableVm` (`fluxvm.zyvor.io`) and creates a same-name `MicroVM`
with `persist: true` and `nodeName` copied. Converted guests get:

- `microvm.fluxvm.zyvor.io/converted-from=disposablevm`
- `microvm.fluxvm.zyvor.io/driven-by=fluxvm-kube` — the MicroVM node agent
  **skips** `POST /v1/vms` so fluxvm-kube remains the sole VMM driver

Deploy manifests leave `--convert` **off**. Enable only when you understand the
`driven-by` skip. Tutorial:
[tutorials/microvm/04-convert-disposablevm.md](tutorials/microvm/04-convert-disposablevm.md).

## Verify

```bash
kubectl -n fluxvm-system get pods -o wide
kubectl -n fluxvm-system logs deploy/fluxvm-microvm-controller --follow
kubectl -n fluxvm-system logs ds/fluxvm-microvm-node --follow
kubectl get crd | grep microvm.fluxvm.zyvor.io
kubectl get mvm,mvmj,mvmp -A
curl -sf http://127.0.0.1:7788/readyz | jq .
```

Tests:

```bash
cargo test -p fluxvm-microvm
./scripts/test-microvm.sh
```

## Limitations (v1)

- No virt-launcher, virtctl, CDI, or live migration.
- No second privileged VMM DaemonSet — reuse `fluxvm-kube` / host `fluxvm serve`.
- No k8s-native image pull — host-staged paths only (`GuestImage` Ready when the file exists on the node).
- Shadow Pod is capacity accounting, not the VMM process.
- Images and TAP/bridges must exist on the scheduled node before Running.

## Tutorials

| Tutorial | Focus |
|----------|-------|
| [01 — Getting started](tutorials/microvm/01-getting-started.md) | print-crd, deploy, create MicroVM, watch phase |
| [02 — MicroVMJob](tutorials/microvm/02-job.md) | Run-to-completion jobs |
| [03 — MicroVMPool](tutorials/microvm/03-pool.md) | Warm pools + claimFrom |
| [04 — Convert DisposableVm](tutorials/microvm/04-convert-disposablevm.md) | `--convert` bridge |

Also: [kubernetes-deployment.md](user/kubernetes-deployment.md) ·
[deploy/k8s/microvm/README.md](../deploy/k8s/microvm/README.md) ·
[PRODUCTION.md](PRODUCTION.md).
