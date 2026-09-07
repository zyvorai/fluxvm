# Kubernetes deployment

`fluxvm-kube` — the `DisposableVm` custom resource plus its node-local operator — ships as a
proper container image and a set of `deploy/k8s/` manifests, so it can run as an actual
per-node DaemonSet instead of only as a host-native systemd service.

This is a different model from a Pod-per-workload platform: a `DisposableVm` never goes through
RuntimeClass or a container runtime shim. Each object maps directly to a raw VM process on
whichever node its `spec.node` names, driven by that node's own `fluxvm-kube` instance talking
to a *local* `fluxvm serve` REST API. There is no scheduler — placement is always explicit.

## What gets deployed

One pod per capable node, two containers sharing the pod's network namespace:

| Container | Runs | Privileges |
|-----------|------|------------|
| `fluxvm` | `fluxvm serve` — the VMM control plane | `/dev/kvm`, `NET_ADMIN`/`SYS_ADMIN`/`NET_BIND_SERVICE`/`NET_RAW`, `hostNetwork: true` |
| `fluxvm-kube` | The `DisposableVm` reconcile loop | None — `runAsNonRoot`, read-only root filesystem |

## Node prerequisites

Before labeling a node `ragnarok.io/fluxvm-capable=true` (or your own equivalent label):

1. `/dev/kvm` present and accessible.
2. `nbd` kernel module loaded (`modprobe nbd`) — needed by the image-customization pipeline; this
   can't be satisfied from inside a container, it's a host-level step.
3. VM images pre-staged under the `state_dir` hostPath (there's no k8s-native image pull path
   yet — images must already exist at the path a `DisposableVm`'s `image` field names).

## Deploy order

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/crd.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl label node <node-name> ragnarok.io/fluxvm-capable=true
kubectl apply -f deploy/k8s/daemonset.yaml
```

`crd.yaml` is generated straight from the Rust type (`cargo run -p fluxvm-kube -- --print-crd`),
not hand-maintained — regenerate it whenever the CRD's Rust definition changes.

## Verifying it

```bash
kubectl -n fluxvm-system get pods -o wide
kubectl -n fluxvm-system logs ds/fluxvm-kube -c fluxvm-kube --follow
# On the node (or via port-forward to the fluxvm container):
# liveness  GET /healthz · readiness GET /readyz  (see deploy/k8s/README.md Probes)
curl -sf http://127.0.0.1:7788/readyz | jq .
```

Then create a test `DisposableVm` targeting the labeled node and watch `phase` move from
`Pending` to `Running` with a real `vmId` populated — see `deploy/k8s/README.md`'s smoke test for
the full manifest. Deleting the object is finalizer-gated: `kubectl delete` blocks until the real
VM is torn down, so a brief pause there is expected, not a hang.

## DisposableVm vs MicroVM

| | **DisposableVm** (`fluxvm-kube`) | **MicroVM** (`fluxvm-microvm`) |
|---|---|---|
| API | `fluxvm.zyvor.io` | `microvm.fluxvm.zyvor.io` |
| Placement | Explicit `spec.node` (optional placer) | kube-scheduler via shadow Pod |
| Where the VMM runs | Host `fluxvm serve` | Host `fluxvm serve` (same DaemonSet) |
| Extra kinds | — | `MicroVMJob`, `MicroVMPool`, `GuestImage` (host-file Ready) |

Deploy MicroVM **after** this DaemonSet: `kubectl apply -f deploy/k8s/microvm/`.
Full guide: [microvm.md](../microvm.md). Tutorials:
[tutorials/microvm/](../tutorials/microvm/README.md). Deploy leaves `--convert`
**off**; opt in with `fluxvm-microvm controller --convert` (converted MicroVMs
get `driven-by=fluxvm-kube` so the node agent does not double-create VMs).
Shadow Pods request `10m`/`32Mi` only.

## Known limitations

- **Networking**: MicroVM CRD maps `networkMode` `none` / `user` / `tap` /
  `macvtap` through to `fluxvm serve`. Bridged TAP still needs the bridge/TAP
  present on the scheduled node and a clear story with the DaemonSet's
  `hostNetwork: true` vs cluster CNI — validate per site before production.
- **No scheduler on DisposableVm**: whatever creates `DisposableVm` objects —
  e.g. [Ragnarok](/docs/ragnarok-manual) — picks `spec.node`. For
  scheduler-driven placement, use MicroVM instead (above).
- **No CDI image pull**: stage disks on each capable node (or use GuestImage
  Ready when the host file exists).

## Ragnarok product path

1. Deploy FluxVM CRD + DaemonSet (this page).
2. Install [Ragnarok](/docs/ragnarok) (KubeVirt required for the main fleet; FluxVM is opt-in).
3. Optional: wire Ragnarok OIDC/SSO (`--with-oidc`) — identity stays on Ragnarok; FluxVM does not terminate browser SSO.
4. Open Ragnarok → [FluxVM VMs](/docs/ragnarok-manual/pages/compute/fluxvm-vms). Missing operator → explicit banner, not a silent empty page.

User manuals: [FluxVM](/docs/fluxvm-manual) · [Ragnarok](/docs/ragnarok-manual).

## Next steps

- [Admin basics](admin-basics.md)
- [Configuration](configuration.md)
- [Use cases](use-cases.md)

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

