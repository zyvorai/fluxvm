# MicroVM tutorials (FluxVM)

Short, copy-paste guides for scheduled MicroVMs on Kubernetes — shadow Pods,
node agent, Jobs, warm pools, GuestImage catalog, and the DisposableVm bridge.

API group: `microvm.fluxvm.zyvor.io`. Controllers: `fluxvm-system`. Design:
[microvm.md](../../microvm.md).

| Tutorial | Focus | Time |
|----------|-------|------|
| [01 — Getting started](01-getting-started.md) | CRDs, deploy, first MicroVM, phases | ~15 min |
| [02 — MicroVMJob](02-job.md) | Run-to-completion + vsock command | ~15 min |
| [03 — MicroVMPool](03-pool.md) | Warm pool + claimFrom | ~15 min |
| [04 — Convert DisposableVm](04-convert-disposablevm.md) | `controller --convert` (opt-in) | ~10 min |
| [05 — GuestImage](05-guestimage.md) | Host-file Ready + catalog `spec.image` | ~10 min |

## Prerequisites

1. Linux nodes with KVM and images staged under `/var/lib/fluxvm/images` (or your
   `state_dir`).
2. `fluxvm-kube` DaemonSet running so `fluxvm serve` is on `127.0.0.1:7788`
   ([deploy/k8s/README.md](../../../deploy/k8s/README.md)).
3. Nodes labeled `ragnarok.io/fluxvm-capable=true`.
4. `fluxvm-microvm` binary (or image `ghcr.io/zyvorai/fluxvm` with that entrypoint).

## CLI cheat sheet

| Task | Command |
|------|---------|
| Print CRDs | `fluxvm-microvm --print-crd` |
| Apply MicroVM stack | `kubectl apply -f deploy/k8s/microvm/` |
| List guests | `kubectl get mvm -A` |
| Watch phase | `kubectl get mvm <name> -w` |
| Jobs / pools | `kubectl get mvmj,mvmp -A` |
| GuestImages | `kubectl get gimg -A` |
| Controller logs | `kubectl -n fluxvm-system logs deploy/fluxvm-microvm-controller` |
| Node agent logs | `kubectl -n fluxvm-system logs ds/fluxvm-microvm-node` |
| Local fluxvm health | `curl -sf http://127.0.0.1:7788/readyz` |

## Automated checks

```bash
cargo test -p fluxvm-microvm
./scripts/test-microvm.sh
python3 scripts/test-microvm-policy.py
# lab k3s (shadow budget, driven-by, GuestImage Ready+resolve):
./scripts/test-microvm-k8s-smoke.sh
```
