# Using FluxVM in DevOps

FluxVM is the sibling engine under [zyvorai/fabric](https://github.com/zyvorai/fabric). Platform pipelines should:

1. Bootstrap the host (`scripts/bootstrap-host.sh` — KVM, nbd, dirs).
2. Run `fluxvm serve`.
3. Gate on `GET /healthz` (alive) and `GET /readyz` (state dir + dataplane when required).
4. Let Fabric (or `fluxvm create --spec`) be the only writer.

## Probes

| Path | Auth | Ready meaning |
|------|------|----------------|
| `/healthz` | no | process up (`{"ok": true}`) |
| `/readyz` | no | `ok` + optional `kvm`, `state_dir`, `dataplane`; HTTP 503 when not ready |

Fabric `GET /readyz` nests this body under `fluxvm` and will stay 503 until this endpoint is 200.

See [contracts/fabric-fluxvm-readyz.json](contracts/fabric-fluxvm-readyz.json).

## CI

- PR: `.github/workflows/devops-gates.yml` (no KVM).
- Image customize jobs already live in `.github/workflows/ci.yml`.
- Live KVM smoke stays on self-hosted runners (`scripts/test-boot-smoke.sh`, dataplane e2e).

## Lab verify

Post-deploy on a KVM host (pairs with Fabric HTTPS `:9095`):

```bash
sudo -E ./scripts/test-lab-verify.sh
# covers: devops units + live devops-gate + upgrade-snapshot +
#         four-tracks e2e + regression (readyz / KVM boot / sandbox / eBPF)
```

`scripts/devops-gate.sh` uses `curl -k` for Fabric self-signed TLS and auto-picks
`https://127.0.0.1:9095` when `FABRIC_URL` is unset.

## Kubernetes

DaemonSet in `deploy/k8s/` uses hostNetwork so Fabric on the same node can reach `127.0.0.1:7788`. GitOps wrapper: `deploy/k8s/gitops`.

## Upgrade with Fabric

Snapshot FluxVM **first**, then Fabric:

```bash
sudo ./scripts/upgrade-snapshot.sh snapshot --tag before-$VERSION
# install fluxvm
./scripts/upgrade-snapshot.sh verify
# on the Fabric repo:
#   sudo ./scripts/upgrade-rollback.sh snapshot --tag before-$VERSION
```

Examples: [examples/devops/README.md](../examples/devops/README.md).
