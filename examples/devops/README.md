# DevOps examples (FluxVM)

FluxVM is the VM engine Fabric drives at `127.0.0.1:7788`. DevOps jobs should gate on `/healthz` and `/readyz`, never on “process exists”.

## Unit (no KVM)

```bash
python3 -m unittest examples.devops.test_contract examples.devops.test_examples
bash scripts/test-devops-gate.sh
bash scripts/test-upgrade-snapshot.sh
```

## Live node

```bash
sudo ./scripts/bootstrap-host.sh
# fluxvm serve --config /etc/fluxvm.toml
export FLUXVM_URL=http://127.0.0.1:7788
export FABRIC_URL=http://127.0.0.1:9095   # optional sibling
ZYVOR_CHECK_FLUXVM=1 bash scripts/devops-gate.sh
```

Create a guest from the production spec:

```bash
fluxvm --config /etc/fluxvm.toml create --spec examples/create-vm-prod.json
```

## GitOps packaging

`deploy/k8s/gitops` is a kustomize wrapper around `deploy/k8s` DaemonSet. It does not replace Fabric’s operator — it only runs FluxVM on capable nodes.

## Upgrade pairing with Fabric

```bash
sudo ./scripts/upgrade-snapshot.sh snapshot --tag before-fabric-0.3
# install new fluxvm
./scripts/upgrade-snapshot.sh verify
# then Fabric upgrade-rollback.sh snapshot/verify
```

Contract: [docs/contracts/fabric-fluxvm-readyz.json](../../docs/contracts/fabric-fluxvm-readyz.json).
