# Common workflows

Day-to-day FluxVM jobs — create, exec, pools, images, Windows, dataplane, and
Kubernetes — as short copy-paste tutorials.

**Prerequisites:** [Getting started](getting-started.md). Commands assume
`fluxvm` on `PATH` and `/etc/fluxvm.toml` (or `--config`).

## 1. CI / sandbox VM with TTL

```bash
# examples/qemu.json plus ttl_seconds in the JSON, or:
fluxvm create --spec examples/qemu.json
ID=…   # from response
fluxvm exec "$ID" -- ./run-tests.sh
fluxvm delete "$ID"
# Or set "ttl_seconds": 900 on create and let the reaper delete it
```

`fluxvm serve` must be running for the TTL reaper.

## 2. Warm pool (fast claim)

```bash
fluxvm pool create --name ci --template examples/qemu.json --size 4
fluxvm pool claim --name ci    # returns a paused, ready VM
# resume / exec / delete as usual
```

Claim latency is roughly resume time, not cold boot.

## 3. Build a reusable golden image

Linux:

```bash
sudo modprobe nbd max_part=16
sudo fluxvm build-image --spec examples/build-image.json
```

Windows (Kryton golden → offline customize):

```bash
./scripts/prepare-windows-golden.sh --build --version 11e
sudo fluxvm build-image --spec examples/build-image-kryton-golden.json
```

Full walkthrough: [build-image-tutorial.md](build-image-tutorial.md) ·
[windows-golden.md](../windows-golden.md) · [tiny-windows.md](../tiny-windows.md).

## 4. Windows lab VM + QGA

```bash
sudo fluxvm build-image --spec examples/build-image-windows.json
fluxvm create --spec examples/windows-qga.json
fluxvm qga ping <id>
fluxvm qga firewall-open <id> --name Lab --port 8080 --protocol tcp
```

QEMU only for this path. Do not use vsock `fluxvm exec` for Windows.

## 5. Multi-host fleet

```bash
# central once
fluxvm-agent central
# each node
fluxvm-agent node
# place without pinning a node
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @examples/qemu.json http://127.0.0.1:7788/fleet/vms
```

## 6. Kubernetes DisposableVm

```bash
kubectl apply -f deploy/crd/
# run fluxvm-kube DaemonSet / operator per node
kubectl apply -f examples/disposablevm.yaml
```

See [Kubernetes deployment](kubernetes-deployment.md) and
[MicroVM tutorials](../tutorials/microvm/README.md).

## 7. Network Fabric edge policy (schema v4)

```bash
# /etc/fluxvm.toml: [sandbox.dataplane] mode = "ebpf"
fluxvm create --spec examples/create-vm-prod.json   # network_tap / netns
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:7788/v1/vms/$ID/network/status | jq .
```

Hands-on: [network-policy tutorials](../tutorials/network-policy/README.md) ·
operator: [network-fabric.md](../network-fabric.md).

## 8. Service Fabric Maglev VIP (v6 / schema 4)

```bash
curl -sS -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @docs/examples/service-fabric-v4-east-west.json \
  http://127.0.0.1:7788/v1/network/services
curl -sS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:7788/v1/network/services/status | jq .
```

Identity policy example: `examples/service-fabric-v6/`. Operator guide:
[service-fabric.md](../service-fabric.md).

## 9. Production readiness

```bash
curl -sf http://127.0.0.1:7788/readyz | jq .
./scripts/release-checklist.sh
```

Tutorial: [production/01-readyz-tenant-auth.md](../tutorials/production/01-readyz-tenant-auth.md).

## Related

- [Use cases](use-cases.md)
- [Admin basics](admin-basics.md)
- [Configuration](configuration.md)
- [CLI & API](using-the-dashboard.md)
- [Page index](PAGE_INDEX.md)
