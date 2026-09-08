# Admin basics

Operate FluxVM on a host: service, ports, auth, logs, and production gates.

## Service

```bash
sudo systemctl enable --now fluxvm    # if unit installed by deploy
# or foreground:
sudo fluxvm --config /etc/fluxvm.toml serve
```

TTL reaper and warm-pool backfill run only while `serve` is up.

## Host dependencies

```bash
./scripts/bootstrap-host.sh
# Windows offline customize needs libhivex + nbd:
sudo modprobe nbd max_part=16
```

Remote: `./scripts/deploy-remote.sh USER@HOST`.

## Ports

| Port | Role |
|------|------|
| **7788** | FluxVM REST (`fluxvm serve`) |
| **9108** | Optional MicroVM Prometheus (`MICROVM_METRICS_ADDR`) |

Fabric (separate product) typically listens on **9095** and proxies FluxVM.

## Health

```bash
curl -sf http://127.0.0.1:7788/healthz
curl -sf http://127.0.0.1:7788/readyz | jq .
```

Both are auth-exempt. Use `/readyz` when dataplane must be ready before work.

## Auth (opt-in)

Default: open API (every request is admin). Before exposing beyond localhost:

```toml
[auth]
require = true

[[auth.tokens]]
token = "replace-me"
role = "admin"
name = "ops"
# tenant = "team-a"   # optional scope
```

```bash
curl -sf -H "Authorization: Bearer replace-me" http://127.0.0.1:7788/v1/vms
```

List/filter: `GET /v1/vms?tenant=team-a`. See [PRODUCTION.md](../PRODUCTION.md)
and [SECURITY.md](../../SECURITY.md).

## State and logs

| Path | Role |
|------|------|
| `<state_dir>/vms.json` | VM inventory (flock via `vms.lock`) |
| `<state_dir>/instances/<uuid>/console.log` | Per-VM console |
| `journalctl -u fluxvm -f` | Daemon journal |

## Production checklist

```bash
./scripts/release-checklist.sh
```

- [PRODUCTION.md](../PRODUCTION.md)
- [examples/create-vm-prod.json](../../examples/create-vm-prod.json)
- [production tutorials](../tutorials/production/README.md)

## Related

- [Getting started](getting-started.md)
- [Configuration](configuration.md)
- [Common workflows](workflows.md)
- [Kubernetes deployment](kubernetes-deployment.md)
