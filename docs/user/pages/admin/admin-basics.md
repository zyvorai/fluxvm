# Admin Basics

## Purpose

Deploy, systemd, ports, host prep, auth, and production operations.

## When to use it

- Standing up `fluxvm serve` under systemd
- Enabling bearer tokens before exposing the API
- Debugging readiness / console logs

## How to get there

- Topic id: `admin-basics`
- Section: **Admin → Admin Basics**
- Full tutorial: [admin-basics.md](../../admin-basics.md)

## Guide

| Topic | Guidance |
|-------|----------|
| **Service** | `fluxvm serve` / systemd unit; TTL + pool backfill need serve |
| **Host deps** | `scripts/bootstrap-host.sh`; `nbd` + `libhivex` for Windows build-image |
| **Ports** | FluxVM REST **7788**; Fabric (if used) **9095** |
| **Health** | `curl -sf http://127.0.0.1:7788/healthz` · `/readyz` |
| **Logs** | `journalctl -u fluxvm -f`; `<state_dir>/instances/<uuid>/console.log` |
| **State** | `<state_dir>/vms.json` + `vms.lock` |
| **Auth** | Opt-in `[[auth.tokens]]`; `/healthz` and `/readyz` stay open |
| **Production** | [PRODUCTION.md](../../../PRODUCTION.md) · [production tutorials](../../../tutorials/production/README.md) |

## Related pages

- [Getting Started](../onboarding/getting-started.md)
- [Configuration](../setup/configuration.md)
- [Kubernetes Deployment](../deploy/kubernetes-deployment.md)
- [Page index](../../PAGE_INDEX.md)
