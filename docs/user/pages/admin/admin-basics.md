# Admin Basics

## Purpose

Deploy, systemd, ports, host prep, and operations.

## How to get there

- Topic id: `admin-basics`
- Section: **Admin → Admin Basics**

## Guide

| Topic | Guidance |
|-------|----------|
| **Service** | Run `fluxvm serve` under the provided systemd unit; the TTL reaper and pool backfill only run while `serve` is up |
| **Host deps** | `scripts/bootstrap-host.sh` / remote deploy install QEMU tooling, `nbd`, and `libhivex` (Windows offline customize). Load `nbd` before `build-image` |
| **Logs** | `journalctl -u fluxvm -f`; each VM also has its own console log under `<state_dir>/instances/<uuid>/console.log` |
| **State** | `<state_dir>/vms.json` is the source of truth, coordinated across concurrent `fluxvm` processes via an OS-level `flock` on `vms.lock` |
| **Security** | Bearer-token auth/RBAC is opt-in — configure `[[auth.tokens]]` (optional `tenant`) before exposing beyond localhost; filter with `GET /v1/vms?tenant=`; `extra_args` is an admin escape hatch |
| **Liveness / readiness** | `curl -sf http://127.0.0.1:7788/healthz` · `curl -sf http://127.0.0.1:7788/readyz` (auth-exempt) |
| **Production** | [PRODUCTION.md](../../../PRODUCTION.md) · `./scripts/release-checklist.sh` · [create-vm-prod.json](../../../../examples/create-vm-prod.json) · [production tutorials](../../../tutorials/production/README.md) |
| **Support** | [GitHub issues](https://github.com/zyvorai/fluxvm/issues) · [Contact Zyvor](/contact) for Enterprise |

See also [Getting started](../onboarding/getting-started.md) and [Configuration](../setup/configuration.md).

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

## Related pages

- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
