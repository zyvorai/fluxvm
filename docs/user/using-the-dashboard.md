# Using FluxVM (CLI & API)

FluxVM is primarily a **CLI + REST** control plane (no first-party web console). Day-to-day work uses `fluxvm` on the host, or the HTTP API the same binary serves.

## CLI essentials

```bash
fluxvm create --spec examples/qemu.json
fluxvm list
fluxvm exec <id> -- echo hello
fluxvm qga ping <id>   # Windows / QEMU GuestKit agent (requires qga.enabled)
fluxvm delete <id>
```

## REST surface

The control plane exposes HTTP endpoints for create/list/get/delete/exec,
QGA (`/v1/vms/{id}/qga/…`), and related lifecycle calls. Point clients
(including Ragnarok and Zyvor Fabric) at the configured listen address.

## Where to go next

| Job | Doc |
|-----|-----|
| First VM | [Getting Started](getting-started.md) |
| Backend & storage | [Configuration](configuration.md) |
| Common jobs | [Workflows](workflows.md) |
| Host / systemd | [Admin Basics](admin-basics.md) |
| Full topic index | [PAGE_INDEX.md](PAGE_INDEX.md) |

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

