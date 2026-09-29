---
name: fluxvm-cli
description: Drive FluxVM with fluxctl. Use when asked to create, list, exec into, pause, resume or delete a VM, or to pick a backend (QEMU, Cloud Hypervisor, Firecracker, flux-vm).
---

# fluxctl

Reference: `README.md` (quick start), `docs/api.md`, `docs/getting-started.md`.

```bash
sudo fluxctl create --spec examples/qemu.json   # boot a VM from a JSON spec
fluxctl list                                    # every VM, every backend
fluxctl exec <id> -- hostname                   # run a command over vsock, no SSH
fluxctl pause <id> && fluxctl resume <id>
fluxctl delete <id>                             # or set ttl_seconds in the spec
```

- Specs live in `examples/` (`qemu.json`, `firecracker.json`, `cloud-hypervisor.json`, `fluxvm.json`, ...). Start from the closest one and change only what is needed.
- `"backend": "auto"` lets FluxVM pick. `flux-vm` is the in-tree hypervisor and the AI-agent sandbox path (`docs/agent-sandbox-gaps.md`).
- Pass a config with `fluxctl --config /etc/fluxvm.toml ...`. `fluxctl serve` runs the REST API.

## Rules

- `create` needs root on the host. Say so before running it, and do not run it on a machine the user did not name.
- Do not delete a VM you did not create in this session without asking.
- Do not print tokens or keys from the config file.
