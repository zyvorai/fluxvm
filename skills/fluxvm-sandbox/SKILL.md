---
name: fluxvm-sandbox
description: Use FluxVM agent sandboxes. Use when asked to confine a process (procbox), see which files an agent changed, run a command and discard its effects (dry-run), or roll a sandbox VM back.
---

# Sandboxes

References: `docs/procbox.md`, `docs/procbox-backend.md`, `docs/sandbox-changes.md`, `docs/agent-sandbox-gaps.md`.

## Pick the boundary

- **microVM** (`backend: "flux-vm"`, Firecracker, Cloud Hypervisor, QEMU): use for hostile code or several tenants.
- **procbox**: rootless Landlock + seccomp around a process. It shares the host kernel, so it is a weaker boundary. Use it for code you mostly trust.

## GPUs

`gpus: N` on sandbox create passes N free GPUs through (VFIO). Use a QEMU-backed template; it is refused with `confidential` or `procbox`. A shortage is a 503, so retry later rather than loop. After creating, check `request.vfio_devices` in the returned record to be sure GPUs were assigned. See `docs/sandbox-gpus.md`.

## procbox

```bash
fluxvm-procbox probe                         # what this kernel can enforce
fluxvm-procbox run -r /usr -r /lib -r /bin -w /tmp/work --net-port 443 \
  -m 256M -P 200 -t 30 --clean-env --json -- python3 task.py
```

Anything not listed is denied. With no `--net-port` all TCP is denied. Exit codes: `124` timeout, `128+signal` killed, `2` sandbox error. Run `probe` first, and prefer strict mode over `--best-effort` unless the user accepts a weaker result.

## What did the agent change? (VM sandboxes)

```text
POST /v1/sandboxes/{id}/baseline   {"paths": ["/workspace"]}
POST /v1/sandboxes/{id}/changes    -> {"added": [...], "modified": [...], "deleted": [...]}
```

Both are admin-only and need the guest agent. They only report; nothing is reverted. To run something and discard it, use `POST /v1/sandboxes/{id}/dry-run`. To roll back on purpose, snapshot and `POST /v1/vms/{id}/restore`.
