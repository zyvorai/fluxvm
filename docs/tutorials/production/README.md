# Production readiness tutorials (FluxVM)

Short guides for the **host-local production bar** — auth, `/readyz`, tenant
IDs — alongside the dataplane runbook.

| Tutorial | Focus | Time |
|----------|-------|------|
| [01 — Readyz, tenant, and auth](01-readyz-tenant-auth.md) | Probes, create with tenant, token inheritance | ~15 min |

Also read:

- [PRODUCTION.md](../../PRODUCTION.md) — whole-stack checklist
- [production-dataplane.md](../../production-dataplane.md) — Network Fabric ops
- [SECURITY.md](../../../SECURITY.md) · [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- Network policy series: [../network-policy/](../network-policy/README.md)
- MicroVM (k8s scheduled guests): [../microvm/](../microvm/README.md) · [microvm.md](../../microvm.md)

Validate locally:

```bash
./scripts/release-checklist.sh
python3 scripts/test-project-production.py
```
