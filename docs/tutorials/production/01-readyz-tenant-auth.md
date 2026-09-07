# 01 — Readyz, tenant, and auth

**Time:** ~15 min · **Level:** Beginner · **Prereq:** `fluxvm serve` on loopback

Confirm liveness vs readiness, create a VM with a tenant, and filter the list.

## 1. Liveness vs readiness

```bash
curl -sf http://127.0.0.1:7788/healthz | jq .
# → {"ok": true}  (process up)

curl -sf http://127.0.0.1:7788/readyz | jq .
# → {"ok": true, "kvm": …, "state_dir": …, "dataplane": …}
```

Both routes work **without** a bearer token even when `[[auth.tokens]]` is set.
Use `/healthz` for liveness and `/readyz` for readiness (state dir + dataplane
when `[sandbox.dataplane] required = true`).

## 2. Create with an explicit tenant

```bash
curl -sS http://127.0.0.1:7788/v1/vms \
  -H 'content-type: application/json' \
  --data-binary @examples/create-vm-prod.json | jq '{id, name, request: {tenant, name}}'
```

Or a minimal body:

```bash
curl -sS http://127.0.0.1:7788/v1/vms \
  -H 'content-type: application/json' \
  -d '{
    "name": "web-1",
    "tenant": "acme",
    "backend": "qemu",
    "image": "/var/lib/fluxvm/images/base.qcow2",
    "vcpus": 1,
    "memory_mib": 512,
    "network": {"mode": "none"}
  }' | jq .
```

## 3. Filter by tenant

```bash
curl -sS 'http://127.0.0.1:7788/v1/vms?tenant=acme' | jq '.items[].name'
```

## 4. Token tenant inheritance (optional)

In `/etc/fluxvm.toml`:

```toml
[[auth.tokens]]
token = "REPLACE_ME_ADMIN_TOKEN"
role = "admin"
name = "ci"
tenant = "acme"
```

Restart `fluxvm`, then create **without** `"tenant"` in the body — the VM
inherits `acme` from the token. If the body sets a different `"tenant"`,
FluxVM returns **403**. Token-scoped callers only see and mutate their own
tenant’s VMs (other UUIDs → **404**).

```bash
curl -sS http://127.0.0.1:7788/v1/vms \
  -H "Authorization: Bearer REPLACE_ME_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"name":"from-token","backend":"qemu","image":"/var/lib/fluxvm/images/base.qcow2","network":{"mode":"none"}}' \
  | jq '.request.tenant'
```

## 5. Checklist

- [PRODUCTION.md](../../PRODUCTION.md)
- `./scripts/release-checklist.sh`
- Dataplane ops: [production-dataplane.md](../../production-dataplane.md)

## Next

[Network policy tutorials](../network-policy/README.md) · Fabric edge series
(when driving FluxVM through Fabric).
