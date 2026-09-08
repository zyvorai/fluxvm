# Configuration

## Purpose

Backends, storage, auth, admission policy, Network Fabric, and Service Fabric
settings in `/etc/fluxvm.toml`.

## When to use it

- First secure install (`[auth] require = true`)
- Switching storage backends or enabling eBPF dataplane
- Caping vCPU/memory/TTL with `[policy]`

## How to get there

- Topic id: `configuration`
- Section: **Setup → Configuration**
- Full tutorial: [configuration.md](../../configuration.md)

## Guide

1. Copy `config.example.toml` → `/etc/fluxvm.toml`
2. Set `[[auth.tokens]]` before binding beyond localhost
3. Optional `[policy]` admission caps
4. Optional `[sandbox.dataplane] mode = "ebpf"` (Network Fabric schema v4)
5. Optional `[sandbox.dataplane.service]` for Service Fabric Maglev (v6)
6. Restart `serve` and check `/readyz`

Operator deep-dives: [network-fabric.md](../../../network-fabric.md) ·
[service-fabric.md](../../../service-fabric.md) ·
[PRODUCTION.md](../../../PRODUCTION.md).

## Related pages

- [Getting Started](../onboarding/getting-started.md)
- [Admin Basics](../admin/admin-basics.md)
- [Workflows](../operations/workflows.md)
- [Page index](../../PAGE_INDEX.md)
