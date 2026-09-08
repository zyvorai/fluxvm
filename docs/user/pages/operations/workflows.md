# Workflows

## Purpose

Day-to-day create / exec / pause / TTL / warm-pool / Windows QGA / dataplane /
Service Fabric jobs.

## When to use it

- You already completed [Getting Started](../onboarding/getting-started.md)
- You need a short recipe (pool, image build, fleet, K8s, Maglev)

## How to get there

- Topic id: `workflows`
- Section: **Operations → Workflows**
- Full tutorial: [workflows.md](../../workflows.md)

## Guide

| Workflow | Steps |
|----------|-------|
| CI/sandbox VM | `fluxvm create` + `ttl_seconds` → `fluxvm exec` → delete or TTL reaper |
| Warm pool | `fluxvm pool create` → `fluxvm pool claim` |
| Image build | `fluxvm build-image` — [build-image-tutorial](../images/build-image-tutorial.md) · [Kryton](../../../windows-golden.md) |
| Windows + QGA | `build-image` windows{} → `create` windows-qga → `fluxvm qga …` |
| Fleet | `fluxvm-agent central` + `node` → `POST /fleet/vms` |
| Kubernetes | DisposableVm CRD + `fluxvm-kube` — [kubernetes-deployment](../deploy/kubernetes-deployment.md) |
| Network Fabric v4 | `mode=ebpf` + bridged VM — [network-policy tutorials](../../../tutorials/network-policy/README.md) |
| Service Fabric v6 | `POST /v1/network/services` — [service-fabric.md](../../../service-fabric.md) |

## Related pages

- [Getting Started](../onboarding/getting-started.md)
- [Use Cases](../onboarding/use-cases.md)
- [Admin Basics](../admin/admin-basics.md)
- [Page index](../../PAGE_INDEX.md)
