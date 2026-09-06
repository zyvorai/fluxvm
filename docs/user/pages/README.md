# Page-by-page guides

Each guide follows: Purpose → When to use it → How to get there → What you can do → Related pages.

Every route is also listed in the [complete page index](../PAGE_INDEX.md).

## Admin

| Page | What it covers |
|------|----------------|
| [Admin Basics](admin/admin-basics.md) | Deploy, systemd, ports, host prep, and operations. |

## Deploy

| Page | What it covers |
|------|----------------|
| [Kubernetes Deployment](deploy/kubernetes-deployment.md) | DaemonSet / DisposableVm CRD operator path. |

## Images

| Page | What it covers |
|------|----------------|
| [Build Custom Images](images/build-image-tutorial.md) | Build and customize Linux or Windows guest images (GuestKit). |

## Integrations

| Page | What it covers |
|------|----------------|
| [Ragnarok Integration](integrations/ragnarok-integration.md) | Drive FluxVM disposable VMs from Ragnarok UI + SSO. |

## Onboarding

| Page | What it covers |
|------|----------------|
| [Getting Started](onboarding/getting-started.md) | Install FluxVM and boot your first disposable VM. |
| [Use Cases](onboarding/use-cases.md) | Concrete scenarios — CI runners, golden images, fleets, sandboxes. |

## Operations

| Page | What it covers |
|------|----------------|
| [Workflows](operations/workflows.md) | Day-to-day create / exec / pause / TTL / warm-pool jobs. |

## Setup

| Page | What it covers |
|------|----------------|
| [Configuration](setup/configuration.md) | Backends, storage, auth, policy, and agent settings. |

---

8 guides. Regenerate: `node scripts/user-docs/generate-guide-index.mjs`.
