# Getting Started

## Purpose

Install FluxVM and boot your first disposable VM — create, exec, and tear down.

## When to use it

- First install on a KVM host
- Validating `/readyz` before admitting workloads
- Teaching the create → exec → delete loop

## How to get there

- Topic id: `getting-started`
- Section: **Onboarding → Getting Started**
- Full tutorial: [getting-started.md](../../getting-started.md)

## Tutorial

Follow the step-by-step guide:

1. Build/install `fluxvm` and copy `/etc/fluxvm.toml`
2. Optional: `fluxvm serve` and check `http://127.0.0.1:7788/readyz`
3. `fluxvm create --spec examples/qemu.json`
4. `fluxvm exec <id> -- echo hello` (Linux) or `fluxvm qga …` (Windows)
5. `fluxvm delete <id>` or rely on `ttl_seconds`

Windows images: [build-image-tutorial](../images/build-image-tutorial.md) ·
[Kryton goldens](../../../windows-golden.md).

## Related pages

- [Use Cases](use-cases.md)
- [Workflows](../operations/workflows.md)
- [Configuration](../setup/configuration.md)
- [Admin Basics](../admin/admin-basics.md)
- [Page index](../../PAGE_INDEX.md)
