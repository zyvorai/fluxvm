# Configuration

## Purpose

Backends, storage, auth, policy, and agent settings.

## How to get there

- Topic id: `configuration`
- Section: **Setup → Configuration**

## Guide

FluxVM is configured through one TOML file (`/etc/fluxvm.toml` by default, or `--config <path>`), plus per-VM fields on each create request.

## Backend and storage binaries

The `[global]`-level keys point at the VMM and storage tool binaries — `qemu_binary`, `qemu_img_binary`, `cloud_hypervisor_binary`, `ch_remote_binary`, `firecracker_binary`, and related paths. Defaults resolve from `$PATH`; set them explicitly if a binary lives somewhere nonstandard.

## Storage backends

Every create request may set `"storage"` to switch how that VM's disk is provisioned — the default (unset) is a qcow2 CoW overlay for QEMU or a reflinked raw file for Cloud Hypervisor/Firecracker, and needs no extra configuration:

| Value | What it needs |
|-------|----------------|
| `lvm-thin` | `image` must be a `/dev/<vg>/<lv>` path to an existing LVM thin logical volume |
| `nbd` | QEMU only — no extra config; a `qemu-nbd` subprocess is spawned automatically |
| `ceph-rbd` | A `[storage]` section with `ceph_user`/`ceph_conf`; `image` is a `pool/image` reference with a protected `fluxvm-base` snapshot already on it |

## Isolation and resource control

- **Firecracker jailer** — a `[jailer]` section (`enabled`, `uid`, `gid`, `chroot_base_dir`) switches every Firecracker VM to launch through `jailer` instead of directly.
- **Network namespaces** — set `netns: true` on a request's `network` block to give that VM its own namespace instead of sharing the host bridge.
- **Sandbox dataplane (optional)** — default remains nftables; set `[sandbox.dataplane]` to `ebpf` or `cilium` for native TC/eBPF IPv4/IPv6 L3+L4 policy, rate limits, stats/flows/status, and optional XDP (Network Fabric v3). See [Network Fabric](../../../network-fabric.md) and [eBPF / Cilium](../../../ebpf-cilium.md).
- **cgroup v2 resource control** applies automatically to every VM; use the REST API's `/resources` endpoint or the CLI to set CPU/memory/IO/pids/cpuset limits after creation.

## Auth

An empty `[auth]` section (the default) leaves the REST API open — every request is treated as admin. Add one or more `[[auth.tokens]]` entries (`token`, `role: "admin" | "read-only"`) to require a bearer token on every request except `/healthz`.

## Policy (admission limits)

An optional `[policy]` section caps `max_vcpus`, `max_memory_mib`, `max_disk_gib`, `max_ttl_seconds`, `allowed_backends`, and `allowed_image_dirs` — every field defaults to unrestricted.

## Troubleshooting

- **A `storage=ceph-rbd` create fails immediately** — confirm `[storage].ceph_conf` points at a real `ceph.conf`, the referenced pool/image exists, and it has a protected snapshot named `fluxvm-base`.
- **Auth returns 401 on every request** — a token is configured but wasn't sent, or doesn't match; requests need `Authorization: Bearer <token>`.
- **A policy-restricted create is rejected** — the response's error message names exactly which `[policy]` limit was exceeded.

## Next steps

- [Getting started](../onboarding/getting-started.md)
- [Common workflows](../operations/workflows.md)
- [Admin basics](../admin/admin-basics.md)

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

## Related pages

- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
