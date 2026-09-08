# Configuration

FluxVM is configured through one TOML file (`/etc/fluxvm.toml` by default, or
`--config <path>`), plus per-VM fields on each create request.

## Tutorial: minimal secure host

1. Copy the example and set binaries if they are not on `$PATH`:

```bash
sudo cp config.example.toml /etc/fluxvm.toml
```

2. Enable bearer auth (required before binding beyond localhost):

```toml
[auth]
require = true

[[auth.tokens]]
token = "ops-token"
role = "admin"
name = "ops"
```

3. Optional admission caps:

```toml
[policy]
max_vcpus = 8
max_memory_mib = 16384
max_disk_gib = 100
max_ttl_seconds = 86400
allowed_backends = ["qemu", "cloud-hypervisor", "firecracker"]
```

4. Restart `fluxvm serve` and verify:

```bash
curl -sf -H "Authorization: Bearer ops-token" http://127.0.0.1:7788/readyz | jq .
```

## Backend binaries

`[global]` keys: `qemu_binary`, `qemu_img_binary`, `cloud_hypervisor_binary`,
`ch_remote_binary`, `firecracker_binary`. Defaults resolve from `$PATH`.

## Storage backends

Unset `storage` → qcow2 CoW (QEMU) or reflinked raw (CH/Firecracker).

| Value | Needs |
|-------|--------|
| `lvm-thin` | `image` = `/dev/<vg>/<lv>` thin LV |
| `nbd` | QEMU only; `qemu-nbd` spawned automatically |
| `ceph-rbd` | `[storage]` with `ceph_user` / `ceph_conf`; `image` = `pool/image` with protected `fluxvm-base` snapshot |

## Isolation and dataplane

- **Firecracker jailer** — `[jailer]` (`enabled`, `uid`, `gid`, `chroot_base_dir`)
- **Network namespaces** — `network.netns: true` on create
- **Network Fabric (schema v4)** — `[sandbox.dataplane] mode = "ebpf"` or `"cilium"` for TC/eBPF L3+L4, groups/CNP, flows. Docs: [network-fabric.md](../network-fabric.md), [network-policy.md](../network-policy.md), [production-dataplane.md](../production-dataplane.md)
- **Service Fabric (v6 / schema 4)** — `[sandbox.dataplane.service]` north-south interfaces, Maglev VIP LB. Doc: [service-fabric.md](../service-fabric.md)
- **cgroup v2** — automatic; tune via `/resources` or CLI after create

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ceph-rbd` create fails | Valid `ceph.conf`, pool/image exists, protected `fluxvm-base` snapshot |
| Every request 401 | Send `Authorization: Bearer <token>` matching `[[auth.tokens]]` |
| Policy reject | Error names the `[policy]` limit that fired |

## Related

- [Getting started](getting-started.md)
- [Common workflows](workflows.md)
- [Admin basics](admin-basics.md)
- [PRODUCTION.md](../PRODUCTION.md)
- [SECURITY.md](../../SECURITY.md)
