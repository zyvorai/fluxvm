# Getting started with FluxVM

Boot a disposable VM on a Linux KVM host — create, exec, and tear down —
using the FluxVM CLI and REST API.

**Level:** Beginner · **Time:** ~20 minutes

## What you need

- Linux x86_64 host with `/dev/kvm`
- `qemu-system-x86_64` + `qemu-img` (minimum); Cloud Hypervisor / Firecracker optional
- Rust toolchain (`cargo`) to build from source, **or** a prebuilt `fluxvm` binary

## 1. Install

```bash
cargo build --release
sudo install -m 0755 target/release/fluxvm /usr/local/bin/fluxvm
sudo install -m 0644 config.example.toml /etc/fluxvm.toml
```

One-shot host prep (packages, CH, Firecracker):

```bash
./scripts/bootstrap-host.sh
# remote: ./scripts/deploy-remote.sh USER@HOST
```

## 2. Start the API (optional for CLI-only create)

```bash
sudo fluxvm --config /etc/fluxvm.toml serve
curl -sf http://127.0.0.1:7788/healthz
curl -sf http://127.0.0.1:7788/readyz | jq .
```

`/healthz` is liveness; `/readyz` is readiness (auth-exempt). Prefer `/readyz`
when Network Fabric or Service Fabric must be up before admitting work.

## 3. Create your first VM

```bash
fluxvm create --spec examples/qemu.json
# Production-shaped (tenant + tap/netns):
# fluxvm create --spec examples/create-vm-prod.json
```

The response includes `id`, status, disk path, and PID. The guest boots from a
copy-on-write overlay — the base image is never modified. Optional `tenant` on
the JSON is filterable via `GET /v1/vms?tenant=`.

## 4. Run a command inside the guest

Linux (vsock guest agent — no SSH required):

```bash
fluxvm exec <id> -- echo hello
```

Requires `"agent": {"enabled": true}` on create and `fluxvm-guest-agent` in the
image.

Windows (QEMU + GuestKit / QGA):

```bash
fluxvm create --spec examples/windows-qga.json
fluxvm qga ping <id>
fluxvm qga powershell <id> -- 'Get-ComputerInfo | Select-Object CsName'
```

See [Building custom OS images](build-image-tutorial.md#windows-images) and
[Windows Kryton goldens](../windows-golden.md).

## 5. Clean up

TTL auto-delete:

```json
{ "ttl_seconds": 600 }
```

Or delete yourself:

```bash
fluxvm delete <id>
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `base image does not exist` | `image` path must exist on this host (or valid `ceph-rbd` / `lvm-thin` ref) — [Configuration](configuration.md) |
| `exec` hangs | Enable agent on create; confirm guest agent is installed |
| `qga` fails (Windows) | `"qga": {"enabled": true}`, backend `qemu`, GuestKit agent injected at build-image |
| `/dev/kvm` missing | Enable virt in BIOS; add user to `kvm` or run as root |

## Next tutorials

- [Common workflows](workflows.md) — TTL, warm pool, fleet, Windows, images
- [Configuration](configuration.md) — backends, auth, policy, dataplane
- [Admin basics](admin-basics.md) — systemd, ports, production gates
- [Network policy tutorials](../tutorials/network-policy/README.md)
- [MicroVM tutorials](../tutorials/microvm/README.md)
- [Production readiness](../tutorials/production/README.md)

## Related

- [Use cases](use-cases.md)
- [Page index](PAGE_INDEX.md)
- [PRODUCTION.md](../PRODUCTION.md)
