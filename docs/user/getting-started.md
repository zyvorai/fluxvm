# Getting started

FluxVM is a Rust control plane for disposable VMs — it needs a Linux x86_64 host with `/dev/kvm` available, and at least one of `qemu-system-x86_64`, Cloud Hypervisor, or Firecracker installed.

## Prerequisites

- A Linux x86_64 host with virtualization enabled and `/dev/kvm` present.
- A Rust toolchain (`cargo`) to build from source.
- `qemu-system-x86_64` and `qemu-img` at minimum; Cloud Hypervisor and Firecracker are optional per-backend.

## 1. Build and install

```bash
cargo build --release
sudo install -m 0755 target/release/fluxvm /usr/local/bin/fluxvm
sudo install -m 0644 config.example.toml /etc/fluxvm.toml
```

A one-command host bootstrap script (`scripts/bootstrap-host.sh`) installs the system packages, Cloud Hypervisor, and Firecracker for you; `scripts/deploy-remote.sh` does the same over SSH to a remote host.

## 2. Create your first VM

```bash
fluxvm create --spec examples/qemu.json
```

The response is the VM's full record — id, status, disk path, PID. It boots from a disposable copy-on-write overlay of the base image named in the spec, so the base image itself is never modified.

## 3. Run something inside it

```bash
fluxvm exec <id> -- echo hello
```

This runs over the vsock guest agent — no SSH, no network path required at all, as long as the guest image has the agent installed and `agent.enabled: true` was set on the create request.

For **Windows** guests (QEMU + GuestKit agent), use `"qga": {"enabled": true}` on create and `fluxvm qga …` instead of vsock `exec` — see [Building custom OS images](build-image-tutorial.md#windows-images).

## 4. Let it clean up on its own

Set `ttl_seconds` on the create request and FluxVM's TTL reaper deletes the VM automatically once it expires — or delete it yourself:

```bash
fluxvm delete <id>
```

## Troubleshooting

- **`create` fails with "base image does not exist"** — the `image` path in the spec must exist on the host running `fluxvm`, and (for the `ceph-rbd`/`lvm-thin` storage backends) follow their specific reference format — see [Configuration](configuration.md).
- **`exec` hangs or fails** — confirm the create request set `"agent": {"enabled": true}` and the guest image actually has `fluxvm-guest-agent` installed and running.
- **`qga` fails on Windows** — confirm `"qga": {"enabled": true}`, backend is `qemu`, and the GuestKit Windows agent was injected (`windows.agent` at build-image time).
- **`/dev/kvm` missing** — enable virtualization in the host's BIOS/hypervisor, and confirm the current user is in the `kvm` group or run as root.

## Next steps

- [Configuration](configuration.md)
- [Common workflows](workflows.md)
- [Admin basics](admin-basics.md)

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

