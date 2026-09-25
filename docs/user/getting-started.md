# Getting started with FluxVM

Boot a VM. Exec a command. Tear it down.

**Level:** Beginner · **Time:** ~20 minutes

## What you need

- Linux x86_64 with `/dev/kvm`
- `qemu-system-x86_64` + `qemu-img` (minimum)
- Rust (`cargo`) **or** a prebuilt `fluxctl` binary

## 1. Install

```bash
cargo build --release
sudo install -m 0755 target/release/fluxctl /usr/local/bin/fluxctl
sudo install -m 0644 config.example.toml /etc/fluxvm.toml
```

Host packages (optional one-shot):

```bash
./scripts/bootstrap-host.sh
```

## 2. Serve

```bash
sudo fluxctl --config /etc/fluxvm.toml serve
curl -sf http://127.0.0.1:7788/readyz | jq .
```

## 3. Create

```bash
fluxctl create --spec examples/qemu.json
fluxctl list
fluxctl exec <id> -- hostname
fluxctl delete <id>
```

The guest boots from a CoW overlay — the base image is never modified.

## Next

- Production auth and tenants → [PRODUCTION.md](../PRODUCTION.md)
- Network Fabric → [tutorials/network-policy](../tutorials/network-policy/README.md)
- More recipes → [workflows.md](workflows.md)
- Product story → [README](../../README.md)
