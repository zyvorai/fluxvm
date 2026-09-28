# Getting started

Clone, build, install and run your first VM, plus the day-2 verbs and the network modes.

[Back to README](../README.md)

## Quick start

```bash
git clone https://github.com/zyvorai/fluxvm.git
cd fluxvm
```

`fluxvm-image` depends on a sibling [`guestkit`](https://github.com/zyvorai/guestkit) checkout
(clone it next to `fluxvm`, i.e. path `../../../guestkit` from `crates/fluxvm-image`).

```bash
# 1. Prepare the host once — packages, Cloud Hypervisor, Firecracker, a bridge.
sudo ./scripts/bootstrap-host.sh vmbr0
./scripts/preflight.sh                    # confirm every tool is on PATH

# 2. Build (current stable Rust toolchain) and install the CLI.
cargo build --release
sudo install -m 0755 target/release/fluxctl /usr/local/bin/fluxctl
sudo install -m 0755 target/release/fluxvm-hypervisor /usr/local/bin/fluxvm-hypervisor
sudo install -m 0644 config.example.toml /etc/fluxvm.toml

# 3. Run a VM — edit examples/qemu.json to point at your base image + SSH pubkey.
sudo fluxctl --config /etc/fluxvm.toml create --spec examples/qemu.json

# Day-2
fluxctl list
fluxctl get <id>                 # includes guest_ip for netns mode
fluxctl exec <id> -- hostname
fluxctl ping <id>                            # health-check the vsock guest agent
fluxctl copy-to <id> ./local.txt /etc/app.cfg
fluxctl copy-from <id> /etc/app.cfg ./local.txt
fluxctl migrate start <id> --destination tcp:10.0.0.9:49152   # QEMU/CH source-side live migration
fluxctl migrate status <id>      # QEMU only -- Cloud Hypervisor's send-migration is fire-and-forget
fluxctl pause <id> && fluxctl resume <id>
fluxctl freeze <id> && fluxctl frozen <id> && fluxctl thaw <id>  # cgroup-level, independent of the VMM's own API
fluxctl restart <id> && fluxctl wait <id> --for running
fluxctl label <id> env=dev fluxvm.io/snapshot-every=6h fluxvm.io/snapshot-keep=4  # `key-` removes
fluxctl list -l env=dev && fluxctl stop -l env=dev
fluxctl clone-vm <stopped-id> web-2         # copies data disks + labels
fluxctl disk attach <id> data --size-gib 10 && fluxctl disk resize <id> root --size-gib 40
fluxctl serial <id>                         # QEMU serial console, Ctrl-] quits
fluxctl backup <id> --all-disks --compress  # live when running
fluxctl vm-template save base --from-vm <id> && fluxctl vm-template create base web-3
fluxctl events -f                           # lifecycle event stream
fluxctl delete <id>              # or wait for ttl_seconds

# Remote daemon (same verbs)
fluxctl context add lab --server http://10.0.0.5:7788 --token "$TOKEN" && fluxctl context use lab
```

Day-2 details (scheduled snapshots, disks, backup, templates, contexts):
[docs/operations.md](operations.md#day-2-vm-operations).

`cargo build --release` also produces `fluxvm-kube`, `fluxvm-agent`, `containerd-shim-fluxvm-v2`,
and `fluxvm-container-agent` — see [Feature highlights](index.md#feature-highlights) for what each is.

**Pick a network mode:**

| Mode | Spec sketch | Guest IP |
|------|-------------|----------|
| Lab / SSH | `"network": {"mode":"user","forwards":[{"host_port":2222,"guest_port":22}]}` | QEMU SLIRP DHCP; SSH via `localhost:2222` |
| LAN DHCP | `"network": {"mode":"tap","bridge":"vmbr0","mac":"06:…"}` | Your bridge's DHCP |
| Known IP | `"network": {"mode":"tap","netns":true,"mac":"06:…"}` | FluxVM dnsmasq; see `fluxctl get` |
| L2 macvtap | `"network": {"mode":"macvtap","parent":"eth0","mac":"06:…"}` | Your L2 / static via cloud-init |
| Bridge-less direct (opt-in) | `"network": {"mode":"tap","mac":"06:…","direct":{"outer":"eth0","mode":"l2-uplink","guest_ips":["…"]}}` | Your L2 / static; eBPF redirect instead of a bridge — [docs/direct-datapath.md](direct-datapath.md) |

Full examples: [`examples/qemu.json`](../examples/qemu.json) (user-mode lab),
[`examples/create-vm-prod.json`](../examples/create-vm-prod.json) (tenant + tap/netns),
[`examples/guestkit-handoff.json`](../examples/guestkit-handoff.json) (post-GuestKit netns + known IP),
[`examples/macvtap.json`](../examples/macvtap.json). Full JSON contract:
[docs/api.md](api.md#vm-json-contract). Verify your build end to end with
`sudo ./scripts/test-networking.sh` and `sudo ./scripts/test-lifecycle.sh` — see
[docs/operations.md](operations.md#testing-networking-and-lifecycle-end-to-end). Deploying to a
remote host: [docs/operations.md](operations.md#deploy-to-a-remote-host).
