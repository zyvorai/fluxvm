# FluxVM on macOS (Apple silicon)

FluxVM's control plane (daemon, REST API, `fluxctl`, scheduler) builds and runs natively on macOS, with a new
**`vz` backend** that runs VMs on Apple's Virtualization.framework. It is a separate, smaller feature set than the
Linux backends: no KVM, TAP, eBPF, cgroups or network namespaces.

## What is verified

On an Apple M4 running macOS 27.2 (Xcode 27, Rust 1.98):

| Check | Result |
| --- | --- |
| `cargo build -p fluxctl`, `cargo build -p fluxvm-apple` | Builds; `fluxctl --version` runs |
| `cargo test -p fluxvm-core --lib` / `-p fluxvm-scheduler --lib` / `-p fluxvm-api --lib` | 70 / 171 / 56 passed |
| `cargo test -p fluxvm-network --lib`, `-p fluxvm-storage --lib`, `-p fluxvm-guest-protocol --lib` | all passed (one Linux-only test is gated) |
| `cargo test -p fluxvm-apple` | 7 passed (capability matrix, control protocol, backend supervision against a fake runner) |
| `scripts/macos-live-test.sh` | **PASS**: daemon → REST create (`backend: vz`) → Debian 13 boots → address in the API → SSH → TCP port forward → shared folder read and write → pause → resume → stop → start → delete |

**Not verified:** macOS guests (IPSW install and boot), the guest-agent vsock proxy, Linux-only crates (`fluxvm-procbox`,
`fluxvm-container-*`, `fluxvm-microvm`, `fluxvm-kube`, the eBPF agent), and any Intel Mac.

## Quick start

```bash
xcode-select --install          # compiler for the Swift runner
brew install hivex              # linked by guestkit's registry support
cargo build -p fluxctl          # also builds and ad-hoc signs target/*/build/fluxvm-apple-*/out/fluxvm-vz-runner
./scripts/macos-live-test.sh    # boots a real Debian VM through the API (downloads the built-in debian-13)
```

Run the daemon yourself:

```bash
fluxctl serve                   # state in ~/Library/Application Support/FluxVM, API on 127.0.0.1:7788
curl -X POST localhost:7788/v1/vms -H 'Content-Type: application/json' -d '{
  "name": "demo", "backend": "vz", "image": "/path/to/arm64-debian.raw",
  "vcpus": 2, "memory_mib": 2048, "network": {"mode": "user"},
  "cloud_init": {"hostname": "demo", "user": "velora", "ssh_authorized_keys": ["ssh-ed25519 AAAA…"]}
}'
curl localhost:7788/v1/vms/<id>        # status, and guest_ip once the guest reports it
```

On a Mac, `"backend": "auto"` resolves to `vz`.

## How it works

The daemon never links Virtualization.framework. `fluxvm-apple` supervises one signed helper process per VM,
`fluxvm-vz-runner` (`crates/fluxvm-apple/runner/Runner.swift`), over a unix control socket (one JSON line per request:
`status`, `pause`, `resume`, `shutdown`, `stop`). The runner holds the `VZVirtualMachine`, writes the guest's serial console
to the VM log, and records the guest's NAT address.

- **Disk:** raw images are cloned instantly (APFS `cp -c`). A qcow2 image is converted to raw while cloning, which needs
  `qemu-img` (`brew install qemu`).
- **Named images:** `"image": "debian-13"` (also `debian-12`, `ubuntu-24.04`) downloads the ARM64 cloud image over HTTPS, checks it against
  the vendor's published SHA file, and caches it under `<state_dir>/images`. Ubuntu ships qcow2, so it is converted to raw once. A
  file of the same name, or a catalog entry, wins. Named images are not catalog images, so `policy.require_catalog_names` rejects them.
- **Cloud-init:** a NoCloud ISO built with `hdiutil`, with a MAC-based DHCP identity so the address stays stable.
- **Guest address:** macOS offers no usable DHCP-lease or ARP view to a spawned process, so FluxVM adds a small systemd
  service to the cloud-init (when a `cloud_init` is given) that prints `VELORA-IP <addr>` on the serial console; the runner
  parses it and `GET /v1/vms/{id}` reports it as `guest_ip`. It also turns off OpenSSH's per-source penalties inside the
  guest so the managing host is never throttled.
- **Networking:** Virtualization.framework NAT only (`network.mode = "user"` or `"none"`). The guest is reachable at its address
  from the Mac. TCP `forwards` listen on `127.0.0.1:<host_port>` (ports 1024 and up) and relay to the guest's address.
- **Shared folders:** `shared_folders` become virtiofs shares tagged `fs0`, `fs1`, …; with `cloud_init` (implied if you give shares)
  the guest mounts them at `guest_path` via `/etc/fstab`, so they survive stop/start. `read_only` is enforced by the host.
- **Signing:** the runner is ad-hoc signed with `com.apple.security.virtualization` by `build.rs`.
  Set `FLUXVM_VZ_RUNNER` to use another binary; `FLUXVM_SKIP_VZ_RUNNER=1` skips building it.

## Snapshots

`POST /v1/vms/{id}/snapshot {"tag": "s1"}` saves a running (or paused) guest: the runner pauses it, writes its memory and device
state with Virtualization.framework (`saveMachineStateTo`), FluxVM clones the disk and EFI variables beside it with APFS
`cp -c` while it is still paused, and the guest continues. Everything lives in `<vm workspace>/snapshots/<tag>/`.
`GET /v1/vms/{id}/snapshots` lists them and `DELETE /v1/vms/{id}/snapshots/{tag}` removes one.

`POST /v1/vms/{id}/restore {"tag": "s1"}` on a **stopped** VM puts the cloned disk back and resumes the saved state: processes that
were running keep running, nothing reboots, and the guest address is reported again. A running VM must be stopped first.

- Needs macOS 14 or later, Apple silicon, and Linux guests.
- **Restoring needs an unlocked login session.** Virtualization.framework encrypts the saved state with a Secure Enclave key that is
  unusable while the Mac's screen is locked: restore then fails with "permission denied". Saving still works. Keep a headless Mac
  mini logged in (auto-login) if you restore on it.
- A saved state is only valid for the configuration it was saved with, and each VM now keeps one machine identifier
  (`generic-id.bin`) so that holds across launches.
- Whether a restore survives a FluxVM runner upgrade has not been tested.

## Capability matrix

| Supported | Not supported |
| --- | --- |
| vCPUs, memory, raw disk, cloud-init | tap / macvtap / netns / eBPF networking, port forwards |
| NAT networking, serial console | NUMA, hugepages, cpuset, VFIO / GPU passthrough |
| shared folders (virtiofs), VM snapshots (memory + disk), pause / resume, graceful shutdown, force stop | secure boot, TPM, confidential profiles |
| guest agent over vsock (proxied like Firecracker; needs the agent in the image) | hotplug, data disks, cdroms |
| macOS guests via IPSW (runner support only) | live migration, in-place restore of a running VM, direct kernel boot |

The same table is encoded in `fluxvm_apple::CAPABILITIES`; unsupported requests are refused with a specific message before any
process starts.

## Honest limits

- This is a preview-quality backend. Only Linux ARM64 guests have been booted.
- macOS guests need an IPSW install step the REST API does not expose yet (`launch` refuses a macOS guest that was never installed).
- Several Linux-only crates still do not build on macOS; CI builds and tests the supported subset by package.
- Memory is not enforced by FluxVM here; the Mac's own memory pressure applies. Plan for one or two small VMs on a 16 GB Mac.
