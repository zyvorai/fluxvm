# FluxVM on macOS (Apple silicon)

FluxVM's control plane (daemon, REST API, `fluxctl`, scheduler) builds and runs natively on macOS, with a new
**`vz` backend** that runs VMs on Apple's Virtualization.framework. It is a separate, smaller feature set than the
Linux backends: no KVM, TAP, eBPF, cgroups or network namespaces.

## What is verified

On an Apple M4 running macOS 27.2 (Xcode 27, Rust 1.98):

| Check | Result |
| --- | --- |
| `cargo build -p fluxctl`, `cargo build -p fluxvm-apple` | Builds; `fluxctl --version` runs |
| `cargo test -p fluxvm-core --lib` / `-p fluxvm-scheduler --lib` / `-p fluxvm-api --lib` | passed when the backend landed (70 / 171 / 56); CI runs them on every change |
| `cargo test -p fluxvm-network --lib`, `-p fluxvm-storage --lib`, `-p fluxvm-guest-protocol --lib` | all passed (one Linux-only test is gated) |
| `cargo test -p fluxvm-apple` | 16 passed (capability matrix and egress validation, control protocol, SSH helpers, snapshot files, backend supervision against a fake runner) |
| `scripts/macos-live-test.sh` | **PASS**, end to end on a real Debian 13 guest: create through the API, address, SSH, TCP forwards (host and guest-to-guest), shared folders, pause/resume, stop/start, snapshot and restore, named images, `fluxctl run` (cold and warm), a two-service stack, sandboxes (exec, files, TTL, warm pool and its refresh after an image update, concurrent creates, offline, allow-listed egress, speculate and changesets), nothing left running |

**Verified by hand only:** macOS guests (IPSW install, boot, clone, SSH; see "macOS guests"), not through the API or the live test. **Not verified:** multi-Mac clusters, Linux-only crates (`fluxvm-procbox`,
`fluxvm-container-*`, `fluxvm-microvm`, `fluxvm-kube`, the eBPF agent), and any Intel Mac. The hosted CI jobs for the `vz` pull requests
have not all been green; see the pull requests for their state.

## Quick start

A Homebrew package can be built from each version tag (see [`packaging/homebrew`](../packaging/homebrew/README.md)), but no tap is
published yet, so build from source as below.

```bash
xcode-select --install          # compiler for the Swift runner
brew install hivex              # linked by guestkit's registry support
cargo build -p fluxctl          # also builds and ad-hoc signs target/*/build/fluxvm-apple-*/out/fluxvm-vz-runner
./scripts/macos-live-test.sh    # boots a real Debian VM through the API (downloads the built-in debian-13, about 300 MB)
```

Or skip the API: `fluxctl run` gives you a throwaway VM and a shell, and everything you did in it is gone when you leave.

```bash
fluxctl run                                  # built-in debian-13, a shell as your own user name
fluxctl run -v ~/src:/mnt/src -p 8080:80     # share a folder, forward 127.0.0.1:8080 to guest port 80
fluxctl run ubuntu-24.04 -- 'uname -a'       # run one command; its exit code is yours
fluxctl run --keep --name dev                # keep the VM; `fluxctl ssh dev` (as your user) or `fluxctl delete dev` later
fluxctl run --no-warm                        # always cold-boot instead of restoring the warm snapshot
```

It uses your first `~/.ssh/id_*.pub` key (or creates `~/.ssh/fluxvm_ed25519`).

**Warm starts.** The first run for a given setup (image, size, ports, volumes, user, key) cold-boots a VM, waits for cloud-init to
finish, snapshots it as a stopped template named `warm-<hash>`, and runs your session on it. Every later run restores that snapshot
(about 2 s on an M4 against about 10 s for a cold boot) and stops the VM afterwards, so each run starts pristine. If the template is
in use by another run, or the restore fails (for example on a locked screen, see Snapshots), `fluxctl run` boots a separate VM
instead. Remove a template with `fluxctl delete warm-<hash>`, for example after a new image version.

Measured on an Apple M4: cold boot about 10 s, warm run 2 to 3 s, snapshot 0.7 s, restore to SSH 1.4 s, sandbox create 8 s cold and
about 2 s from the warm pool.

A project that needs several VMs can describe them in a `fluxvm.toml` and use `fluxctl up` / `down`; see [stacks](macos-stacks.md).

An AI agent can get a disposable VM through the sandbox API or MCP; see [sandboxes](macos-sandboxes.md).

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
`status`, `pause`, `resume`, `shutdown`, `stop`, `save`). The runner holds the `VZVirtualMachine`, writes the guest's serial console
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
- **Networking:** Virtualization.framework NAT only (`network.mode = "user"`), or `"none"`, which attaches no network card at all (see [sandboxes](macos-sandboxes.md)). The guest is reachable at its address
  from the Mac. TCP `forwards` listen on `127.0.0.1:<host_port>` (ports 1024 and up) and relay to the guest's address. Guests on this NAT cannot reach
  each other; a forward with `"guests": true` also listens on the NAT gateway address (the Mac, as guests see it) so other guests can use it
  (that is how [stacks](macos-stacks.md) connect services).
- **Shared folders:** `shared_folders` become virtiofs shares tagged `fs0`, `fs1`, …; with `cloud_init` (implied if you give shares)
  the guest mounts them at `guest_path` via `/etc/fstab`, so they survive stop/start. `read_only` is enforced by the host.
- **vsock:** every VM has a vsock proxy socket (`CONNECT <port>` over a unix socket). The daemon uses it to reach an offline sandbox's sshd
  (guest port 22), and the guest reaches a host-side egress proxy over it (guest to host, port 3128). See [sandboxes](macos-sandboxes.md).
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

## macOS guests

Verified by hand on an Apple M4 running macOS 27.2 with macOS 27.0.1 (26A434) as the guest. What works:

- **Install.** `fluxvm-vz-runner install --config <json>` (with `guest_os: "macos"`, `media` = the IPSW, `disk` = a sparse raw file of at
  least 40 GB, 4 CPUs, 8 GiB) installs from an IPSW and writes `hardware.bin`, `identity.bin` and `auxiliary.bin` beside the disk. The
  installer reached 100% and the guest then booted. The IPSW is 26.6 GB; Apple's public catalog
  (`https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml`) lists it, since
  `VZMacOSRestoreImage.fetchLatestSupported` failed to load its catalog on that machine. The install is not exposed through the API yet.
- **Prepare once, by hand.** The guest stops at Setup Assistant. Boot it with `window: true` from a terminal (the window needs a
  foreground app), create a user, turn on **Remote Login** (System Settings, General, Sharing; if the toggle does not stick, give
  Terminal Full Disk Access and run `sudo systemsetup -setremotelogin on`), install your SSH key, and shut down. That disk is the template.
  Doing this offline from the host needs root and was not attempted.
- **Clone.** `POST /v1/vms` with `backend: "vz"`, `apple: {guest_os: "macos"}` and `image` = the template's `disk.raw` clones the disk
  (APFS `cp -c`, instant) and takes `hardware.bin` and `auxiliary.bin` from beside it. The runner gives every clone its own machine
  identifier, so a clone is a separate machine (it has its own serial number). The clone's state directory must be on the same APFS volume as
  the template, or the "clone" is a full copy of a 20+ GB disk.
- **Address.** A macOS guest has no systemd, so the runner reads the Mac's DHCP leases (`/var/db/dhcpd_leases`) for the MAC the guest's
  card was given and reports it as `guest_ip`. (The ARP table is not an option: macOS shows it empty to a spawned process.)
- **Key login on a fresh clone.** In the guest we prepared, sshd refused the public key on a new clone (home directory not yet readable)
  until one password login had happened; after that the key worked. Two ways round it: log in once with the password, or put the key
  in a file outside the home directory (`AuthorizedKeysFile /etc/ssh/fluxvm_authorized_keys` in `/etc/ssh/sshd_config.d/`, root-owned)
  when you prepare the template. We did not automate either.
- **First boot of a clone** is slow on a USB drive (about 5 minutes to SSH at 37 MB/s) and restarts sshd once, so retry SSH for a minute.

Not done: installing through the REST API or `fluxctl`, a `macos` image name, shared folders and snapshots for macOS guests (the
runner only sets those up for Linux), and a vsock proxy. Apple allows two macOS VMs at a time per Mac.

## Display, audio, sharing and USB options

`request.apple` takes these first-party Virtualization.framework options:

```json
{"backend": "vz", "apple": {"guest_os": "macos", "window": true, "display_width": 5120, "display_height": 2880,
 "display_ppi": 220, "audio_output": true, "microphone": false, "usb_controller": true}}
```

- **Display:** `display_width` 800 to 5120 (default 2560), `display_height` 600 to 2880 (default 1600), `display_ppi` 72 to 300 (default 220).
  With `window: true` the guest follows the window as it is resized.
- **Audio:** output to the host's default device is on by default. `microphone` is off by default; turning it on makes macOS ask for
  microphone access.
- **Shared folders on macOS guests** (macOS 13+ host): all entries share one automount device, so they appear under
  `/Volumes/My Shared Files`; two folders with the same name get a `-2` suffix. Linux guests keep the `fs0`, `fs1`, … tags.
- **Linux only:** `rosetta: true` adds a Rosetta share (the guest still mounts it and registers binfmt); `nested_virtualization: true`
  needs macOS 15 and an M3 or later, and fails clearly otherwise. Both are refused for macOS guests.
- **USB:** `usb_controller: true` adds an XHCI controller (macOS 15+). Choosing and attaching a physical device is not built.

### Mac Studio options

These are built and type-checked against the macOS 27 SDK, but none has been run on hardware yet. They all default to off, so an
existing request behaves as before.

- **`display_count`** (1 to 8, default 1): number of virtual displays on a macOS guest, each `display_width` x `display_height`.
- **`clipboard: true`:** Linux guests only (refused for macOS). Adds a SPICE agent console port; the guest needs `spice-vdagent`.
- **`bridge_interface`** (for example `"en0"`): bridges the guest to that host interface instead of NAT. Needs `network.mode = "user"`
  with no `forwards` (port forwards are NAT-only). The runner needs the restricted `com.apple.vm.networking` entitlement, so build with
  `FLUXVM_VZ_BRIDGE=1` to sign it with `runner/Entitlements.networking.plist`; the default build does not carry it.
- **`asif_overlay: true`:** macOS 27+ host. The base `disk.raw` is opened read-only and guest writes go to a sparse
  `disk-overlay.asif` in the VM workspace (DiskImageKit). Snapshots now copy the overlay too.
- **`provision_full_name`, `provision_username`, `provision_password_file`, `provision_auto_login`, `provision_remote_login`:** macOS 27+
  host and guest. First boot creates the account, optionally logs in automatically and enables Remote Login. Full name, username and
  password file are all required. The runner reads the password from the file and deletes it; it is never sent in the VM request.
- **Balloon:** the existing `GET`/`POST /v1/vms/<id>/balloon` (and the memory report and idle reclaim) now also work for `vz` VMs, through
  the runner's Virtualization.framework balloon device. For `vz`, `target_mib` and `actual_mib` both report the memory taken from the guest,
  as set on the host; the guest driver's progress is not read back.
- **USB hotplug:** the runner control socket accepts `usb-attach` (`path`, optional `read_only`) and `usb-detach` (`uuid`) for a disk
  image as USB mass storage. It needs `usb_controller: true` and macOS 15+. There is no HTTP route for these yet, only
  `fluxvm_apple::usb_attach` / `usb_detach`.

Unverified on hardware: bridged networking on a real NIC, multi-display boot, SPICE clipboard sync, balloon reclaim, USB attach and
detach, ASIF overlay growth and snapshot/restore, and macOS 27 provisioning.

## Capability matrix

| Supported | Not supported |
| --- | --- |
| vCPUs, memory, raw disk, cloud-init | tap / macvtap / netns / eBPF networking, UDP port forwards |
| NAT networking, TCP port forwards, no-network mode, serial console | NUMA, hugepages, cpuset, VFIO / GPU passthrough |
| shared folders (virtiofs), VM snapshots (memory + disk), pause / resume, graceful shutdown, force stop | secure boot, TPM, confidential profiles |
| guest agent over vsock (proxied like Firecracker; needs the agent in the image) | hotplug, data disks, cdroms |
| macOS guests (installed by hand from an IPSW, then cloned; see above) | live migration, in-place restore of a running VM, direct kernel boot |

The same table is encoded in `fluxvm_apple::CAPABILITIES`; unsupported requests are refused with a specific message before any
process starts.

## Honest limits

- This is a preview-quality backend. Only Linux ARM64 guests have been booted.
- macOS guests exist only as clones of a template you install and prepare by hand (see "macOS guests"); the API cannot install one. The
  restore image is 26.6 GB and the installed disk about 24 GB, so plan for 55 GB or more free on the volume that holds them.
- Restoring a snapshot (warm starts, the warm sandbox pool, speculate) needs an unlocked login session; each path falls back to a cold boot
  where it can.
- A sandbox that has a network card is on an unfiltered NAT; only offline and allow-listed sandboxes are isolated.
- Several Linux-only crates still do not build on macOS; CI builds and tests the supported subset by package.
- Memory is not enforced by FluxVM here; the Mac's own memory pressure applies. Plan for one or two small VMs on a 16 GB Mac.
