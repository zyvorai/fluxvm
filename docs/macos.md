# FluxVM on macOS (Apple silicon)

FluxVM's control plane (daemon, REST API, `fluxctl`, scheduler) builds and runs natively on macOS, with a new
**`vz` backend** that runs VMs on Apple's Virtualization.framework. It is a separate, smaller feature set than the
Linux backends: no KVM, TAP, eBPF, cgroups or network namespaces.

For how the pieces fit together (runner per VM, control socket, vsock, warm pool, networking), see [macos-architecture.md](macos-architecture.md).

## What is verified

On an Apple M4 running macOS 27.2 (Xcode 27, Rust 1.98):

| Check | Result |
| --- | --- |
| `cargo build -p fluxctl`, `cargo build -p fluxvm-apple` | Builds; `fluxctl --version` runs |
| `cargo test -p fluxvm-core --lib` / `-p fluxvm-scheduler --lib` / `-p fluxvm-api --lib` | core 79 and scheduler 204 passed on the M4 (api 56 when the backend landed); CI runs them on every change |
| `cargo test -p fluxvm-network --lib`, `-p fluxvm-storage --lib`, `-p fluxvm-guest-protocol --lib` | all passed (one Linux-only test is gated) |
| `cargo test -p fluxvm-apple` / `-p fluxvm-agent --lib` | fluxvm-apple 49 unit tests (capability matrix and egress validation, control protocol, SSH helpers, snapshot files, host-capabilities decode) plus 1 `backend` test against a fake runner and 6 source-contract tests (they only grep Swift and C source, they run nothing); fluxvm-agent 55; all pass, and `cargo clippy -p fluxvm-apple -p fluxvm-agent -- -D warnings` is clean |
| `fluxvm-vz-runner host-capabilities` | Printed the M4's real capabilities (macOS 27.2, 10 CPUs, 16 GiB, nested virtualization, vmnet, custom Virtio, USB API, bridged `en5` and `en0`); the Rust decode and the node heartbeat used it |
| Fleet placement on loopback | `fluxvm-agent central` with one real `node` (heartbeat carried its `apple` caps) and two fake nodes: `vz` requests (plain, `custom_virtio`, `nested_virtualization`) landed on the real node, the fake nodes without those features or without Apple caps were excluded; a named shared vmnet request went to the only vmnet-capable node |
| Custom Virtio guest bus | Debian 13 guest (kernel 6.12), `apple.custom_virtio: true`, device id `0x3F`: the driver binds, `/dev/fluxvm` appears, `fluxvm_virtioctl ping`, `echo`, `stats` and `capabilities` work, and all four bulk operations (fill, zero, copy, crc32; up to 1 MiB) pass. See "Mac Studio options" for what is not exercised |
| `scripts/macos-live-test.sh` | **PASS**, end to end on a real Debian 13 guest: create through the API, address, SSH, TCP forwards (host and guest-to-guest), shared folders, pause/resume, stop/start, snapshot and restore, named images, `fluxctl run` (cold and warm), a two-service stack, sandboxes (exec, files, TTL, warm pool and its refresh after an image update, concurrent creates, offline, allow-listed egress, speculate and changesets), nothing left running |
| `scripts/oci-live-test.sh` | **PASS** with the `oci-boot` CI artifacts: container exit codes, uid, read-only root, exec, distroless argv exec, offline, allow-list, a private network between two sandboxes, `linux/amd64` under Rosetta, a warm-pool claim, TTL |
| `scripts/vz-devices-live-test.sh` | **PASS** on a Debian 13 guest: extra disks on virtio, NVMe and USB, a host block device, an NBD export, USB hot-attach and detach, a console port both ways, a 1600x900 Linux display |
| `scripts/macos-guest-live-test.sh` | Clones a prepared macOS guest template through the API, checks the reported address and SSH, deletes it; needs your own template (`FLUXVM_MACOS_TEMPLATE`), so CI does not run it |

**Verified by hand only:** the macOS IPSW install (see "macOS guests"); `apple.install` and `provision_*` have not run against a real IPSW through the API. **Not verified:** multi-Mac clusters (placement was only checked on loopback with one real Mac and fake nodes), the shared vmnet broker, physical USB passthrough, Linux-only crates (`fluxvm-procbox`,
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

An AI agent can get a disposable VM through the sandbox API or MCP; see [sandboxes](macos-sandboxes.md). A container image can be
the sandbox too, one lightweight VM per container: `fluxctl sandbox run alpine:3.22 --rm -- echo hi`; see
[container sandboxes](oci-sandboxes.md).

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
- **Direct kernel boot:** a Linux guest with `kernel` (and optionally `initrd`, `kernel_args`) boots through `VZLinuxBootLoader`
  instead of EFI from the disk; both paths keep the generic platform, so snapshots work. `apple.root_read_only` attaches the root
  disk read-only, and `apple.tagged_shares` adds virtiofs shares with fixed tags (other than `fsN` and `rosetta`). Container sandboxes
  use all three ([oci-sandboxes.md](oci-sandboxes.md)).
- **Signing:** the runner is ad-hoc signed with `com.apple.security.virtualization` by `build.rs`.
  Set `FLUXVM_VZ_RUNNER` to use another binary; `FLUXVM_SKIP_VZ_RUNNER=1` skips building it. The runner needs the macOS 27 SDK
  (Xcode 27). If Swift is installed but the runner does not compile or sign, the build fails and shows the swiftc errors; with no
  Swift toolchain it only warns.

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
- **Key login on a fresh clone: turn FileVault off in the template.** With FileVault on, a clone boots with its volume locked and sshd
  refuses every key ("Permission denied (publickey,...)") until one password login unlocks it ("System successfully unlocked. You may
  now use SSH to authenticate normally."). Moving the key outside the home directory (`AuthorizedKeysFile` in `/etc/ssh/`) does not help,
  because the whole Data volume is locked. Fix it once, in the template: boot it, log in, and run
  `sudo fdesetup disable` (give it the user's name and password), then wait for decryption to finish (`fdesetup status` says "FileVault is
  Off"; about 25 minutes for a 50 GB disk on an Apple M4), shut the guest down cleanly and use that disk as the template. Verified on an
  Apple M4: a fresh clone of such a template accepted the key on its first login, no password needed. If encryption is still running
  when you try, `fdesetup disable` fails with error -69573; wait for it to reach 100% first. The guest's disk is a file on your Mac, so
  turning FileVault off there only matters if the template file itself needs to stay secret.
- **First boot of a clone** is slow on a USB drive (about 5 minutes to SSH at 37 MB/s) and restarts sshd once, so retry SSH for a minute.

### Installing through the API

`apple.install: true` installs from an IPSW as part of `POST /v1/vms` (tested against a fake runner; not yet run against a real IPSW
through the API):

```bash
curl -X POST localhost:7788/v1/vms -H 'Content-Type: application/json' -d @examples/macos-install.json
```

- The IPSW is `apple.media`, or `image` when `media` is unset; it must be a local absolute path (URLs are refused, download first).
- FluxVM creates a sparse disk of `disk_size_gib` (default 64, minimum 40), runs `fluxvm-vz-runner install` to completion (progress
  events land in `vz-runner.log` in the VM workspace; the request returns only after the install, up to 3 hours), then boots the guest.
  A workspace marker (`macos-installed`) stops a restart from installing again; a failed install leaves no marker and is retried.
- The installed guest stops at Setup Assistant unless you use the macOS 27 `provision_*` options (see "Mac Studio options"). Stop the
  VM afterwards and use its `root.raw` as a template for clones.

### First-boot keys

`apple.firstboot: {"ssh_public_keys": ["ssh-ed25519 …"], "enable_remote_login": true}` shares a read-only folder into the guest at
`/Volumes/My Shared Files/firstboot` with `authorized_keys` and `firstboot.sh` (also in [`scripts/macos-firstboot-helper.sh`](../scripts/macos-firstboot-helper.sh)).
Run it once in the template as an admin, or from a LaunchDaemon you bake in: it installs the keys as a root-owned
`/etc/ssh/fluxvm_authorized_keys` (via `sshd_config.d`), which sshd reads before any home directory is unlocked, so fresh clones accept
the key on first boot, and turns on Remote Login. FluxVM cannot run it inside the guest for you.

### Snapshots of macOS guests

The same `snapshot` / `restore` endpoints work for macOS guests (macOS 14+ host); the snapshot also keeps the guest's NVRAM
(`auxiliary.bin`). Earlier runners ignored the saved state of a macOS guest and cold-booted it; the runner now resumes it the same
way as for Linux guests. Not yet exercised on a real macOS guest.

Not done: a `macos` image name, downloading an IPSW, and exec over vsock for macOS guests (they have no FluxVM guest agent). Apple
allows two macOS VMs at a time per Mac.

## Display, audio, sharing and USB options

`request.apple` takes these first-party Virtualization.framework options:

```json
{"backend": "vz", "apple": {"guest_os": "macos", "window": true, "display_width": 5120, "display_height": 2880,
 "display_ppi": 220, "audio_output": true, "microphone": false, "usb_controller": true}}
```

- **Display:** `display_width` 800 to 5120 (default 2560), `display_height` 600 to 2880 (default 1600), `display_ppi` 72 to 300 (default 220).
  With `window: true` the guest follows the window as it is resized. Linux guests use `display_width` and `display_height` for
  their virtio-gpu scanout too (they used a fixed 1280x800 before).
- **Audio:** output to the host's default device is on by default. `microphone` is off by default; turning it on makes macOS ask for
  microphone access.
- **Shared folders on macOS guests** (macOS 13+ host): all entries share one automount device, so they appear under
  `/Volumes/My Shared Files`; two folders with the same name get a `-2` suffix. Linux guests keep the `fs0`, `fs1`, … tags.
- **Linux only:** `rosetta: true` adds a Rosetta share (the guest still mounts it and registers binfmt); `nested_virtualization: true`
  needs macOS 15 and an M3 or later, and fails clearly otherwise. Both are refused for macOS guests.
- **USB:** `usb_controller: true` adds an XHCI controller (macOS 15+). Attaching a disk image to a running guest is covered under
  "Extra disks" and "Mac Studio options"; a physical device can be attached through Accessory Access (see "Mac Studio options"; not verified).
- **Console log:** a Linux guest's serial console goes to the VM's `console.log`. Past `serial_log_max_mib` (default 16; a key
  of the `[apple]` table in `fluxvm.toml`, not a request field) the runner moves it to `console.log.1`, replacing the previous one, and starts a new file, so a chatty guest cannot fill the
  disk. `sandbox logs` reads both files; `GET /v1/vms/{id}/serial` follows the current one.

### Agent screen and input

An agent can see and drive the display of any running `vz` VM, Linux or macOS guest, with no console window and no Screen
Recording or Accessibility permission on the host: the runner renders the display into a hidden window of its own and sends
keyboard and mouse events to it.

```sh
fluxctl screenshot web --out screen.png --max-width 1280
fluxctl input web '{"action":"click","x":600,"y":400}' --text 'ls -la
'
fluxctl input web '{"action":"key","key":"c","modifiers":["control"]}'
```

The REST routes are `GET /v1/vms/{id}/screenshot` and `POST /v1/vms/{id}/input` (admin only, see [api.md](api.md)); the MCP
tools are `vm_screenshot` and `vm_input` ([mcp.md](mcp.md)).

- **Size:** a display 1920 pixels or wider is captured at half its pixels (a 2560x1600 display gives 1280x800, the size macOS
  shows it at on a Retina screen); a smaller one at its own size. `max_width` scales down further.
- **Coordinates** are screenshot pixels from the top left. After scaling with `max_width`, pass the same number as
  `screen_width`.
- **Typing** uses a US layout and covers printable ASCII, newline and tab. Keys: a character, `enter`, `tab`, `escape`,
  `backspace`, `delete`, arrows, `home`, `end`, `page_up`, `page_down`, `f1`-`f12`; modifiers `shift`, `control`, `option`,
  `command`.
- **Pointer:** the guest gets absolute positions (a Linux guest's USB screen-coordinate digitizer, a macOS guest's trackpad), so a
  click lands where the screenshot shows it; `right_click` and `middle_click` send those buttons, and `scroll` moves by wheel
  notches.
- **Verified** on macOS 27.2 (M4) with a Debian 13 guest: console login by typing, Ctrl+C, and left/right/middle clicks, drag and
  scroll checked with evdev in the guest, before and after a guest reboot and a stop/start.

### Named console ports

`apple.console_ports` (Linux guests, up to 8) adds virtio console ports for a byte stream between host and guest that needs no
network and no agent, for example a debug shell, a log pipe or a custom control channel:

```json
"apple": {"console_ports": ["agent", "debug"]}
```

- **Guest:** each port appears as `/dev/virtio-ports/<name>` (udev creates the link; without udev, find the name in
  `/sys/class/virtio-ports/vport*/name`).
- **Host:** the runner bridges each port to a unix socket, `/tmp/fluxvm-<uid>/<vm id>.port-<name>` (mode 0600). One client at a
  time; a new client replaces the old one. Guest output while no client is connected is dropped, and so is host input while
  no guest process has the port open: have one side announce itself before the other sends (the guest can keep one
  descriptor for both directions, e.g. `exec 3<>/dev/virtio-ports/<name>`).
- **Clients:** `fluxctl port-connect <vm> <name>` connects stdin and stdout (Ctrl-] detaches), locally or with `--server`. Over
  REST, the websocket `GET /v1/vms/{id}/ports/{name}` (admin) carries raw bytes both ways.
- **Names:** 1-32 of `a-z`, `0-9`, `.`, `-` and `_`, starting with a letter or digit. Ports are fixed when the VM starts.

## Private networks between guests

On the Mac's NAT, Virtualization.framework keeps guests apart: each reaches only the Mac. `apple.networks` adds a second network card
on a private layer-2 network that only the guests joining it share (Linux guests):

```json
{"backend": "vz", "apple": {"networks": [{"name": "shop"}, {"name": "lab", "address": "10.89.7.20/24"}]}}
```

- **Addresses:** each network name gets its own `10.89.N.0/24`. A guest gets the lowest free host address (`.2` and up) and a random
  locally administered MAC, unless it asks for `address` or `mac`. Both are kept in the VM record, so they survive restarts. A
  requested address must be in the network's subnet and free. At most 4 networks per guest; names are `a-z`, `0-9` and `-`.
- **In the guest:** container sandboxes (`oci.networks`) get the address from init, matched by MAC, with no route and no DHCP on that
  card. Full VMs get it through cloud-init: a systemd-networkd unit per card, and a `fluxvm-vznet.service` oneshot that sets the
  same address with `ip` on guests without networkd.
- **The switch:** each network is one `fluxvm-vz-switch` process (installed next to `fluxctl`, or `FLUXVM_VZ_SWITCH`), started on
  demand and listening on `/tmp/fluxvm-<uid>/vznet-<name>.sock` (mode 0600). The runner hands it one end of a datagram socket pair
  (`VZFileHandleNetworkDeviceAttachment`). The switch forwards by the MAC each port registered with, drops frames with any other
  source MAC, floods broadcast and multicast, and drops unicast to unknown MACs. It exits 30 s after the last guest leaves; a runner
  that loses its switch starts it again and reconnects.
- **Isolation:** guests on different networks, or not on one, cannot reach each other. A network belongs to the tenant of the VMs
  already on it. `networks` works with `network.mode = "none"` (an isolated cluster) but not with `egress_allow`, since another guest
  could relay around the proxy.
- **Listing:** `fluxctl vznet ls` and `GET /v1/vznets` show each network's subnet, members and whether its switch is running.

## Extra disks

A Linux guest takes extra disks in `apple.extra_disks`, or with `fluxctl disk attach` (`POST /v1/vms/{id}/disks`):

```json
"apple": {"extra_disks": [
  {"name": "scratch", "path": "/Volumes/Fast/scratch.raw", "caching": "uncached", "sync": "none", "controller": "nvme"},
  {"name": "raw", "kind": "block", "path": "/dev/disk4", "read_only": true},
  {"name": "shared", "kind": "nbd", "url": "nbd://10.0.0.5:10809/vol1"}
]}
```

| Field | Values |
|-------|--------|
| `kind` | `image` (a raw file, default), `block` (a host device, `/dev/diskN`), `nbd` (an NBD export in `url`) |
| `caching` | `automatic` (default), `cached`, `uncached`; image files only |
| `sync` | `full` (default), `fsync` (image files only), `none` (fastest; data can be lost if the host crashes) |
| `controller` | `virtio` (default, `/dev/vdX`), `nvme` (`/dev/nvmeXn1`), `usb` (`/dev/sdX`) |

- `block`, `nbd` and `nvme` need macOS 14. A block device must be readable (and, unless `read_only`, writable) by the user the
  daemon runs as; FluxVM never changes device permissions. Image files and devices go through the same
  `policy.allowed_image_dirs` check as QEMU data disks.
- NBD URLs are `nbd://host:port/export`, `nbds://…` (TLS), or `nbd+unix:///export?socket=/path`. Virtualization.framework
  reconnects when the server drops; a missing server fails the VM's start.
- Virtualization.framework fixes a VM's devices when it starts, so `fluxctl disk attach` and `detach` apply at the next start. The
  exception is a USB image disk on a running guest: attach plugs it in at once (macOS 15), and detach unplugs it at once as long
  as the VM has not restarted since. A new image made with `--size-gib` is deleted on detach once nothing uses it.

```bash
fluxctl disk attach web scratch --size-gib 20 --controller nvme --caching uncached   # a new sparse image in the VM's workspace
fluxctl disk attach web shared --url nbd://10.0.0.5:10809/vol1 --read-only
fluxctl disk ls web
fluxctl disk detach web scratch
```

## Mac Studio options

These compile against the macOS 27 SDK and are validated at admission. Except for USB disk hot-attach and the share swap, which
`scripts/vz-devices-live-test.sh` and `scripts/oci-live-test.sh` exercise, they have **not been verified on hardware** yet, except where an item below says otherwise (host capabilities, fleet placement and the custom Virtio control channel).

- **Several displays (macOS guests):** `display_count` 1 to 8 (default 1), each `display_width` x `display_height`.
- **Clipboard (Linux guests):** `clipboard: true` adds a SPICE agent port; the guest needs `spice-vdagent`. Refused for macOS guests.
- **Bridged networking:** `bridge_interface: "en0"` puts the guest on the host's LAN (for example a Mac Studio's 10GbE) instead of NAT.
  Needs `network.mode = "user"` with no `forwards`, and a runner signed with `com.apple.vm.networking`: build with
  `FLUXVM_VZ_BRIDGE=1 cargo build -p fluxvm-apple` (ad-hoc signing of that entitlement only works with SIP/AMFI relaxed or a
  provisioning profile).
- **vmnet networks (macOS 26+):** `vmnet: {"mode": "shared" | "host-only", "subnet": "192.168.105.0", "mask": "255.255.255.0",
  "reserved_ip": "192.168.105.10", "forwards": [{"protocol": "tcp", "host_port": 8080, "guest_port": 80, "guest_ip": "192.168.105.10"}]}`
  gives the VM its own network with a stable DHCP reservation for its MAC and TCP/UDP host forwards. Admission checks that the mask is
  contiguous (/30 or wider) and that `reserved_ip` and each forward's `guest_ip` are inside the subnet. The SDK has no DHCP pool setter,
  so the whole subnet is served and `dhcp_start`/`dhcp_end` are refused. The other vmnet settings are passed through:
  `ipv6_prefix` (`"fd00:1::/64"`), `mtu` (1280-9000), `external_interface` (shared mode), and the switches `disable_dhcp`
  (refused with `reserved_ip`), `disable_dns_proxy`, `disable_nat44`, `disable_nat66` and `disable_router_advertisement`; a named
  network's fingerprint includes them. Each runner owns its network unless the VMs name it: `vmnet.name` (macOS 26+) makes them share one network through the `fluxvm-vmnetd` broker over XPC
  ([VMNET_BROKER.md](VMNET_BROKER.md)). **Not verified:** on the test Mac the ad-hoc signed broker was killed at launch (SIP on, `com.apple.vm.networking`), so two runners on one name have not run; with no broker a named VM fails with "vmnetd XPC connection failed". Exclusive with `bridge_interface`. IP discovery and the 127.0.0.1 `network.forwards`
  relay read the NAT lease file, so use `vmnet.forwards` instead.
- **Custom Virtio (macOS 27+, Linux guests):** `custom_virtio: true` adds a vendor Virtio device (id `0x3F`, PCI `1af4:107f`; an earlier id, `0xFF00`, was outside the range Linux binds) with a host-side provider. Queue 0 is a bounded (1 MiB) versioned JSON control channel (`ping`, `echo`, `capabilities`, `stats`, `map-probe`); queue 1 is the bulk queue (`bulk_zero`, `fill`, `copy`, `crc32`, up to 64 MiB). The guest driver is in `guest/virtio-flux` (`/dev/fluxvm`, `/dev/fluxvm-bulk`, `fluxvm_virtioctl`). **Verified** on the M4 with a Debian 13 guest: `ping`, `echo`, `stats` and `capabilities`. `fluxvm_virtioctl bulk-test`, `bulk-zero-test`, `bulk-copy-test` and `bulk-crc-test` (queue 1, 1 B to 1 MiB) pass after the driver stopped using a stack buffer for its request; the 64 MiB host cap was not tried. See [macos-vz27-full-stack.md](macos-vz27-full-stack.md).
  The device also handles DRIVER_OK, stop, pause, resume and reset, and saves its counters with a VM snapshot (the configuration sets
  `supportsSaveRestore`; without it Virtualization refuses to save a VM with the device). **Verified** on the M4: snapshot, stop and
  `start-from-snapshot` resumed the Debian guest without a reboot, `ping` and `echo` worked, and the counters continued. The control socket takes
  `{"cmd":"virtio-status"}` (driver state and counters) and `{"cmd":"virtio-reset"}` (host-initiated reset: the device sets DEVICE_NEEDS_RESET, which Linux ignores unless the
  driver handles it; `virtio_flux` resets the device, aborts requests still queued with `EIO`, and sets the queues up again. Needs
  `CONFIG_PM_SLEEP`. **Verified** on the M4: after two resets in a row, `ping` and `bulk-test` worked);
  `fluxvm_apple::vz27` wraps both.
- **EFI Secure Boot (macOS 27+, Linux EFI guests):** top-level `secure_boot: true` enrolls Microsoft's KEK, UEFI CA and revocation list
  and enables Secure Boot with Apple's platform key, so Microsoft-signed shims boot. `apple.efi_secure_boot` customises it:
  `platform_key` (X.509, DER or PEM), `kek`/`db`/`dbx` (certificates, SHA-256 hashes or EFI signature lists),
  `default_signatures: false` and `reset: true` (clear previously enrolled keys first). `secure_boot: false` turns it off and keeps the
  keys; leaving it out does not touch `efi.bin`. Refused with direct kernel boot and for macOS guests. `{"cmd":"secure-boot-status"}` reports
  the state and signature counts. **Verified** on the M4: enable with default keys (2 KEK, 2 db, 26 dbx), status, disable, and a stock Debian 13 cloud image booting through the API with `secure_boot: true` (guest efivars: `SecureBoot=1`, `SetupMode=0`). The guest kernel reports "Secure boot enabled" and runs in lockdown (integrity), so it loads only signed modules: an out-of-tree
  module such as `virtio_flux.ko` must be signed with an enrolled key (for example a MOK) to load under Secure Boot. While the VM runs,
  Virtualization keeps `efi.bin` locked, so `secure-boot-status` returns the state read just before start, marked `"as_of": "boot"`;
  with the VM stopped it reads the store.
- **Recovery (macOS guests):** `recovery: true` starts the guest in macOS Recovery.
- **Rosetta cache (Linux guests):** with `rosetta: true`, `rosetta_cache` is `"default"`, a guest socket path or an abstract socket name for
  `rosettad`'s AOT cache. A Mac without Rosetta fails at boot with a pointer to `fluxvm-vz-runner install-rosetta`.
- **Disk serials:** an `extra_disks` entry on the virtio controller can set `block_device_id` (1-20 ASCII), shown in the guest as
  `/dev/disk/by-id/virtio-<id>`.
- **VM label (macOS 27+):** the runner sets `VZVirtualMachineConfiguration.label` to the VM's name (trimmed to 64 characters) so system
  services show it; the console window uses `VZVirtualMachineViewAdaptor`.
- **Events:** the runner log gets `network-disconnected` (a bridged or vmnet attachment went away), `nbd-connected` / `nbd-failed`,
  `usb-passthrough-disconnected` (the host took a device back) and `secure-boot` lines.
- **Memory balloon:** `GET /v1/vms/{id}/balloon` and `POST /v1/vms/{id}/balloon {"balloon_mib": N}` work for `vz` VMs too (the runner sets
  the balloon target), and idle reclaim inflates idle `vz` sandboxes the same way as KVM ones.
- **USB disk hotplug:** with `usb_controller: true`, the runner's control socket accepts
  `{"cmd":"usb-attach","path":"/path/disk.img","read_only":false}` (returns a `uuid`) and `{"cmd":"usb-detach","uuid":"…"}` (macOS 15+).
  `{"cmd":"usb-list"}` lists what is attached now. A snapshot is refused while a hot-attached USB disk is still attached: macOS 27 can
  crash restoring such a state without the disk (177528319). Passed-through devices are detached before saving instead (174267926), and
  the `save` reply lists them in `usb_detached`.
- **Physical USB passthrough (macOS 27):** the runner's control socket also takes `{"cmd":"usb-physical-list"}` and
  `{"cmd":"usb-physical-attach","registry_id":…}`. It goes through Apple's Accessory Access consent, so it needs the `FluxVMUSBAccess` app
  signed with the `com.apple.developer.accessory-access.usb` entitlement (an Apple entitlement). There is no REST route or `fluxctl`
  command. **Not verified:** on the test Mac the ad-hoc signed app was killed at launch and no USB device was attached.
- **Share swap:** `{"cmd":"share-set","tag":"fluxvm-vol0","path":"/dir","read_only":false}` points a running guest's virtiofs share at
  another directory. The container sandbox warm pool ([oci-sandboxes.md](oci-sandboxes.md#warm-pool)) uses it with USB hot-attach
  to hand a pre-booted VM its rootfs and volumes.
- **ASIF overlay (macOS 27+):** `asif_overlay: true` keeps the base disk read-only and writes to a sparse `disk-overlay.asif`, which
  snapshots include.
- **Unattended first boot (macOS 27 guests):** `provision_full_name`, `provision_username`, `provision_password_file` (a one-shot file the
  runner deletes after reading), `provision_auto_login`, `provision_remote_login` create the user and turn on Remote Login without Setup
  Assistant.
- **Host capabilities:** `fluxvm-vz-runner host-capabilities` prints the host's OS version, CPU and memory, `maximumVmCPUs`, nested
  virtualization, vmnet, custom-Virtio and USB API support and bridgeable interfaces; `fluxvm_apple::host_capabilities` decodes it.
  (`{"cmd":"capabilities"}` on a runner's control socket reports a running VM's view.) **Verified** on the M4.
- **Fleet placement for `vz`:** `fluxvm-agent node` puts these capabilities, with free CPU and memory and the macOS guest count, in its
  heartbeat (`apple`), and `fluxvm-agent central` scores nodes with `fluxvm_scheduler::apple_placement` for `backend: vz` requests. Nodes
  without Apple capabilities are excluded for `vz`; among nodes that fit, the tightest fit wins. **Verified** only on loopback: one real
  M4 node plus two fake nodes registered by hand. No second Mac was used; central's `vz` filtering is unit-tested (request parsing, nodes without Apple capabilities, feature requirements, the two-macOS-guest limit).

## Capability matrix

| Supported | Not supported |
| --- | --- |
| vCPUs, memory, raw disk, cloud-init, direct kernel boot (Linux guests) | tap / macvtap / netns / eBPF networking, UDP port forwards |
| NAT networking, TCP port forwards, no-network mode, serial console | NUMA, hugepages, cpuset, VFIO / GPU passthrough |
| shared folders (virtiofs), VM snapshots (memory + disk, Linux and macOS guests), pause / resume, graceful shutdown, force stop, EFI Secure Boot (macOS 27+, Linux) | TPM, confidential profiles |
| guest agent over vsock (proxied like Firecracker; needs the agent in the image) | hotplug of CPU, memory and NICs; cdroms; firmware overrides |
| macOS guests (installed from an IPSW through the API or by hand, then cloned; see above) | live migration, in-place restore of a running VM, direct kernel boot of macOS guests |
| extra disks (image, block device, NBD; virtio, NVMe, USB), USB disk hot-attach and detach, private networks, console ports, bridged and vmnet networking, balloon, Rosetta, display, audio | (vmnet forwards may be UDP; NAT forwards are TCP only) |

The same table is encoded in `fluxvm_apple::CAPABILITIES`; unsupported requests are refused with a specific message before any
process starts.

## Honest limits

- This is a preview-quality backend. Linux ARM64 guests are what the live tests boot; macOS guests were booted by hand and cloned
  through `scripts/macos-guest-live-test.sh`.
- macOS guests are installed through the API or by hand, but finishing Setup Assistant still needs a person unless the host and guest
  are on macOS 27 (`provision_*`). The restore image is 26.6 GB and the installed disk about 24 GB, so plan for 55 GB or more free on
  the volume that holds them.
- Restoring a snapshot (warm starts, the warm sandbox pool, speculate) needs an unlocked login session; each path falls back to a cold boot
  where it can.
- Container warm-pool slots are hidden from `fluxctl ls` and `GET /v1/vms` unless you pass `--all` / `?all=true` or select
  `fluxvm.oci-warm`. A sandbox claimed from a warm slot is not hibernated until it restarts, because its root disk is a hot-attached
  USB disk.
- The Mac's DHCP server keeps one lease per MAC for a day, so a deleted VM's MAC is handed to the next new VM (and with it the old
  address), rather than filling the lease file.
- A sandbox that has a network card is on an unfiltered NAT; only offline and allow-listed sandboxes are isolated.
- Private networks (`apple.networks`) are IPv4 /24s with static addresses: no DHCP, DNS or routing between networks. The switch runs
  in user space, so it is slower than the NAT card.
- Container sandboxes need boot artifacts built on Linux arm64 (`scripts/build-oci-boot.sh`, or the `oci-boot` CI workflow's
  artifacts) and take `linux/arm64` images (or `linux/amd64` under Rosetta).
- Several Linux-only crates still do not build on macOS; CI builds and tests the supported subset by package.
- Memory is not enforced by FluxVM here; the Mac's own memory pressure applies. Plan for one or two small VMs on a 16 GB Mac.
