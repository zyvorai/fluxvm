---
title: How FluxVM works on a Mac
description: The architecture of FluxVM's vz backend on Apple silicon - one signed runner process per VM, vsock, guests, networking, snapshots, warm pools, agent and container sandboxes, and what has and has not been verified on hardware.
---

# How FluxVM works on a Mac

FluxVM on a Mac is a small daemon that never touches Apple's hypervisor itself. For every VM it starts one tiny signed helper
process, and that helper is the only thing that links Virtualization.framework. Everything else (the REST API, `fluxctl`, the MCP
server, quotas, TTLs, warm pools, snapshots, placement) is ordinary Rust in the daemon that talks to the helper over a unix socket.
That split is what lets the same control plane serve Linux VMs, macOS VMs, agent sandboxes and one-VM-per-container sandboxes on
Apple silicon, and it is why a crash in one VM takes down one process and not your other guests.

This page is the map. For the how-to details and every request field, see [macos.md](macos.md). Where a feature has not been
checked on real hardware, this page says so; the full list is in [section 14](#14-what-is-verified).

## 1. Overview

```
 you / agent / Kairon
        |  REST :7788, fluxctl, MCP
        v
 +--------------------------------------------------------------+
 |  fluxctl serve   (the daemon; never links Virtualization.fw) |
 |  API, scheduler, quotas, TTLs, warm pools, snapshots, images |
 +----+---------------+---------------+-------------------------+
      | unix socket   | unix socket   | unix socket
      | JSON lines    | JSON lines    | JSON lines
      v               v               v
 +-----------+   +-----------+   +-----------+      +-------------------+
 | fluxvm-   |   | fluxvm-   |   | fluxvm-   |      | fluxvm-vz-switch  |
 | vz-runner |   | vz-runner |   | vz-runner |<---->| (one per private  |
 | (signed)  |   | (signed)  |   | (signed)  |      |  network)         |
 | VM: Linux |   | VM: macOS |   | VM: OCI   |      +-------------------+
 +-----------+   +-----------+   +-----------+
   Virtualization.framework   (one VZVirtualMachine per runner)
```

- **One runner per VM.** `fluxvm-vz-runner` is a Swift program (`crates/fluxvm-apple/runner/`) that holds one `VZVirtualMachine`.
- **The daemon supervises, the runner executes.** The daemon builds a JSON config, starts the runner, and from then on only talks to
  it through a control socket and a vsock proxy socket.
- **Small feature set, on purpose.** This is the `vz` backend: no KVM, TAP, eBPF, cgroups or network namespaces. The supported and
  refused features are encoded in `fluxvm_apple::CAPABILITIES`, and an unsupported request is refused with a specific message before
  any process starts ([macos.md](macos.md#capability-matrix)).

## 2. Process model

### One runner per VM

`fluxvm-apple` (`crates/fluxvm-apple/src/lib.rs`) implements the `vz` backend. On launch it:

1. validates the request against the capability matrix;
2. prepares the workspace (restores a snapshot's files if asked, adopts a macOS template, writes the optional first-boot share and
   the container-sandbox metadata);
3. writes the runner's JSON config and starts `fluxvm-vz-runner run --config <file>` in its own process group, with stdout and
   stderr going to the runner log in the VM workspace;
4. polls the control socket with `status` every 200 ms until the guest reports `running`. A runner that exits first has failed (the
   tail of its log is returned in the error); no `running` within 120 s kills the runner and fails the launch.

The runner outlives the launch call. The daemon stops it through the control socket or with a signal.

### Signing and entitlements

`build.rs` compiles the Swift sources with `xcrun swiftc` (targeting `arm64-apple-macosx14.0`, linking AppKit and Virtualization)
and signs the result **ad hoc** with `codesign --sign -`. Virtualization.framework refuses to start a VM without the
`com.apple.security.virtualization` entitlement, so the entitlement plist is part of the signature. There is no Apple developer
certificate involved.

| Build | Entitlements | When |
| --- | --- | --- |
| Default | `com.apple.security.virtualization` | always |
| Networking build | `com.apple.security.virtualization` and `com.apple.vm.networking` | opt in with `FLUXVM_VZ_BRIDGE=1 cargo build -p fluxvm-apple`; needed for bridged networking |

`com.apple.vm.networking` is restricted: ad-hoc signing of it only works with SIP/AMFI relaxed or a provisioning profile
([macos.md](macos.md#mac-studio-options)). Environment switches: `FLUXVM_VZ_RUNNER` points at another runner binary,
`FLUXVM_SKIP_VZ_RUNNER=1` skips building it, and `FLUXVM_VZ_SWITCH` points at another switch binary.

### The control socket

Each runner listens on `/tmp/fluxvm-<uid>/<first 8 hex of VM id>.ctl` (the directory is mode 0700, the socket mode 0600; unix socket
paths are limited to about 104 bytes on macOS, which is why they do not live in the workspace). One JSON object per line in, one
JSON line out.

| Command | Arguments | What it does |
| --- | --- | --- |
| `ping` | | Liveness check |
| `status` | | `{state, ip}`; `state` is `starting`, `running` or `paused` |
| `pause`, `resume` | | Pause or resume the guest |
| `save` | `path` | Pause the guest and write its memory and device state to `path` (macOS 14+); the guest stays paused so the host can clone the disk at the same instant |
| `shutdown` | | Graceful: ask the guest to stop (`requestStop`) |
| `stop` | | Force stop, then the runner exits |
| `capabilities` | | CPU and memory limits, nested virtualization, bridgeable interfaces, vmnet and custom-Virtio support |
| `host-capabilities` | | The host-wide report (OS version, CPU and memory, `maximumVmCPUs`, nested virtualization, vmnet, vmnet serialisation, custom Virtio and its queue backend, guest-memory mapping, USB passthrough API, bridged interfaces). Also available without a VM as `fluxvm-vz-runner host-capabilities`, which `fluxvm-agent node` uses for its heartbeat |
| `usb-physical-list` | | List the physical USB accessories that the signed `FluxVMUSBAccess.app` helper has been authorised to export (macOS 27+) |
| `usb-physical-attach` | `registry_id` | Hot-attach one of them to the VM's XHCI controller as a `VZUSBPassthroughDevice`; returns a `uuid` for `usb-detach` (macOS 27+, needs `usb_controller`) |
| `balloon` | optional `balloon_mib` | Read the memory balloon, or set its target |
| `usb-attach` | `path`, optional `read_only` | Hot-plug a USB disk image; returns a `uuid` (macOS 15+, needs `usb_controller`) |
| `usb-detach` | `uuid` | Unplug a disk image or a passthrough device (macOS 15+) |
| `share-set` | `tag`, `path`, optional `read_only` | Point a running guest's virtiofs share at another directory |

### Lifecycle

```
 create request
      |
      v
 validate -> workspace -> runner config -> spawn runner
                                              |
                          starting  --- control socket answers `status` ---> running
                                              |
                                  pause <-> resume      save (paused) -> clone disk -> resume
                                              |
                                  shutdown (graceful)  or  stop (force)
                                              |
                                      runner exits, sockets removed
```

Beyond the runner itself, a VM's workspace keeps a stable MAC (a locally administered `02:..` address in `vz-mac`), a
`generic-id.bin` machine identifier for Linux guests, `efi.bin` for EFI boots, the console log, the guest address file `vz-ip`,
and `snapshots/<tag>/`.

## 3. vsock

Every runner serves a Firecracker-style vsock proxy on a unix socket (`vm.vsock_socket`, mode 0600, by default `vsock.sock` in the
workspace, relocated under `/tmp/fluxvm-<uid>/` if the path would be too long). A client connects, sends `CONNECT <port>\n`, and the
runner opens a vsock connection to that guest port and relays bytes both ways. The reply is `OK <port>`, or no reply at all with
`CONNECT <port> QUIET` (used by `ssh`'s ProxyCommand).

```
 daemon ---- "CONNECT 17777\n" ----> unix socket (vsock.sock)
                                          |  fluxvm-vz-runner
                                          |  VZVirtioSocketDevice.connect(toPort: 17777)
                                          v
                                    guest port 17777  (guest agent)
```

| Port | Direction | Purpose |
| --- | --- | --- |
| 17777 | host to guest | The FluxVM guest agent: exec, files, ping. Used by `agent-micro` sandboxes and always by container sandboxes ([vsock-proxy.md](vsock-proxy.md), [vsock-agent.md](vsock-agent.md)) |
| 22 | host to guest | sshd on vsock, so an offline guest (no network card) is still reachable over SSH. Stock Debian 13 images have `sshd-vsock.socket`. `fluxctl vsock-proxy <socket> 22` is the ProxyCommand |
| 3128 | guest to host | The runner's allow-list HTTP(S) proxy, for sandboxes with `allow_hosts` |
| 1026 | host to guest | The container warm-pool claim: the daemon sends a claim to a waiting slot's init ([section 11](#11-container-oci-sandboxes)) |

The relay copies both directions until each side has finished, then closes the unix socket and releases the vsock connection, so one
connection per command does not exhaust descriptors. The same relay carries the TCP forwards between guests and the egress proxy.

## 4. Guests

### Linux ARM64

- **Boot.** Either EFI from the disk (a per-VM `efi.bin` variable store), or direct kernel boot through `VZLinuxBootLoader` when the
  request has `kernel` (and optionally `initrd`, `kernel_args`). Both keep the generic platform, so snapshots work.
- **Disk.** A raw image cloned instantly with APFS `cp -c`. A qcow2 image is converted to raw while cloning, which needs `qemu-img`.
  `apple.root_read_only` attaches the root disk read-only.
- **cloud-init.** A NoCloud ISO built with `hdiutil`, with a MAC-based DHCP identity so the address stays stable. FluxVM also adds
  small systemd units through it (address reporting, the egress forwarder, shared-folder mounts).
- **Named images.** `debian-13` (also `debian-12`, `ubuntu-24.04`) is downloaded over HTTPS, checked against the vendor's published
  SHA file and cached under `<state_dir>/images`. Ubuntu ships qcow2, so it is converted to raw once. Named images are not catalog
  images, so `policy.require_catalog_names` rejects them.

### macOS guests

```
 IPSW (26.6 GB)                                   template (stopped, FileVault off)
      |  fluxvm-vz-runner install                       disk.raw  hardware.bin  auxiliary.bin
      v                                                         |
 disk.raw + hardware.bin + identity.bin + auxiliary.bin         |  cp -c  (instant, same APFS volume)
      |  boot, Setup Assistant by hand, Remote Login,           v
      |  SSH key, FileVault off, shut down            clone: own disk, own machine identifier
      +-------------------> template ------------->   (identity.bin created on first launch)
```

- **Install.** `fluxvm-vz-runner install --config <json>` installs from an IPSW and writes `hardware.bin`, `identity.bin` and
  `auxiliary.bin` beside the disk. It was run by hand on an Apple M4 with macOS 27.0.1 as the guest. Through the API it is
  `apple.install: true`, which is unit-tested against a fake runner and not yet run against a real IPSW ([section 14](#14-what-is-verified)).
- **Clone.** `POST /v1/vms` with `apple: {guest_os: "macos"}` and `image` set to the template's `disk.raw` clones the disk and takes
  `hardware.bin` and `auxiliary.bin` from beside it. The machine identifier is deliberately not copied: the runner gives every clone its
  own, so two clones are two machines, each with its own serial number. Keep the clone's state directory on the same APFS volume as
  the template, or the "clone" is a full copy of a 20+ GB disk.
- **Address by DHCP lease.** A macOS guest has no systemd and cannot print its address on the console, so the runner reads the Mac's
  DHCP leases (`/var/db/dhcpd_leases`) for the MAC the guest's card was given ([section 5](#5-address-discovery)).
- **FileVault must be off in the template.** With FileVault on, a clone boots with its volume locked and sshd refuses every key until
  one password login unlocks it. Run `sudo fdesetup disable` in the template, wait for decryption to finish (about 25 minutes for a
  50 GB disk on an Apple M4), shut down cleanly, and use that disk as the template. A fresh clone of such a template accepted the key on
  its first login ([macos.md](macos.md#macos-guests)). Alternatively `apple.firstboot` shares a helper that installs a root-owned
  `/etc/ssh/fluxvm_authorized_keys` so keys work before any home directory is unlocked; FluxVM cannot run it inside the guest for you.
- **Two macOS guests per Mac.** Apple's licence allows two macOS VMs at a time per Mac. FluxVM does not enforce this when it starts a
  VM: it is a *placement rule*, `MAX_MACOS_GUESTS = 2` in `fluxvm_scheduler::apple_placement`, which excludes a host that already runs two
  ([section 12](#12-mac-fleet)).
- **Not supported for macOS guests:** direct kernel boot, Rosetta, nested virtualization, clipboard, extra disks, private networks,
  console ports, tagged shares, and the FluxVM guest agent (so no exec over vsock).

## 5. Address discovery

The daemon needs the guest's IP to reach SSH and to point TCP forwards at. The runner finds it differently per guest:

| Guest | How the address is found |
| --- | --- |
| Linux with `cloud_init` | A systemd service FluxVM adds (`fluxvm-report-ip.service`) prints `VELORA-IP <addr>` on the serial console. The runner tails the log (only output written by this boot), parses the line and writes it to `vz-ip`; `GET /v1/vms/{id}` reports it as `guest_ip`. |
| Restored Linux guest | A restored guest does not print its address again, so the runner reads the one saved in `vz-ip` when the state was saved. |
| macOS | The runner polls `/var/db/dhcpd_leases` once a second for the MAC the card was given. The ARP table is not an option: macOS shows it empty to a spawned process. |
| Container sandbox | `fluxvm-oci-init` brings up `eth0` with its own DHCP client and prints `VELORA-IP <addr>`. |
| vmnet network | The 127.0.0.1 forward relay and IP discovery read the NAT lease file, so use `vmnet.forwards` instead. |

Each VM keeps a stable MAC across restarts. MACs of deleted VMs go back to a pool that new VMs reuse first, because the Mac's DHCP
server keeps one lease per MAC for a day: a fresh MAC per VM would run the /24 dry after about 250 creates, while a recycled MAC gets
its old address back.

## 6. Networking

| Mode | How to ask | What the guest sees | Notes |
| --- | --- | --- | --- |
| NAT | `network.mode = "user"` (default) | One card on Virtualization.framework's NAT; reachable from the Mac at its address | Guests on this NAT cannot reach each other. TCP only for forwards. Verified |
| None | `network.mode = "none"` | No network card at all | Commands and files still work over vsock. Verified |
| Allow-listed egress | `egress_allow` / `allow_hosts` (implies none) | No card; HTTP(S) only through the host's proxy | Verified |
| Private network | `apple.networks` | A second card on a user-space L2 switch shared only with guests on the same network | Linux guests; verified for container sandboxes |
| Per-VM vmnet | `apple.vmnet` (macOS 26+) | Its own vmnet network with a DHCP reservation and host forwards | **Unverified on hardware** |
| Bridge | `apple.bridge_interface` | On the host's LAN, for example a Mac Studio's 10GbE | **Unverified on hardware**; needs the networking build |

### NAT and forwards

TCP `forwards` listen on `127.0.0.1:<host_port>` (ports 1024 and up, because the daemon does not run as root) and the runner relays
them to the guest's address. A forward with `"guests": true` listens on the NAT gateway address (the Mac, as guests see it) instead, so
other guests can use it. That is how [stacks](macos-stacks.md) connect services.

### Allow-listed egress

```
 guest process --http_proxy--> 127.0.0.1:3128 (fluxvm-egress.service)
                                      |  vsock, guest to host, port 3128
                                      v
                         runner: allow-list check, then connect
                         (exact name or *.suffix, ports 80 and 443 only,
                          loopback / private / link-local / CGNAT refused)
                                      |
                                      v
                                 the internet
```

The guest has no card, so a program that ignores the proxy settings has no route. The host decides: names are matched in the runner,
DNS is done by the host, and a name that resolves to a private address is refused with a `403` naming the host. HTTPS is tunnelled
(`CONNECT`), not inspected. `egress_allow` requires `network.mode = "none"`, because with a card the guest could bypass the proxy.
Limits: HTTP and HTTPS only, tools must honour the proxy variables, and the list is fixed at creation
([macos-sandboxes.md](macos-sandboxes.md)).

### Private networks with `fluxvm-vz-switch`

Virtualization.framework's NAT keeps guests apart. `apple.networks` adds a second card on a private layer-2 network.

```
  guest A                  guest B
  (card 2)                 (card 2)
     |  datagram socket       |  datagram socket
     |  pair, one frame       |  pair, one frame
     |  per datagram          |  per datagram
     v                        v
  fluxvm-vz-runner A      fluxvm-vz-runner B
     |   SCM_RIGHTS hand-over of one socket end     |
     +--------------> fluxvm-vz-switch <------------+
                      /tmp/fluxvm-<uid>/vznet-<name>.sock
                      one process per network
```

- Each runner connects to the switch's unix socket, sends a hello with the VM id and MAC, and passes one end of a `SOCK_DGRAM` socket
  pair with `SCM_RIGHTS`; the other end backs a `VZFileHandleNetworkDeviceAttachment`.
- The switch forwards by the MAC each port registered with, drops frames with any other source MAC (no spoofing), floods broadcast and
  multicast, and drops unicast to unknown MACs. Frames above 1600 bytes are dropped.
- Each network name gets its own `10.89.N.0/24`. Addresses are static: a guest gets the lowest free host address from `.2`, or asks
  for `address` or `mac`. At most 4 networks per guest.
- The switch starts on demand and exits 30 s after the last guest leaves. A runner that loses its switch starts it again and
  reconnects.
- Guests on different networks, or on none, cannot reach each other. Works with `network.mode = "none"` but not with `egress_allow`.
- Honest limits: IPv4 /24s only, no DHCP, DNS or routing between networks, and the switch runs in user space, so it is slower than
  the NAT card.

### vmnet and bridge

`apple.vmnet` (macOS 26+) gives one VM its own vmnet network (`shared` or `host-only`) with a stable DHCP reservation for its MAC and
TCP/UDP host forwards. Each runner owns its network; VMs sharing one network need the broker designed in
the broker in [VMNET_BROKER.md](VMNET_BROKER.md): `apple.vmnet.name` makes a network shared, and `fluxvm-vmnetd` hands it to each runner
over XPC with Apple's serialisation. The broker is written but its runtime has **not** been verified (see section 14); an unnamed
`apple.vmnet` stays per runner. `apple.bridge_interface` puts the guest on the host's LAN; it needs `network.mode = "user"` with no `forwards` and a runner
signed with `com.apple.vm.networking`. The two are mutually exclusive. **Neither the per-VM vmnet network, the bridge nor the shared broker has been verified on hardware.**

## 7. Storage and snapshots

### Disks

- **Clone.** Root disks are APFS clones (`cp -c`), so a new VM takes almost no time or space until it writes. On a filesystem without
  clones the helper falls back to a plain copy.
- **Extra disks** (`apple.extra_disks`, Linux guests): `image` (a raw file), `block` (a host device) or `nbd` (an NBD export), on
  `virtio`, `nvme` or `usb` controllers. `block`, `nbd` and `nvme` need macOS 14. Virtualization.framework fixes a VM's devices when
  it starts, so attach and detach apply at the next start, except a USB image disk, which hot-plugs into a running guest (macOS 15).
  `scripts/vz-devices-live-test.sh` passes for virtio, NVMe and USB image disks, a host block device, an NBD export and USB
  hot-attach and detach.
- **ASIF overlay** (`asif_overlay`, macOS 27+): the base disk stays read-only and writes go to a sparse `disk-overlay.asif`, which
  snapshots include. **Unverified on hardware.**

### Snapshots

```
 POST /v1/vms/{id}/snapshot {"tag":"s1"}
        |
        v
 runner: pause -> saveMachineStateTo(state.vzvmsave)   (memory + device state)
        |
        v   guest still paused
 daemon: cp -c disk.raw, efi.bin / auxiliary.bin, disk-overlay.asif
        |   -> <workspace>/snapshots/s1/
        v
 runner: resume          (the guest continues)

 POST /v1/vms/{id}/restore {"tag":"s1"}   (VM must be stopped)
        -> clone the saved disk back, start the runner with restore_state, resume
```

Needs macOS 14 or later and Apple silicon. The snapshot is a coherent pair: memory and a disk clone taken while the guest was paused.

**Why a saved state is tied to the MAC and machine identifier.** The saved device state records the virtual hardware as it was. A
restore only works against the same configuration, so the VM keeps one machine identifier (`generic-id.bin`; a generic platform
would otherwise invent a new one on every launch) and one MAC address (`vz-mac`). Restoring with another MAC or identifier fails with
"invalid argument". The consequence for pools is in the next section.

Two practical limits: restoring needs an **unlocked login session** (the saved state is encrypted with a Secure Enclave key that is
unusable while the screen is locked; saving still works), and whether a restore survives a FluxVM runner upgrade has not been tested.
In the runner, restore is wired for Linux guests; snapshots of macOS guests are implemented but not yet exercised on a real macOS
guest ([macos.md](macos.md#snapshots-of-macos-guests)).

## 8. Warm pool and why each slot has its own MAC

A cold sandbox takes about 8 s; restoring a warm one takes about 2 s. The obvious design, one snapshot restored many times, does not
work, for two reasons from the section above: a saved state only restores with its own MAC and machine identifier, and two VMs
restored from one snapshot would share a MAC and so an address on the Mac's NAT, and the Mac would reach one or the other at random.

So each **slot** is an ordinary stopped VM with its own MAC and its own `warm` snapshot.

```
 build slot (background, one at a time)           claim (a default-shaped create)
 +-------------------------------------+          +-------------------------------------------+
 | cold-boot default sandbox           |          | skip stale slots (old base image)         |
 | label fluxvm.pool=sandbox           |          | skip a slot whose fluxvm.slot-ip a        |
 | label fluxvm.image-id=<build>       |          |   running VM already holds                |
 | wait for guest, label slot-ip       |          | restore the `warm` snapshot  (~2 s)       |
 | cloud-init status --wait            |          | relabel as a sandbox, set name and TTL    |
 | snapshot "warm", stop               |          | start a refill                            |
 +-------------------------------------+          +-------------------------------------------+
   stopped: costs disk, no RAM                      restore fails or no slot free -> cold-boot
```

- **Eligible creates:** default-shaped only: no `template`, no `spec`, no volumes, no resource overrides, not tenant-scoped. Anything
  else cold-boots. Slots are standard-sized (2 vCPU, 2 GiB), so `tiny` and `small` profiles cold-boot.
- **Size:** `sandbox.warm_slots`, default 2 on a Mac and 0 elsewhere. `POST /v1/sandboxes/warm {"count": N}` (1 to 64, never below
  `warm_slots`) fills it further before a burst; surplus slots stay until claimed or deleted. A slot costs an APFS clone plus a few
  hundred MB of saved memory, and no RAM while stopped.
- **The slot-ip address-skip rule.** Slots are built one after another, and the NAT frees a stopped guest's address, so two slots can end
  up with the same one. A restored guest cannot change its address. Each slot records its address in the `fluxvm.slot-ip` label when
  it is built, and a claim skips any slot whose address a running VM already holds; that create cold-boots instead of sharing the
  address. (This is the fix from #184.)
- **The pool follows the base image.** Slots are labelled with the build of `debian-13` they came from (`fluxvm.image-id`). When a
  newer build is downloaded (the vendor's list is checked at most once a day), old slots are never restored, are deleted, and the pool
  is rebuilt.
- **Needs** an unlocked login session. Without one, the restore fails and the create cold-boots.

## 9. Devices

| Device | Notes |
| --- | --- |
| virtiofs shares | `shared_folders` become shares tagged `fs0`, `fs1`, ... that the guest mounts via `/etc/fstab`; `read_only` is enforced by the host. macOS guests (host macOS 13+) get one automount device under `/Volumes/My Shared Files`. `apple.tagged_shares` adds shares with fixed tags; `share-set` re-points a running share |
| USB | `usb_controller: true` adds an XHCI controller (macOS 15+). Disk-image hot-attach and detach through the control socket. Physical devices are exposed through the control socket only (`usb-physical-list`, `usb-physical-attach`; no REST route or `fluxctl` command) and need the separately signed `FluxVMUSBAccess.app` (macOS 27+). **Unverified on hardware**: the helper was killed at launch in our test (section 14) |
| Memory balloon | Every VM has a balloon device. `GET`/`POST /v1/vms/{id}/balloon` set the target; idle reclaim uses it. **Reclaim unverified on hardware** |
| Display | Linux: virtio-gpu scanout; macOS: Mac graphics with `display_count` 1 to 8 (**multi-display unverified on hardware**). Width 800 to 5120, height 600 to 2880, PPI 72 to 300. `window: true` opens a window that the guest follows when resized. A 1600x900 Linux display is covered by `scripts/vz-devices-live-test.sh` |
| Audio | Output to the host's default device is on by default; `microphone` is off by default and makes macOS ask for access |
| Rosetta | `rosetta: true` adds a Rosetta share (Linux guests; the guest mounts it and registers binfmt). Needs Rosetta installed. Used for `linux/amd64` container sandboxes, which `scripts/oci-live-test.sh` covers |
| Nested virtualization | `nested_virtualization: true`, Linux guests, macOS 15 and an M3 or later; fails clearly otherwise |
| Clipboard | `clipboard: true` adds a SPICE agent port (Linux guests; the guest needs `spice-vdagent`). **Unverified on hardware** |
| Console ports | `apple.console_ports` (Linux guests, up to 8) adds virtio console ports at `/dev/virtio-ports/<name>`; the runner bridges each to `/tmp/fluxvm-<uid>/<vm id>.port-<name>` (mode 0600). `fluxctl port-connect` or the websocket `GET /v1/vms/{id}/ports/{name}`. Covered by `scripts/vz-devices-live-test.sh`, both directions |
| Serial console | A Linux guest's serial console goes to `console.log`, rotated to `console.log.1` past `serial_log_max_mib` (default 16) |
| Custom Virtio | `custom_virtio: true` (macOS 27+, Linux guests) adds a vendor virtio device with device id `0x3F` (PCI `1af4:107f`) and two queues: 0 is a bounded JSON control plane (ping, echo, capabilities, stats), 1 is bulk guest-memory operations (zero, fill, copy, CRC32, up to 64 MiB) through `VZGuestMemoryMapping`. The Linux driver is in `guest/virtio-flux`. The id must be at most `0x3F`: Linux binds only PCI ids `0x1040` to `0x107f`, and the earlier `0xFF00` produced `1af4:0f40`, which nothing binds. Control requests work on hardware; all four bulk operations verified (section 14) |

## 10. Agent sandboxes

A sandbox is a disposable Linux VM behind `POST /v1/sandboxes`, `/process`, `/fs/read` and `/fs/write`, with the MCP tools
`sandbox_create`, `sandbox_exec`, `sandbox_read_file`, `sandbox_write_file` and `sandbox_logs` on top. With no `template` and no
`spec`, a Mac creates a 2-vCPU, 2 GiB Debian 13 VM. Details: [macos-sandboxes.md](macos-sandboxes.md) and
[agent-density.md](agent-density.md).

### Request path

```
 agent --REST/MCP--> daemon
                       |
          agent enabled? ---yes---> CONNECT 17777 on vsock.sock --> guest agent --> answer (final, even an error)
                       |                          | unreachable
                       no                         v
                       +-----------------> SSH to the guest's address
                                           (or, offline: to sshd on vsock port 22)
```

- **Guest agent or SSH.** Stock cloud images (`debian-13`) have no agent, so the daemon uses SSH with its own key
  (`<state_dir>/sandbox_ed25519`), moving files with `cat`/`chmod` (32 MiB per file). Sandboxes with the agent enabled use vsock first
  and fall back to SSH only when the agent does not answer. A per-exec `policy` (Landlock and seccomp) and argv exec need the agent.
  `/metrics` counts agent calls and SSH fallbacks.
- **`agent-micro`.** Debian 13's arm64 cloud image with the static guest agent installed and enabled ([agent-micro.md](agent-micro.md)).
  It is a catalog entry you build on Linux and register with `fluxctl catalog add`; no published build exists, and its boot time and
  size on a Mac are not measured. `agent-micro` sandboxes cold-boot.
- **MCP.** `fluxctl mcp serve --allow-write` offers the same operations to an agent over stdio.

### Profiles and admission

| Profile | vCPUs | Memory |
| --- | --- | --- |
| `tiny` | 1 | 512 MiB |
| `small` | 1 | 1 GiB |
| `standard` | 2 | 2 GiB |

An explicit `vcpus` or `memory_mib` wins. Admission on a Mac samples available memory from `vm_stat` and the kernel's
`kern.memorystatus_vm_pressure_level`. `policy.deny_host_pressure_level`, `min_host_mem_available_mib` and `pressure_defer_secs`
(all off by default) refuse or defer a create under pressure, audited as `quota.deny`. FluxVM does not enforce VM memory on a Mac:
the Mac's own memory pressure applies.

### Idle stages

Three stages, all off by default, driven by one scan (`sandbox.autopause_scan_secs`) and applied only to VMs labelled
`fluxvm.sandbox`:

| Setting | After this long idle | Frees | On the next request |
| --- | --- | --- | --- |
| `idle_balloon_secs` | inflate the balloon | `idle_balloon_percent` of its memory | deflated at once |
| `autopause_idle_secs` | pause the VM | CPU only | resumed at once |
| `hibernate_idle_secs` | save memory to disk and stop | all of its memory | restored, about 2 s |

A hibernated sandbox shows as `stopped` with the label `fluxvm.hibernated`. Hibernate uses snapshot restore, so it needs an unlocked
login session; if the restore fails, the sandbox cold-boots, losing memory but keeping its disk. No live-test script named in this
page exercises the idle stages.

### Density report

`GET /v1/sandboxes/density` (or `fluxctl sandbox density`) reports configured and ready warm slots, hits and misses, counts of
active, paused and hibernated sandboxes, `resident_estimate_mib` (the *configured* memory of running and paused sandboxes, not a
measurement of resident memory), host memory and pressure level, and the `oci_warm_*` fields for the container pool. `/metrics` adds
`fluxvm_sandbox_warm_hits_total` and `fluxvm_sandbox_warm_misses_total`. `scripts/density-smoke.sh` creates a batch and prints the
report, which is the quickest way to find the real number for a host.

### Speculate

`POST /v1/sandboxes/{id}/speculate` snapshots the sandbox, runs a command, records which files under the given `paths` changed, then
relaunches the VM from the snapshot. The result is a pending changeset that you approve and apply, with a conflict if those files
changed meanwhile. Only file changes are captured; network calls the command made really happened.

## 11. Container (OCI) sandboxes

A sandbox can be a container image, with one lightweight VM per container and no Docker, no shared Linux VM and no SSH
([oci-sandboxes.md](oci-sandboxes.md)).

```
 pull (host, pure Rust)              rootfs cache                    per-sandbox
 +-----------------------+     +--------------------------+     +----------------------------------+
 | resolve ref, pick     |     | builder VM (no network): |     | APFS clone of <digest>.ext4      |
 | linux/arm64 or amd64, | --> | mke2fs, apply layers     | --> | VZLinuxBootLoader: oci-kernel +  |
 | verify every digest   |     | with whiteouts, check    |     | oci-initrd, no firmware          |
 | into state_dir/oci    |     | diff_ids, once per       |     | fluxvm-oci-init is PID 1:        |
 +-----------------------+     | manifest digest          |     |  mount root, DHCP, volumes,      |
                               +--------------------------+     |  start agent, run the process    |
                                state_dir/oci/rootfs/<digest>.ext4  +-------------+------------------+
                                                                                 |
                                       ready = guest agent answers ping on vsock 17777
```

- **Rootfs cache.** The first use of an image pulls it and builds an ext4 rootfs once per manifest digest in a short-lived builder VM
  that has no network card (build timeout 15 minutes). Later sandboxes only clone it.
- **Isolation.** A hypervisor boundary per container. The root is read-only (an overlay with a tmpfs), the process runs as
  `65534:65534` unless the image or request says otherwise, with `no_new_privs`. Exec and files go only through the guest agent with a
  per-VM token; there is no SSH fallback.
- **Profiles.** 1 vCPU and 512 MiB by default, 512 MiB being the minimum (`vz` will not start a VM with less). Profiles, admission,
  quotas and TTLs apply as for any sandbox.
- **Own warm pool.** `apple.oci_warm_slots` (default 0) keeps pre-booted container VMs per size in `apple.oci_warm_sizes`. A slot is a
  *running* VM whose init waits on vsock port 1026, with a 1 MiB placeholder root disk, a USB controller and four placeholder volume
  shares. A claim clones the rootfs, points the volume shares at the volumes with `share-set`, hot-attaches the rootfs as USB mass
  storage, and sends the claim over vsock 1026; init mounts `/dev/sda` and carries on as on a cold boot. Needs macOS 15. Waiting slots
  hold their memory, unlike the stopped slots of the Debian pool. A failed claim deletes the slot, cold-boots the sandbox, and pauses
  refills for 10 minutes.
- **x86-64.** `platform: linux/amd64` runs under Rosetta; the kernel and init stay arm64.
- **Limits.** `linux/arm64` and `linux/amd64` only, no image building, no GPUs, TCP ports only, and boot artifacts must be built on
  Linux arm64 (`scripts/build-oci-boot.sh`). Hibernation has not been tested on container sandboxes.

## 12. Mac fleet

Several Macs, each running `fluxctl serve`, can share bursts of sandboxes ([macos-cluster.md](macos-cluster.md),
[kairon-mac-scheduling.md](kairon-mac-scheduling.md)).

```
 Mac Studio                Mac Studio                Mac mini
 fluxctl serve (vz)        fluxctl serve (vz)        fluxctl serve (vz)
 fluxvm-agent node --+     fluxvm-agent node --+     fluxvm-agent node --+
                     +------------+------------+-----------------------+
                          fluxvm-agent central   (or Kairon)
```

- **Kairon labels.** Each Mac registers as a node with static labels such as `kairon.zyvor.dev/backend.vz=true`,
  `kairon.zyvor.dev/chip` and `kairon.zyvor.dev/memory-gib`. Labels are fixed at agent start, so anything that changes (pressure, warm
  slots) is reported in `density`, not in labels. Kairon's Mac node reports allocatable memory as unified memory minus the larger of
  3 GiB and a quarter.
- **Heartbeat.** `fluxvm-agent node` heartbeats every 10 s with total vCPUs and memory, VM count, labels, and the `density` report. On a Mac it also sends `apple` capabilities: it takes memory from `hw.memsize`, runs the signed runner's `host-capabilities` mode, and counts running macOS guests.
- **Built-in central placement.** `POST /fleet/vms` without a `node` picks from healthy, uncordoned nodes whose labels match the
  `nodeSelector`; skips nodes at **critical** memory pressure; prefers **normal** (or none reported) over **warn**; then takes the most
  residual capacity, then fewer VMs. The daemon's own admission is the last check.
- **`apple_placement`.** `fluxvm_scheduler::apple_placement` is a pure scorer. A host is `AppleHostCaps` (free CPU and memory, nested
  virtualization, vmnet, custom Virtio, bridgeable interfaces, running macOS guests); a request is reduced from a `CreateVmRequest`.
  `score` excludes a host that lacks the resources or a needed feature, or that already runs two macOS guests, and otherwise prefers
  the tightest fit, so small agent VMs pack onto busy hosts and the big Macs stay free. `pick` returns the best host.
- **Placement in central.** For `POST /fleet/vms` with `backend: vz`, central builds the request from the body (`apple.guest_os`,
  `nested_virtualization`, `vmnet`, `custom_virtio`, `bridge_interface`) and applies `apple_placement::score` to each node's `apple`
  caps; nodes that report none are excluded for `vz` requests. Other backends keep the existing capacity, security and selector scoring.
  Checked only on loopback with one real Mac and two fake registrations (section 14); `apple_placement_request` and the `vz` filtering have unit tests in `central.rs` (request parsing, skipping nodes without Apple capabilities, feature requirements, the two-macOS-guest limit).
- **One Mac.** With one node, placement always picks it.

## 13. Version gates

The runner is built for macOS 14 and later. Features above that check the host at run time and fail with a clear message.

| Host macOS | What it enables |
| --- | --- |
| 13 | Shared folders for macOS guests |
| 14 | Everything in the runner's baseline; snapshots (`save`, restore); block-device, NBD and NVMe extra disks |
| 15 | Nested virtualization (also needs an M3 or later); XHCI USB controller; USB disk hot-attach and detach; the container warm pool |
| 26 | `apple.vmnet` networks; the shared-network broker `fluxvm-vmnetd` (named networks) |
| 27 | `custom_virtio` (and its guest-memory mapping); physical USB passthrough through `FluxVMUSBAccess.app`; `asif_overlay` (DiskImageKit); unattended macOS first boot (`provision_*`) |

The `capabilities` and `host-capabilities` control commands report `nestedVirtualization`, `vmnetCustomNetworks`, `vmnetSerialization`, `customVirtio`, `customVirtioQueueBackend`, `guestMemoryMapping` and `usbPassthroughAPI` for a given Mac. Features
without a gate (bridge, clipboard, multiple displays, balloon) are restricted by entitlement or guest type, not by OS version.

## 14. What is verified

All hardware checks below ran on an Apple M4 with macOS 27.2 ([macos.md](macos.md#what-is-verified)). No Intel Mac has been tried.

| Status | What | Covered by |
| --- | --- | --- |
| **Verified** | VM lifecycle through the API, address, SSH, TCP forwards (host and guest to guest), shared folders, pause and resume, stop and start, snapshot and restore, named images, `fluxctl run` cold and warm, a two-service stack | `scripts/macos-live-test.sh` |
| **Verified** | Sandboxes: exec, files, TTL, warm pool and its refresh after an image update, concurrent creates, offline, allow-listed egress, speculate and changesets | `scripts/macos-live-test.sh` |
| **Verified** | Container sandboxes: exit codes, uid, read-only root, exec, distroless argv exec, offline, allow-list, a private network between two sandboxes, `linux/amd64` under Rosetta, a warm-pool claim, TTL | `scripts/oci-live-test.sh` (with the `oci-boot` CI artifacts) |
| **Verified** | Extra disks on virtio, NVMe and USB, a host block device, an NBD export, USB hot-attach and detach, a console port both ways, a 1600x900 Linux display | `scripts/vz-devices-live-test.sh` |
| **Verified** | Cloning a prepared macOS guest through the API, the reported address, SSH, delete | `scripts/macos-guest-live-test.sh` (needs your own template via `FLUXVM_MACOS_TEMPLATE`; CI does not run it) |
| **Verified** | A Kairon `vz` Machine scheduled to the Mac and run through FluxVM | [macos-cluster.md](macos-cluster.md) |
| **Verified by hand only** | macOS IPSW install with a macOS 27.0.1 guest; the FileVault-off template and key login on a fresh clone | manual runs ([macos.md](macos.md#macos-guests)) |
| **Implemented, not verified on hardware** | Installing macOS through the API (`apple.install`); first-boot keys; snapshots of macOS guests; `provision_*`; vmnet; bridge; clipboard; multi-display; ASIF overlay; balloon reclaim; custom Virtio's bulk queue | unit tests, a fake runner, or admission checks only |
| **Implemented, not covered by a named live test** | Idle stages (balloon, pause, hibernate), memory-pressure admission, nested virtualization, Rosetta in full VMs, audio, `agent-micro` (built and booted by hand on an M4, where `scripts/e2e-smoke.sh` passed with the guest agent answering over vsock; never built or booted in CI) | |
| **Unit-tested only** | Container published ports, volumes, restart and health checks, `secret_env`, stacks of containers, `--fleet` placement | |
| **Not verified** | Multi-Mac clusters (placement was checked only on one Mac plus fake nodes, below), Thunderbolt RDMA, any Intel Mac, the Linux-only crates (`fluxvm-procbox`, `fluxvm-container-*`, `fluxvm-microvm`, `fluxvm-kube`, the eBPF agent) | |
| **Written, not verified at runtime** | The shared vmnet broker (`fluxvm-vmnetd`) and physical USB passthrough (`FluxVMUSBAccess.app`): built and ad-hoc signed, but killed at launch on a SIP-on host (see below) | [VMNET_BROKER.md](VMNET_BROKER.md) |

### Verification of #198/#199 (2026-10-10, one Apple M4, macOS 27.2)

One Apple M4, 16 GiB, macOS 27.2 (build 26B5101f), SIP on, no `sudo`, AMFI default.

| Gate | Result | Detail |
| --- | --- | --- |
| Unit tests and clippy | Verified | `--lib` tests pass: fluxvm-agent 55, fluxvm-apple 49 (plus 1 integration `backend` test and 6 source-contract tests), fluxvm-core 79, fluxvm-scheduler 204. `clippy -p fluxvm-apple -p fluxvm-agent -D warnings` passes. The source-contract tests only grep Swift and C source text; they do not exercise behaviour |
| Format gate | Verified with fix | `scripts/ci-fmt-check.sh` failed on main (unformatted `crates/fluxvm-apple/tests/vz27_source_contract.rs`); fixed in PR #200 |
| `fluxvm-vz-runner host-capabilities` | Verified | On the M4: macOS 27.2, 10 CPUs, 16 GiB, `maximumVmCPUs` 64, nested, vmnet custom networks, vmnet serialisation, custom Virtio and its queue backend, guest-memory mapping and USB passthrough API all true; bridged interfaces `en5`, `en0`. The Rust decode works on this output and the node heartbeat used it |
| Fleet placement (loopback) | Verified, limited | One real `fluxvm-agent node` plus two fake registrations (one Apple node without custom Virtio, nested or vmnet; one with no `apple` caps). The real node's heartbeat carried `apple` caps. `backend: vz` requests (with `custom_virtio`, with `nested_virtualization`, and with no apple options) all landed on the real node despite the fakes' larger capacity. No second Mac was used |
| Named shared vmnet VM | Blocked | Placed on the real node (the only vmnet-capable one), then failed with `vmnetd XPC connection failed` because the broker was not running |
| Shared vmnet broker (`fluxvm-vmnetd`) | Blocked | Built with `xcrun swiftc` (macOS 26 target) and ad-hoc signed with `com.apple.vm.networking`; killed immediately (exit 137, SIGKILL) on this SIP-on host. The installer needs `sudo` (no password available) and `launchctl bootstrap`, which the session's permission check refused |
| Two runners on one `apple.vmnet.name` | Not run | Depends on the broker |
| Physical USB passthrough | Blocked | `FluxVMUSBAccess.app` built and ad-hoc signed with `com.apple.developer.accessory-access.usb`; killed immediately (exit 137). No USB devices were attached. `usb-physical-list` and `usb-physical-attach` not run |
| Custom Virtio guest bus, as merged (id `0xFF00`) | Failed | Debian 13 (kernel 6.12.111+deb13-arm64) saw PCI `1af4:0f40` with no driver and no virtio device: the PCI id is `0x1040 + id` truncated to 16 bits, outside `0x1040` to `0x107f`. `virtio_flux` could never attach |
| `virtio_flux.c` on kernel 6.12 | Verified with fix | Did not compile (missing `virtio_config.h` include, `no_llseek` removed, `virtio_find_vqs` now takes `struct virtqueue_info`, `virtio_set_drvdata` removed). Fixed in PR #200 |
| Custom Virtio at id `0x3F` (PR #200) | Verified (queue 0) | PCI `1af4:107f` binds as virtio9; `/dev/fluxvm` and `/dev/fluxvm-bulk` appear; `fluxvm_virtioctl ping` returns pong with the VM id, `echo` echoes, `stats` returns counts, `capabilities` lists 2 queues, bulk zero/fill/copy/crc32, `bulk_max_bytes` 67108864, `guest_memory_mapping` true |
| Custom Virtio bulk queue (queue 1) | Verified with fix | `fluxvm_virtioctl bulk-test` hung because the driver gave the device a kernel-stack buffer (invalid with VMAP_STACK); the host saw the notification but `nextElement()` returned nil. With a heap buffer all four operations pass at sizes from 1 B to 1 MiB: the guest checks the fill, the zeroing and the copy byte for byte, the host-computed CRC32 equals the guest's own, and the fill CRC equals zlib's. 8 bulk requests, 0 errors on the device. 64 MiB (the host cap) was not tried. Root cause not found |
| Multi-Mac placement | Not run | No second Mac |

Central's `apple_placement_request` and `vz` filtering have four unit tests (they do not replace a run on two real Macs). `fluxvm-container-agent` and `fluxvm-containerd-shim` do not build on macOS (unrelated).

The hosted CI jobs for the `vz` pull requests have not all been green; see the pull requests for their state.

## 15. Measured numbers

Everything here comes from the repository docs and was measured on one Apple M4 running macOS 27.2. Each row names its source. These
are single-machine figures, not benchmarks, and a few are approximate in the source.

| Measurement | Value | Source |
| --- | --- | --- |
| Cold VM boot | about 10 s | [macos.md](macos.md#quick-start) |
| `fluxctl run` warm start | 2 to 3 s (restore about 2 s) | [macos.md](macos.md#quick-start) |
| Snapshot | 0.7 s | [macos.md](macos.md#quick-start) |
| Restore to SSH | 1.4 s | [macos.md](macos.md#quick-start) |
| Sandbox create, cold | about 8 s (7.6 s in one run) | [macos.md](macos.md#quick-start), [macos-sandboxes.md](macos-sandboxes.md#verified) |
| Sandbox create, warm pool | about 2 s | [macos.md](macos.md#quick-start) |
| Two warm slots built after the first create | about 15 s | [macos-sandboxes.md](macos-sandboxes.md#verified) |
| Two concurrent creates from the pool | 1.7 s and 3.6 s | [macos-sandboxes.md](macos-sandboxes.md#verified) |
| Create after the pool was consumed and refilled | 1.9 s | [macos-sandboxes.md](macos-sandboxes.md#verified) |
| Offline sandbox cold boot | about 6 s | [macos-sandboxes.md](macos-sandboxes.md) |
| Speculate, small command | about 5 s | [macos-sandboxes.md](macos-sandboxes.md) |
| Container sandbox, cold start (`alpine:3.22` cached) | about 1.75 s | [oci-sandboxes.md](oci-sandboxes.md#verified) |
| Container warm-pool claim | about 1.3 s, of which about 0.9 s is resolving the tag on Docker Hub | [oci-sandboxes.md](oci-sandboxes.md#verified) |
| FileVault decryption of a 50 GB macOS template disk | about 25 minutes | [macos.md](macos.md#macos-guests) |
| First boot of a macOS clone from a USB drive | about 5 minutes to SSH at 37 MB/s | [macos.md](macos.md#macos-guests) |
| macOS restore image / installed disk | 26.6 GB / about 24 GB (plan for 55 GB or more free) | [macos.md](macos.md#macos-guests) |

**Estimates, not measurements.** [agent-density.md](agent-density.md#rough-capacity) gives rough counts of active `tiny` sandboxes:
4 to 8 on a 16 GB Mac mini, 12 to 20 on a 36 GB Mac Studio, 25 to 40 on a 64 GB or larger Mac Studio. The source states they are
estimates that host load, the guest image and what the agents run will change.

**Not measured.** There is no per-sandbox memory measurement in the repository, so this page does not quote one. The `agent-micro`
boot time and image size on a Mac are also unmeasured.

## Where to go next

- [macos.md](macos.md): quick start, every option, and the honest limits.
- [macos-sandboxes.md](macos-sandboxes.md), [agent-density.md](agent-density.md), [agent-micro.md](agent-micro.md): agent sandboxes.
- [oci-sandboxes.md](oci-sandboxes.md): container sandboxes.
- [vsock-proxy.md](vsock-proxy.md), [vsock-agent.md](vsock-agent.md): the vsock path.
- [macos-cluster.md](macos-cluster.md), [kairon-mac-scheduling.md](kairon-mac-scheduling.md): several Macs.
- [VMNET_BROKER.md](VMNET_BROKER.md): the shared vmnet design.
