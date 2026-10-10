# macOS 27 VZ: remaining full-stack implementation

This change finishes the post-#198 work in one PR. Everything below is implemented; what was and was not verified on hardware is listed under "Hardware status" at the end.

## 1. virtio-flux guest path

The host custom device is ID `0x3f` with two virtqueues. Queue 0 is the bounded JSON control plane. Queue 1 is now active for guest-memory operations through `VZGuestMemoryMapping`: zero, fill, copy and CRC32, capped at 64 MiB per request. The Linux out-of-tree driver exposes `/dev/fluxvm` and `/dev/fluxvm-bulk`; `fluxvm-virtioctl bulk-test` allocates guest memory, asks the host to mutate it by guest physical address, then verifies the bytes and CRC in the guest.

The existing vsock guest agent remains the **host→guest management plane** (exec, file copy, shell, shutdown). `virtio-flux` is the **guest→host high-performance service/telemetry plane**. This avoids inventing a polling protocol merely to duplicate a management channel VZ already provides efficiently through vsock.

## 2. shared vmnet broker

`apple.vmnet.name` makes a vmnet network named and shareable. A per-user `fluxvm-vmnetd` launch agent owns the `vmnet_network_ref`; runners acquire the same network through Apple's `vmnet_network_copy_serialization` / `vmnet_network_create_with_serialization` XPC representation. The broker rejects reuse of a name with a different configuration and reference-counts acquisitions.

Unnamed `apple.vmnet` preserves the existing per-runner behavior.

## 3. physical USB Accessory Access

`FluxVMUSBAccess.app` registers `AAUSBAccessoryManager` and owns the user-consent lifecycle. It exports the authorized accessory's XPC representation to the runner. The runner reconstructs `AAUSBAccessory`, creates `VZUSBPassthroughDeviceConfiguration`, and hot-attaches a `VZUSBPassthroughDevice` to the VM's XHCI controller.

The runner control protocol adds:

- `usb-physical-list`
- `usb-physical-attach` with `registry_id`
- existing `usb-detach` detaches either mass-storage or passthrough devices by VZ UUID.

## 4. Apple-aware fleet placement

`fluxvm-agent node` now works as a Mac fleet heartbeat source: macOS memory comes from `hw.memsize`, the node queries the signed VZ runner's new `host-capabilities` mode, counts active macOS guests, and reports `AppleHostCaps`. Central placement applies `fluxvm_scheduler::apple_placement::score` for automatic `backend: vz` requests while retaining existing capacity/security/selector scoring for every other backend.

## 5. API coverage against the macOS 27 SDK

Checked against WWDC26 session 224, the macOS 27 SDK headers (Virtualization, vmnet) and the macOS 27 release notes.
`tests/vz27_api_coverage_contract.rs` fails if the runner stops using any API below.

| Area | API | Where | Hardware |
|---|---|---|---|
| Guest provisioning | `VZMacGuestProvisioningOptions`, `setGuestProvisioning`, `guestProvisioningInvalid*` errors | `ModernFeatures.swift`, `SecureBoot.swift` | earlier gate |
| EFI Secure Boot | `enableSecureBoot(platformKey:)`, `enableSecureBootUsingDefaultPlatformKey`, `disableSecureBoot`, `resetSecureBoot`, `enrollDefaultSecureBootSignatures`, `enrollSecureBootSignatures`, `isSecureBootEnabled`, `enrolledSecureBootSignatures`, `VZEFISignatureList`, `efi*` errors | `SecureBoot.swift` | enable/status/disable verified on the M4 |
| Custom Virtio | provider, `didCreateDevice`, notifications, `DidAcceptDriverOk`, `WillStop/Pause/Resume/Reset`, `SaveState(forRestore:)`, `ShouldRestore`, `requestReset`, `guestMemoryMapping` | `CustomVirtio.swift` | control, bulk operations, driver-ready/pause/resume/stop, save/restore and `requestReset` (with the driver's NEEDS_RESET handler) verified |
| USB | `VZUSBPassthroughDevice`, `VZUSBController.Delegate` (`usbPassthroughDeviceDidDisconnect`) | `USBPassthrough.swift` | not run (no consent helper) |
| Configuration and view | `VZVirtualMachineConfiguration.label`, `VZVirtualMachineViewAdaptor` | `Runner.swift` | label verified; window not opened |
| DiskImageKit | `VZDiskImageStorageDeviceAttachment(diskImage:)` | `ModernFeatures.swift` | earlier gate |
| vmnet (macOS 26) | subnet, DHCP reservation, port forwards, IPv6 prefix, MTU, external interface, disable DHCP/DNS proxy/NAT44/NAT66/RA, serialization | `AdvancedNetwork.swift`, `VmnetOptions.swift`, `vmnetd` | not run |
| Earlier APIs | network `attachmentWasDisconnected`, NBD delegate, `blockDeviceIdentifier`, `startUpFromMacOSRecovery`, Rosetta availability/install/caching, save/restore for macOS guests | `Runner.swift`, `ModernFeatures.swift` | Rosetta availability verified |

Not applicable: `VZCustomVirtioDevice` has no host interrupt call (completions interrupt the guest), and vmnet has no DHCP pool
setter, so `dhcp_start`/`dhcp_end` stay refused. Release-note workarounds: passed-through USB devices are detached before
`save` (174267926), and `save` is refused while a hot-plugged USB disk is attached (177528319).

## Hardware status (2026-10-10, one Apple M4, macOS 27.2)

Details in [macos-architecture.md](macos-architecture.md#14-what-is-verified).

1. Runner `host-capabilities`: verified. Compile of the vmnetd and USB helper: built, but both were killed at launch (SIGKILL) under ad-hoc signing on a SIP-on host.
2. Linux guest with `virtio_flux.ko`: after PR #200 (id `0x3F`, kernel 6.12 build fixes), `ping`, `echo`, `stats` and `capabilities` work. all four bulk operations (queue 1) pass after the driver stopped using a stack buffer for its request; sizes up to 1 MiB.
3. Two runners on one named vmnet network: not run (broker could not start).
4. Accessory Access consent, USB list and attach: not run (helper could not start; no USB devices attached).
5. Fleet placement: verified only on loopback with one real Mac and two fake nodes; no second Mac.
6. EFI Secure Boot: verified with an EFI guest on an empty disk: default keys enrolled (2 KEK, 2 db, 26 dbx), `secure-boot-status`
   reports enabled, `secure_boot: false` disables it and keeps the keys. Booting a signed distro under Secure Boot is not run.
7. Custom Virtio save/restore: Debian 13 guest with `virtio_flux.ko`, snapshot, stop, `start-from-snapshot`. The guest resumed without
   a reboot, `ping` and `echo` answered, and the device counters continued from the saved values. Without `supportsSaveRestore` the
   save failed with "Unsupported custom virtio device in configuration"; the runner now sets it.

## Production gates

Code/static tests are necessary but not sufficient for these Apple APIs. Before a release is marked production-ready, record a real Apple-silicon macOS 27 run covering:

1. Xcode 27/current SDK compile of the runner, vmnetd and USB helper.
2. Linux guest with `virtio_flux.ko`: ping, capabilities and `bulk-test`.
3. Two independent runner processes on one named vmnet network, bidirectional TCP+UDP.
4. Accessory Access consent, USB list, attach to a running VM, guest enumeration, detach and host reappearance.
5. Fleet registry with at least two Macs where a nested/custom-Virtio request is rejected from an incapable node and placed on a capable one.

No generic Linux CI run can substitute for these five hardware checks.
