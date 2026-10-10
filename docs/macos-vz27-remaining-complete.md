# macOS 27 VZ: remaining full-stack implementation

This change finishes the post-#198 work in one PR.

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

## Production gates

Code/static tests are necessary but not sufficient for these Apple APIs. Before a release is marked production-ready, record a real Apple-silicon macOS 27 run covering:

1. Xcode 27/current SDK compile of the runner, vmnetd and USB helper.
2. Linux guest with `virtio_flux.ko`: ping, capabilities and `bulk-test`.
3. Two independent runner processes on one named vmnet network, bidirectional TCP+UDP.
4. Accessory Access consent, USB list, attach to a running VM, guest enumeration, detach and host reappearance.
5. Fleet registry with at least two Macs where a nested/custom-Virtio request is rejected from an incapable node and placed on a capable one.

No generic Linux CI run can substitute for these five hardware checks.
