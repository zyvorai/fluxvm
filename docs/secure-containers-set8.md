# Secure Containers — Set 8: raw block and VFIO device passthrough

Set 8 adds real hardware-device attachment to the QEMU-backed Secure Containers path. It does not emulate host device nodes inside the guest.

## Raw block volumes

A bind source that is a block device is accepted only when it is inside the current Kubernetes Pod's `/var/lib/kubelet/pods/<uid>/volumeDevices` tree, or under an operator-supplied `FLUXVM_CONTAINER_BLOCK_ALLOW_PREFIXES` prefix. OCI `linux.devices` block entries are reverse-resolved by major/minor into that same Pod-scoped tree before use.

The shim attaches the host block device to the running Pod VM through QMP using `blockdev-add` (`host_device`) followed by `device_add` (`scsi-hd`) on the pre-existing `scsi0.0` controller. Each attachment gets a deterministic `fluxvm-<hash>` SCSI serial. The OCI spec passed to the guest carries only that serial, never a host major/minor. The guest agent waits for the matching `/sys/class/block/*/device/serial`, resolves the real guest `/dev/<node>`, and bind-mounts that device at the container target.

This preserves the hardware-VM boundary and prevents accidentally targeting an unrelated guest device that happens to reuse a host device number.

## VFIO / GPU / device-plugin path

Non-built-in OCI character devices are mapped to their host PCI parent through `/sys/dev/char/<major>:<minor>/device`. Passthrough is allowed only when:

- the PCI BDF is explicitly listed in `FLUXVM_CONTAINER_VFIO_ALLOW`;
- the host PCI function is already bound to `vfio-pci`;
- QEMU has a free `hotplug-pcie-*` root port;
- the guest image has the required driver and creates the requested guest device path (for example `/dev/nvidia0`).

Set 8 deliberately does **not** unbind production host drivers or rebind devices to VFIO automatically. That is node/device-management policy and must happen before the workload is scheduled.

The shim marks passthrough character entries so the guest agent bind-mounts the driver-created guest node into the container rootfs. Host major/minor values are never recreated inside the guest.

## Configuration

- `FLUXVM_CONTAINER_DEVICE_PASSTHROUGH=1` — enable Set 8 device handling (default on; policy gates still apply).
- `FLUXVM_CONTAINER_BLOCK_ALLOW_PREFIXES=/dev/mapper/tenant-a:/dev/disk/by-id/...` — optional extra raw block prefixes. Pod `volumeDevices` paths need no extra allowlist.
- `FLUXVM_CONTAINER_VFIO_ALLOW=0000:65:00.0,0000:65:00.1` — exact PCI functions allowed for VFIO.

## Lifetime and recovery

Attachments are owned by the Pod VM, not by an individual container. They remain attached until the sandbox VM is destroyed. The Set 6 recovery journal now persists Set 8 attachment metadata, so a replacement shim deduplicates existing hotplug state.

## Remaining gates

Before production GPU use, validate the exact hardware/IOMMU topology, guest driver, reset behavior, and device-plugin/DRA integration on the target node. Multi-function GPUs usually require every relevant function/IOMMU-group member to be handled consistently.
