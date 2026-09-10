# Secure Containers — Set 9: device lifecycle and GPU reconciliation

Set 9 turns Set 8 passthrough from a Pod-lifetime attachment prototype into a recovery-aware device lifecycle. It keeps the same VM security boundary: host device numbers are never recreated inside the guest, raw block devices remain Pod-scoped, and VFIO functions remain explicit operator policy.

## Reference-counted claims

Every new Set 9 block or VFIO attachment records the container IDs that currently claim it. Multiple containers may share the same attachment without duplicate QMP `device_add`. When an init container is deleted, its claims are removed. The device is eligible for unplug only when the last owner disappears.

Set 8 journals have no owner list. They deserialize with `owners = null` and stay **legacy-pinned** until the whole sandbox is destroyed. This deliberately favors availability and isolation over guessing ownership during an upgrade.

## Correct QEMU hot-unplug ordering

For a zero-owner device the shim sends `device_del` and waits for the matching QEMU `DEVICE_DELETED` event. A raw-block backend is removed with `blockdev-del` only after the frontend device is confirmed gone. `DEVICE_UNPLUG_GUEST_ERROR` and timeouts leave the attachment journaled as **pending-unplug** so a later attach/recovery can retry it.

Container deletion is not failed after the guest process is already gone merely because hardware unplug is delayed. The journal remains the source of truth until cleanup succeeds or the entire Pod VM is destroyed.

## Raw-block identity hardening

Kubernetes raw block `volumeDevices` paths are kubelet-owned symlinks. Set 9 authorizes the original Pod-scoped path (or an explicitly trusted `FLUXVM_CONTAINER_BLOCK_ALLOW_PREFIXES` origin), then canonicalizes it and records the actual host block major/minor. Recovery fails closed if that block identity changes.

Extra block prefixes are operator-trusted. Prefer stable `/dev/disk/by-id` or tightly scoped mapper directories; do not allow broad paths such as `/dev`.

## Strict VFIO/IOMMU groups

`FLUXVM_CONTAINER_VFIO_REQUIRE_IOMMU_GROUP=1` is the default. The requested BDF and **every function in its IOMMU group** must be listed in `FLUXVM_CONTAINER_VFIO_ALLOW` and already bound to `vfio-pci`. FluxVM still never unbinds or rebinds host drivers automatically.

A recovered shim verifies the BDF, IOMMU-group identity, driver binding, and the QEMU device object before restoring task metadata. A mismatch fails closed instead of silently reattaching different hardware.

For isolated development machines only, `FLUXVM_CONTAINER_VFIO_REQUIRE_IOMMU_GROUP=0` relaxes the group-presence requirement. It does not relax the exact requested-BDF allowlist or `vfio-pci` binding check.

## GPU device-plugin companion nodes

A PCI passthrough workload may also list global character nodes that are created by the **guest** GPU driver rather than mapping one-to-one to a host PCI function. Set 9 recognizes common NVIDIA control/UVM/caps nodes and AMD `/dev/kfd`, and permits extra exact guest paths through `FLUXVM_CONTAINER_GUEST_DEVICE_ALLOW`.

These entries are guest-only companion nodes: the shim marks them for guest resolution and the container agent bind-mounts the guest driver's node. No host major/minor value is propagated across the VM boundary.

## Configuration

- `FLUXVM_CONTAINER_VFIO_REQUIRE_IOMMU_GROUP=1` — require and validate the complete group (default).
- `FLUXVM_CONTAINER_GUEST_DEVICE_ALLOW=/dev/vendorctl,/dev/vendor-uvm` — extra exact guest-driver companion nodes.
- `FLUXVM_CONTAINER_DEVICE_UNPLUG_TIMEOUT_SECS=10` — wait for QEMU unplug completion, clamped to 1–120 seconds.
- Set 8 controls remain: `FLUXVM_CONTAINER_DEVICE_PASSTHROUGH`, `FLUXVM_CONTAINER_BLOCK_ALLOW_PREFIXES`, and `FLUXVM_CONTAINER_VFIO_ALLOW`.

## Telemetry and validation

`device_stats` in each `runtime-state.json` records successful attaches, successful detaches, unplug failures, and recovery checks. Run `scripts/inspect-secure-container-devices.sh` on a node to see attachment ownership and pending cleanup.

For raw-block lifecycle validation, set `PVC_NAME` to a disposable Bound `volumeMode: Block` PVC and run `scripts/e2e-secure-containers-device-lifecycle.sh`. For VFIO, first run the Set 8 preflight and validate reset/unplug behavior on the exact hardware.

## Merge note

The Set 9 patch in this handoff is generated against the Set 8 cumulative bundle. Upstream FluxVM `main` already contains newer namespace/Sentinel Secure Containers work; replay/rebase the Set 8/Set 9 device changes on that newer tree rather than replacing those files wholesale.
