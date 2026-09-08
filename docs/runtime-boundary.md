# FluxVM runtime boundary

<!-- ZYVOR_RUNTIME_BOUNDARY_V1 -->

FluxVM is the **node-local execution runtime**. Zyvor Fabric is the distributed
private-cloud control plane. GuestKit owns offline guest-disk internals.

The rule for new features is:

- If the feature manipulates a VMM, KVM memory/device state, a VM-local cgroup,
  TAP/netns, or the VM-edge eBPF hook, it belongs in FluxVM.
- If the feature decides *which host*, *which tenant/policy*, *when to evacuate*,
  *how to replicate*, or *how to present the operation to users*, it belongs in
  Zyvor Fabric.

## Runtime contract v1

`GET /v1/runtime/capabilities` advertises stable node-local primitives.

QEMU live migration primitives:

- `POST /v1/vms/{id}/migration/start`
- `GET /v1/vms/{id}/migration/status`
- `POST /v1/vms/{id}/migration/cancel`

Contract v1 is intentionally narrow:

- QEMU only.
- Pre-copy, post-copy and multifd are supported by the source runtime.
- `tcp:` and `unix:` QEMU migration URIs are accepted. `exec:` is rejected.
- VM disks are **not copied** by this contract. Fabric must confirm shared
  storage or prepare storage independently before starting migration.
- FluxVM does not select the destination node, reserve capacity, perform
  fencing, update tenant inventory, or run DRS. Those are Fabric concerns.

The legacy `fluxvm-agent` multi-host registry remains a lightweight standalone
mode for users who do not run Fabric. It must not grow Fabric-class HA, DRS,
site recovery, tenant scheduling, or datacenter semantics.

## Target receiver

This version exposes the source-side VMM transport and capability contract.
Fabric's prepared-target orchestration API consumes it. Creating/arming the
remote incoming QEMU process as a first-class FluxVM receiver is the next
contract revision and must land before Fabric labels native live migration GA.
