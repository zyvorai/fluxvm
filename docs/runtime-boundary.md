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

Live migration primitives:

- `POST /v1/vms/{id}/migration/start`
- `GET /v1/vms/{id}/migration/status`
- `POST /v1/vms/{id}/migration/cancel`

`fluxvm migrate start|status|cancel` is the CLI equivalent of the three
routes above -- for the standalone mode mentioned below, where there is no
Fabric orchestrator to drive them over HTTP.

Contract v1 is intentionally narrow:

- QEMU and Cloud Hypervisor. Firecracker and the in-tree FluxVM hypervisor
  have neither.
- Pre-copy, post-copy and multifd are supported by both source runtimes.
- `tcp:` and `unix:` migration URIs are accepted for both. `exec:` is
  rejected (QEMU has this scheme at all; Cloud Hypervisor doesn't, but the
  same shared allowlist covers both so the rule can't drift between them).
- VM disks are **not copied** by this contract. Fabric must confirm shared
  storage or prepare storage independently before starting migration.
- FluxVM does not select the destination node, reserve capacity, perform
  fencing, update tenant inventory, or run DRS. Those are Fabric concerns.
- **`status`/`cancel` remain QEMU-only.** QEMU's QMP `migrate` is
  asynchronous with a `query-migrate` progress query and a `migrate_cancel`
  primitive; Cloud Hypervisor's `send-migration` is fire-and-forget --
  verified live, it returns success as soon as the request is *accepted*,
  before the transfer (or its failure) is known, and Cloud Hypervisor
  exposes no API to poll or cancel what happens next. `GET
  /v1/runtime/capabilities`'s migration entry carries this as
  `statusPollable` (`true` for QEMU, `false` for Cloud Hypervisor) so
  Fabric can tell up front rather than discovering it from a `start` call
  that never resolves into a pollable status. For Cloud Hypervisor, Fabric
  must instead infer the outcome the same way it already watches for any
  other node-local state change: the VM disappearing from this node's `GET
  /v1/vms` once its process exits (migration succeeded) versus it staying
  `Running` there (nothing has succeeded yet).

The legacy `fluxvm-agent` multi-host registry remains a lightweight standalone
mode for users who do not run Fabric. It must not grow Fabric-class HA, DRS,
site recovery, tenant scheduling, or datacenter semantics.

## Target receiver

This version exposes the source-side VMM transport and capability contract.
Fabric's prepared-target orchestration API consumes it. Creating/arming the
remote incoming QEMU process as a first-class FluxVM receiver is the next
contract revision and must land before Fabric labels native live migration GA.
