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

`fluxctl migrate start|status|cancel` is the CLI equivalent of the three
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

## Threat containment (Firecracker figures)

FluxVM maps Firecracker's host-integration and threat-containment figures to
node-local layers:

| Barrier | Owner |
|---|---|
| KVM + minimal virtio device model | VMM backends (FC / in-tree / CH / QEMU) |
| Virtio I/O rate limiters | Firecracker `rate_limiter` from create fields; in-tree token buckets; Fabric Mbps/PPS |
| Jailer + cgroups + seccomp | `[jailer]` + `fluxvm-cgroup` + stock FC / in-tree seccomp |
| Host egress filter | Network Fabric or `network.mode=none` (required outside the VMM) |

Capability numbers (Track A isolation vs optional Track B density):
[capability-figures.md](capability-figures.md).

## Target receiver

`POST /v1/migration/receivers` arms a QEMU `-incoming defer` process on the
target node. Two forms exist:

- **Bare** (`{vcpus, memory_mib, disk, ...}`): a disk-only q35 QEMU. The source
  must have the same minimal device model; it cannot be adopted.
- **Adopt-mode** (`{record, listen_host, advertise_host, ...}` where `record` is
  the source's `GET /v1/vms/{id}`): the receiver is launched from the record's
  own device model (network, seed, agent vsock, firmware) with its own
  workspace, tap/netns and vsock CID, so the source and receiver can run side
  by side, even on one node. It is stored as a `Creating` VM labelled
  `fluxvm.dev/migrating-from=<source id>`, with the receiver's id and the
  source's name. Contract v1 accepts QEMU VMs on `storage: shared` or
  `ceph-rbd-in-place` without TPM, VFIO, virtiofs, data disks, hot-added NICs
  or a direct/macvtap datapath.

Disks are never copied. Full order:

1. target: `POST /v1/migration/receivers` with `record`, then
   `POST /v1/migration/receivers/{id}/activate {token}`;
2. source: `POST /v1/vms/{id}/network/migration/quiesce` and `export` (when a
   dataplane is attached), then `POST /v1/vms/{id}/migration/start
   {destination: <receiver uri>}`; poll `GET /v1/vms/{id}/migration/status`
   until `completed`;
3. source: `POST /v1/vms/{id}/migration/finish` stops the paused source QEMU
   and removes its record and workspace (409 until the phase is `completed`;
   the disk stays);
4. target: `POST /v1/migration/receivers/{id}/adopt {token}` turns the receiver
   into a `running` VM labelled `fluxvm.dev/migrated-from=<source id>` (409
   until the incoming side has finished), then `network/migration/restore` and
   `resume` on the adopted id.

The adopted VM keeps the source's name but has the receiver's id: on one node
both processes exist at once, so they cannot share an id, tap or netns. A
caller that tracks VMs by id swaps it at adopt. `DELETE
/v1/migration/receivers/{id}` before adopt kills the receiver and removes its
VM record.

## Shared-disk storage

`storage: shared` uses `request.image` (a raw file or block device on storage
every node can open) in place. Delete never removes it. `<disk>.fluxvm-lock`
names the VM and node that have it open; a launch is refused while another VM
holds it, unless that holder is on this node and gone (missing record or dead
process). A holder on another node is never assumed dead: after fencing it,
re-create with `POST /v1/vms?shared_takeover=true`, which breaks the lock first
(HA re-create).

## Read-only serial

`GET /v1/vms/{id}/serial` is an interactive socket on QEMU. Every other backend
writes its console to `console.log`, so the same route streams that file
read-only: the last 64 KiB, then new bytes as binary frames; inbound frames are
ignored. A jailed Firecracker VM has no UART and gets 400.
