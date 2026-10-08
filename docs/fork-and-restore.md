# Fork and snapshot restore (in-tree KVM engine)

How `POST /v1/vms/{id}/fork` works, how a snapshot's RAM is brought back, and
how each child gets its own identity. Written from `crates/fluxvm-scheduler/src/fork.rs`,
`crates/fluxvm-hypervisor/src/{memory,kvm_snap}.rs`,
`crates/fluxvm-guest-agent/src/main.rs` and the bench scripts.

## Status: read this first

| Piece | State |
|---|---|
| Fork flow, `MAP_PRIVATE` restore with eager fallback, `ResetIdentity`, `?ready=exec`, bench scripts | Implemented and type-checked. Unit tests cover `check_forkable`, hostname validation and request/response shapes. |
| Any of it running against real KVM guests | **Not verified on hardware.** No fork, restore or identity reset from this batch has been run end to end. `bench-fork.sh` and `bench-first-command.sh` have produced no numbers yet, so this page makes no latency or memory claims. |

## Fork flow

`VmManager::fork_vm(id, count, name_prefix)` turns one running VM into `count`
new running VMs named `{prefix}-{n}` (prefix defaults to `{parent}-fork`).

Preconditions (`check_forkable`):

- backend `flux-vm` with the in-tree **KVM** engine (a Firecracker vmstate names
  the parent's disk and tap by absolute host path, so a child would share them);
- parent is Running or Paused; `1 <= count <= 32` (`MAX_FORK_COUNT`);
- local file-backed disk (`storage: default`);
- network `none`, `user`, or `tap` with `netns: true`, no `direct`, no extra
  NICs. Children keep the parent's MAC and IP, so they must never share an L2
  segment.

Steps:

1. Journal a `fork` intent (see [crash-recovery.md](crash-recovery.md)) naming
   the parent's fork snapshot directory `snapshots/fork-<12 hex>`.
2. One `SnapshotSave` of the parent: a pause of a few milliseconds plus a
   reflink of its rootfs. The parent keeps running afterwards.
3. For each child, in sequence: check tenant and host quota, record a
   `fork_child` resource, create the workspace, insert the record (with its own
   vsock CID if the parent had one), reflink `snap.rootfs` to the child's
   `root.raw` (`clone_cow`), prepare a fresh tap in its own netns (MAC cleared so
   it is regenerated), write a per-child snapshot spec pointing at the shared
   `snap.mem` and `snap.vmstate`, and `start_from_snapshot`.
4. After resume, `reset_child_identity` (below).
5. Delete the parent's fork snapshot and clear the intent.

All or nothing: if any child fails, every child created by this call is deleted
and the call returns an error. Children carry the label
`fluxvm.dev/forked-from = <parent id>`. `snap.mem` and `snap.vmstate` are shared
read-only; either restore path below means the files can be unlinked once every
child runs.

## RAM restore: MAP_PRIVATE with an eager fallback

`kvm_snap::load_memory_into` first checks the file size equals guest RAM. It
then calls `GuestMemory::remap_private_file`, which replaces the existing
anonymous RAM mapping **in place** with a `MAP_PRIVATE | MAP_FIXED |
MAP_NORESERVE` mapping of `snap.mem`. The host address does not change, so the
KVM memslot and every copy of `host_ptr()` stay valid. Pages fault in from the
page cache on first touch; children restored from one snapshot share every page
none of them wrote and copy only the pages they dirty. It must run before any
vCPU or device thread touches RAM.

It returns an error, leaving the anonymous mapping untouched, and the loader
falls back to a plain `read_exact` copy of the whole file (logging
`[kvm-engine] file-backed restore unavailable, copying RAM: <reason>`), when:

- `FLUXVM_KVM_EAGER_RESTORE=1` (forces the eager copy; use it for "before"
  numbers),
- `FLUXVM_KVM_LOCK_MEM=1` (mlock/populated RAM) or `FLUXVM_HUGEPAGES=1`, since a
  file mapping can honour neither,
- the file size differs from guest RAM,
- the `mmap` fails for any other reason, or on non-Linux hosts.

Two cautions:

- **SIGBUS.** The snapshot file must not be truncated or rewritten in place while
  a child runs on it. Touching a page past the new end of file kills the guest
  with SIGBUS. Unlinking the file is fine (the mapping keeps the inode alive).
  Nothing in the daemon guards against an operator truncating `snap.mem`.
- The vmstate: a `FLUXKVM1` version below 5 has no full-fidelity state; the
  restore then sets registers only and LAPIC, MSRs, FPU, clock, irqchip and PIT
  start fresh (logged as `[kvm] vmstate vN has no full-fidelity state`).

## Child identity reset

A fork resumes the parent's memory, so every child starts with the parent's
hostname, `/etc/machine-id` and kernel RNG state. `fork_child` sends the guest
agent `AgentRequest::ResetIdentity` and retries for up to 15 s (every 250 ms,
5 s per call) while the resumed agent starts answering.

The host sends: the child's name as hostname, `regenerate_machine_id: true`,
`reseed_entropy: true`, and 32 bytes of host entropy (two v4 UUIDs, base64). The
agent (`reset_identity`, Linux) does, each step independent and best effort:

1. Entropy first: `RNDADDENTROPY` on `/dev/urandom` with the supplied bytes
   (at most 512 are used), crediting them to the pool. With no entropy supplied it
   reports a failure rather than guessing.
2. Hostname: `sethostname` and `/etc/hostname`, after validating the name
   (no dots, no leading `-`, at most 63 characters).
3. Machine id: a fresh random id into `/etc/machine-id`, and
   `/var/lib/dbus/machine-id` if it is a regular file (a symlink is left alone).
4. `ip neigh flush all`, dropping the parent's neighbour cache.

The response is `IdentityReset { applied, failures }`. A clean reset is audited
as `vm.fork.identity-reset`. Any failure, or a child with no agent, is **not
fatal**: the child keeps running, a loud error is logged and
`vm.fork.identity-reset-failed` is audited. A child that failed the reset shares
the parent's identity or RNG state, which is a correctness problem.

Not done:

- **Open connections are not touched.** Established TCP connections, listening
  sockets and in-flight requests in the parent are present in the child (the
  child's netns and tap differ, but the guest believes the old state). Quiesce the
  parent before forking.
- The IP and MAC stay the parent's (hence the netns requirement). The child is
  not re-addressed.
- No clock step, no per-process re-seeding (an application that already read
  random bytes keeps them, e.g. a TLS session cache or a language runtime's PRNG
  state), no SSH host key regeneration, no cloud-init re-run.
- Not run at all for VMs created without the agent.
- A plain snapshot restore of the same VM (`vm_restore.rs`) does not call
  `ResetIdentity`; it only waits for the agent to answer again.

## First-command latency: ?ready=exec

`?ready=exec` (or `?wait_first_command=true`) on `POST /v1/vms`,
`POST /v1/vms/{id}/fork` and `POST /v1/pools/{name}/claim` makes the API wait,
after the create/fork/claim itself returns, for a trivial `true` exec through the
guest agent to succeed, and adds timing to the response:

- `first_command_ms`: milliseconds from request receipt (measured by the server,
  not the client) to the first successful exec. For fork it is the **worst** child;
  per-child results are in `first_command`.
- `phases`: `create_done_ms` (when the create/fork/claim returned),
  `agent_wait_ms` (the extra wait for the agent) and `first_exec_ms`.

A `vm.first_command` event is also recorded. The request fails if the agent never
answers within 60 s. This changes the response (the call blocks longer),
so use it for measurement and for callers that really need a usable shell, not as
a default.

## Benchmarks (none run yet)

`scripts/bench-fork.sh`: `VM=<uuid> COUNT=8 RUNS=5 ./scripts/bench-fork.sh`,
against a running `fluxctl serve` and a running flux-vm VM. Linux/KVM only
(exits 0 elsewhere). Prints per child:

- `ready_ms_per_child_p50` / `_p95`: fork API time divided by child count. It
  covers the parent snapshot, reflinked disks, memory restores and the identity
  reset, not guest init;
- `pss_kb_per_child_p50`, `private_kb_per_child_p50`, `rss_kb_per_child_p50`
  from `/proc/<pid>/smaps_rollup` (needs root);
- `disk_bytes_copied_per_child_p50`: a filesystem-wide `used` delta, near zero for
  a reflink and noisy on a busy host.

Record a baseline with the daemon started under `FLUXVM_KVM_EAGER_RESTORE=1`,
then again without, and compare.

`scripts/bench-first-command.sh`: `N=10 IMAGE=... POOL=<pool> FORK_SRC=<uuid>
./scripts/bench-first-command.sh`. Cold create, warm-pool claim (needs `POOL` with
at least N ready members) and fork (needs `FORK_SRC`; never deleted) via
`?ready=exec`; prints p50/p95 of `first_command_ms` as JSON per section. It only
deletes VMs it created.

`scripts/bench-density-count.sh` (memory, not fork) boots VMs until create is
refused or a memory floor is hit. It consumes host memory and refuses to run
without `FLUXVM_BENCH_CONFIRM=1`.

Results table: not yet measured.

| Measure | Eager copy | MAP_PRIVATE |
|---|---:|---:|
| Fork ready ms per child, p50 / p95 | not yet measured | not yet measured |
| PSS per child | not yet measured | not yet measured |
| First command ms (fork), p50 / p95 | not yet measured | not yet measured |

## Not implemented

userfaultfd demand paging, dirty-log incremental snapshots and fork-backed warm
pools are designs only; see [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md).
