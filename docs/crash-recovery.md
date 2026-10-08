# Crash-safe VM lifecycle

What happens to a VM operation when the daemon dies in the middle of it, and
how the next start cleans up. Everything here was written against the code in
`crates/fluxvm-storage`, `crates/fluxvm-scheduler` (`journal.rs`, `recovery.rs`,
`idempotency.rs`) and `crates/fluxvm-api` (`idempotency.rs`).

## Status: read this first

| Piece | State |
|---|---|
| Durable writes, journal, `OpGuard`, rollback, orphan sweep, idempotency store and middleware | Implemented and type-checked. Unit tests pass (journal, name-ownership checks, start-time parsing, key hashing). |
| End to end behaviour with a real daemon SIGKILLed mid-operation | **Not verified on hardware.** `scripts/test-crash-recovery.sh` exists to do it; it has not been run to completion against real VMs yet. |

Treat the guarantees below as the design and the code's intent, not as
measured behaviour.

## Durable writes

`fluxvm_storage::write_durable(tmp, dest, bytes)` writes `bytes` to `tmp`,
`fsync`s the file, renames it over `dest`, then `fsync`s the parent directory.
After it returns the new contents survive power loss or a kernel crash, and a
reader never sees a half-written file. It is used for:

- `vms.json` (every store mutation),
- the quota ledger `quotas.json`,
- every operation intent in the journal,
- every stored idempotent response.

The delete intent (`begin_delete`) does the same sequence inline. A torn
`*.json.tmp` file left by a crash is never read: listings only match the final
`*.json` names.

## The operation journal

Directory: `<state_dir>/journal/`.

`delete()` removes the VM record before it reclaims what the record points at
(workspace, jail tree, LVM snapshot). A crash in between would leave resources
nothing names. So:

- **Delete intent**, `delete-<vm_id>.json`: workspace, optional jail path,
  optional LVM LV. Written (durably) after the "still alive" check and before
  the record is removed. `finish_delete` clears it once cleanup is done.
  `reconcile()` rolls any leftover intent forward (`replay_pending_deletes`).
  The intent lists only workspace, jail path and LVM LV: it does not name a
  qemu-nbd process or a Ceph clone (see known gaps).
- **Operation intents**, `<op>-<op_id>.json` for `create`, `snapshot`, `fork`
  and `restore`. Each is written before the operation allocates anything, lists
  every resource it may have allocated, and is cleared when the operation ends.

An `OpIntent` records: `op`, `op_id` (for create, the new VM's id), `vm_id` (the
VM acted on; the parent for fork and snapshot), `started_at`, `owner_pid`,
`owner_start`, `attempts` and `resources`.

Resource kinds: `workspace`, `netns` (`eph-<short id>`), `tap` (`eph<short id>`),
`lvm_lv` (`/dev/<vg>/eph-<short id>`), `ceph_clone` (`<pool>/eph-<short id>`),
`nbd_pid` (pid plus `/proc` start time), `snapshot_dir`, `fork_child` and
`temp_file` (`*.restore.tmp`). `<short id>` is the first 8 hex digits of the VM
id. Names are recorded before the allocation they describe, so a crash at any
point leaves a complete list of what could exist.

What each operation journals:

| Operation | Journaled up front | Added while running |
|---|---|---|
| create | workspace, netns or auto-named tap (not both; a user-named tap is skipped), LVM LV or Ceph clone when that storage is used (`planned_create_resources`) | `nbd_pid` once qemu-nbd is spawned |
| snapshot | `snapshot_dir` for `<workspace>/snapshots/<tag>`, only when the tag does not exist yet and the backend is not QEMU (QEMU keeps snapshots inside the disk image) | nothing |
| fork | the parent's fork snapshot dir | one `fork_child` per child, recorded before its workspace is made |
| restore | `temp_file` `<disk>.restore.tmp` | nothing |

### OpGuard

`OpGuard` is the RAII handle for one journaled operation.

- `OpGuard::begin` durably writes the intent, stamped with this process's pid
  and its `/proc/<pid>/stat` start time.
- `record(resource)` appends a resource (durably) before it is allocated;
  recording the same resource twice is a no-op.
- `finish()` clears the intent: the operation completed, or cleaned up after
  itself.
- Dropping the guard any other way (early `?`, a cancelled request future, a
  panic) rewrites the intent with `owner_pid = 0`: *abandoned*, roll back at the
  next reconcile.
- A hard crash runs neither; the intent then names a dead owner and is treated
  the same way.

Restore only calls `finish()` when the restore succeeded; a failed restore
leaves the intent abandoned so its temp file is swept.

### Owner liveness

`owner_alive(pid, start)` is false for pid 0. Otherwise it reads field 22 of
`/proc/<pid>/stat` (parsed after the last `)`, because command names can contain
spaces and parentheses) and compares it with the recorded start time, so a
reused pid does not look like the old owner. Where `/proc` has no such process
it falls back to `kill(pid, 0)` (treating `EPERM` as alive). Intents of a live
owner are skipped, so replaying on every reconcile tick is safe.

## Recovery on start (`recovery.rs`)

`reconcile()` runs `replay_pending_deletes`, then `replay_pending_ops`, then its
usual per-VM repair, and ends with `sweep_orphans`. The interval is
`reaper_interval_secs` (default 5).

### replay_pending_ops

For each intent whose owner is gone:

- **create**: if a record exists and its status is no longer `Creating`, the
  create finished (or cleaned up itself) and only the intent is stale. Otherwise
  it kills VMM-like processes whose command line names the workspace or VM id,
  then for each journaled resource: kills the qemu-nbd pid (only if its start
  time still matches), cleans up the netns or tap, removes the LVM LV, deletes the
  Ceph clone, removes the sandbox policy, deletes the `Creating` placeholder
  through `delete()`, and finally removes the workspace.
- **snapshot** and **restore**: remove the `snapshot_dir` or `*.restore.tmp`
  file. Nothing else.
- **fork**: all or nothing. Every child it started is removed (through
  `delete()` if it has a record; otherwise by killing its VMM, cleaning its
  netns and policy and removing its workspace), then the parent's fork snapshot.

If every step succeeded the intent is cleared. Otherwise `attempts` is
incremented and written back; after `MAX_ROLLBACK_ATTEMPTS` (5) the intent is
cleared with an error log, so a resource that can never be removed does not pin
the intent forever (it may then leak).

### resource_is_ours

A journal file is not trusted blindly. Before touching the host, every resource
is re-validated against the VM id the intent is about, and ignored (with a
warning) if it fails:

- workspace: exactly `<state_dir>/instances/<that uuid>`;
- netns: exactly `eph-<short id>`; tap: exactly `eph<short id>`;
- LVM LV: file name `eph-<short id>` directly under `/dev/<vg>/`;
- Ceph clone: `<pool>/eph-<short id>` with a plain pool name (no leading `-`);
- snapshot dir: `<that VM's workspace>/snapshots/<tag>`, tag not empty, `.` or `..`;
- temp file: ends in `.restore.tmp`, directly in that VM's workspace;
- `nbd_pid` is checked against the live process's start time at rollback.

Only processes whose `/proc/<pid>/comm` starts with `qemu`, `cloud-hyper`,
`firecracker`, `jailer`, `virtiofsd`, `swtpm` or `fluxvm` are ever killed on a
rolled-back VM's behalf.

### sweep_orphans

Removes things nothing accounts for. A name is "claimed" if a VM record, a
pending operation intent (its `vm_id`, `op_id` or fork children) or a pending
delete intent mentions it. Unclaimed:

| Resource | Shape considered | Grace before removal |
|---|---|---|
| Workspace | `<state_dir>/instances/<uuid>` directory with no record or intent and no VMM process referencing it | `ORPHAN_DIR_GRACE` = 1 hour since its newest modification |
| Network namespace | `eph-<8 hex>` in `/run/netns` (or `/var/run/netns`) | `ORPHAN_NET_GRACE` = 120 s of being seen unclaimed across successive sweeps |
| Tap | `eph<8 hex>` in `/sys/class/net` that has `tun_flags` (a bridge or veth with a matching name is left alone) | same 120 s |

The long directory grace exists because some paths (sandbox staging, migration
receivers) create the directory a little before their record. The same sweep
also purges expired idempotency records (see below).

Names must match the daemon's own scheme exactly. Anything else is left alone.
**The netns and tap sweeps work on host-wide names.** On a host shared with
another FluxVM instance that uses a different state dir, that instance's
namespaces look unclaimed to this one. Do not run two daemons with different
state dirs on one host.

## Idempotency keys

Header `Idempotency-Key` on the four mutating VM routes:

- `POST /v1/vms`
- `DELETE /v1/vms/{id}`
- `POST /v1/vms/{id}/snapshot`
- `POST /v1/vms/{id}/fork`

Other routes ignore the header. Without the header behaviour is unchanged.

The key is 1 to 255 visible ASCII characters (0x21..0x7e); anything else is
**400**. A record is scoped by (tenant, or the authenticated caller, or
`anonymous`; method and path; key), hashed with SHA-256, so two callers using
the same key never see each other's responses. The middleware sits innermost in
the router, so the auth and tenant guards still run before a stored response is
replayed.

| Situation | Result |
|---|---|
| First request | Runs. A 2xx response is stored (fsynced) before the caller gets it. |
| Same scope, route, key and identical body, within 24 h | Stored response replayed with `Idempotent-Replayed: true`. The operation does not run again. |
| Same key, same route, **different body** | **422** |
| Same key while the first request is still running (this process) | **409** |
| Bad key | **400** |
| First attempt returned non-2xx | Nothing stored; the same key can be retried. |

Details worth knowing:

- Records live in `<state_dir>/idempotency/<hash>.json`, TTL 24 h
  (`TTL_SECS`); an expired record counts as a miss and is removed. They survive
  a daemon restart.
- The fingerprint is a hash of method, path and the exact body bytes. A
  re-serialised but semantically equal body is a different request.
- Because the route is part of the key hash, reusing a key on a *different
  route* is a fresh key, not a 422. Only a changed body on the same route is a
  conflict. (The module comment in `fluxvm-api/src/idempotency.rs` says "method,
  path or body"; the code only reaches the conflict path for the body.)
- The 409 guard is an in-memory set, so it covers one daemon process. Across a
  restart a request that was running when the daemon died has stored nothing and
  simply re-runs.
- If persisting the response fails, a warning is logged and a retry will re-run
  the request.
- Request bodies over 16 MiB are refused with 413; responses over 8 MiB are not
  recorded (the request returns 500).
- A retried delete replays its original 2xx instead of returning 404.

## scripts/test-crash-recovery.sh

Fault-injection test. It SIGKILLs the daemon while a create, delete, snapshot or
fork is in flight, restarts it, and checks that the next start converges: no
leaked taps, network namespaces, VMM processes, workspaces or journal intents.
It also checks the idempotency behaviour above.

```sh
sudo ./scripts/test-crash-recovery.sh [--image PATH] [--fork-spec FILE] [--port N] [--keep]
# FLUXVM_BIN=/path/to/fluxctl overrides the binary lookup
```

- Needs Linux with `/dev/kvm`, root, curl and python3, and exits otherwise.
- `--image` must be a **bootable** image: the script really boots QEMU VMs from
  it. The default is `/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2`
  (`scripts/test-lifecycle.sh` creates it).
- `--fork-spec FILE` is a create spec for a KVM-engine VM with
  `network.netns = true`; without it the fork case is skipped.
- Kill points: create at four stages (intent written, workspace exists, root
  disk exists, VMM running), delete right after its intent, snapshot right after
  its intent, fork right after its intent. A kill that lands after the operation
  already finished is reported as SKIP, not a failure.
- Idempotency checks: a retried create returns the same VM, the retry carries
  `Idempotent-Replayed: true`, the VM count does not grow, a changed body is
  422, the stored response replays after a daemon crash, and a retried delete
  replays a 2xx.

### Isolation

The daemon runs from a throwaway config in a `mktemp -d` directory, with its own
`state_dir`, `run_dir`, port (default 17788) and `reaper_interval_secs = 2`. It
does not read or write `/var/lib/fluxvm` VM state (it only reads the image).
VMM cleanup is `pkill -9 -f "<temp state>/instances"`, scoped to that path.

### Baseline namespaces and taps

At start-up the script records every `eph-<8hex>` netns and `eph|tap<8hex>`
link already on the host (`BASE_NETNS`, `BASE_TAPS`). Leak counts and cleanup
only consider names that appear afterwards; anything in the baseline belongs to
someone else's VM and is never counted or deleted.

> **WARNING.** An earlier version of this script did not take that baseline and
> deleted **every** `eph-<8hex>` network namespace on the host, including those
> of real running VMs. The current version only deletes what appeared during its
> own run, but this script kills daemons, boots VMs and removes network objects
> as root. Run it only on hosts you control, preferably an idle lab host. The
> baseline is a snapshot taken once: a namespace created by something else *during*
> the run looks like ours and may be removed.

## Known gaps

These are real and are not covered by the tests above.

- **IPAM lease not released by the orphan sweep.** Removing an orphaned netns
  derives the VM id from the 8-hex short id only; the IPAM lease is keyed by the
  full id and stays leased.
- **QEMU internal `savevm` is not rolled back.** A snapshot on a QEMU VM lives
  inside the qcow2; the journal lists no resource for it, so a crash mid-snapshot
  can leave a partial internal snapshot.
- **Not journaled:** extra-NIC taps, user-named taps (deliberately left alone as
  "not ours") and jailer trees. The create intent also cannot predict them.
- **Delete intent omits nbd and Ceph.** A crash after the record is removed but
  before qemu-nbd is stopped or the Ceph clone deleted leaves them behind; the
  delete roll-forward only reclaims workspace, jail path and LVM LV.
- **Idempotency 409 is per process** (above), and 422 needs the same route.
- **Rollback gives up after 5 attempts** and clears the intent with an error log.
