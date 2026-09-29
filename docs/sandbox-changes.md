# Sandbox file change-set

See which files an agent changed inside a sandbox VM: record a **baseline**
of the regular files under some directories, run the agent, then ask for
the **changes** (added / modified / deleted). This is the same question
Sandlock's `--dry-run` answers for a process sandbox, answered for a guest.

Baseline and changes only report; they do not revert anything. To run a
command and throw its effects away, use [dry-run](#dry-run-on-a-vm-sandbox);
to roll back explicitly, snapshot and `POST /v1/vms/{id}/restore`.

## API

Both routes are admin-only and tenant-scoped exactly like every other
`/v1/sandboxes/{id}/...` route that reaches the guest (`fs/read`,
`process`, ...), and resume an auto-paused sandbox like they do. The guest
agent must be enabled: the manifest is built by running a shell command
through the existing guest exec path.

### `POST /v1/sandboxes/{id}/baseline`

```json
{ "paths": ["/workspace", "/home/agent"] }
```

Records the current state of regular files under each directory, replacing
any earlier baseline for the sandbox.

```json
{ "ok": true, "files": 1284, "mode": "sha256", "paths": ["/home/agent", "/workspace"] }
```

### `POST /v1/sandboxes/{id}/changes`

Body is optional. `{ "paths": [...] }` narrows the comparison to a subset of
the baseline's directories (default: all of them).

```json
{
  "added": ["/workspace/out.txt"],
  "modified": ["/workspace/main.py"],
  "deleted": ["/workspace/old.py"],
  "unchanged": 1281,
  "mode": "sha256",
  "paths": ["/home/agent", "/workspace"],
  "baseline_taken_at_unix": 1790585116
}
```

A rename appears as one deletion plus one addition. Lists are sorted.

| Status | Meaning |
|---|---|
| 400 | Unsafe or invalid `paths`, path not a directory in the guest, guest error, corrupt stored baseline |
| 403 | Not an admin token |
| 404 | Unknown sandbox (or another tenant's), or **no baseline recorded yet** |
| 409 | The baseline and the current listing used different fingerprint modes; take a new baseline |

## How it works and limits

- Paths must be absolute, contain no `..` and no control characters; at most
  64 paths of at most 4096 bytes. Single quotes and shell metacharacters in a
  path are quoted, never interpreted.
- Only **regular files** on the same filesystem (`find -xdev -type f`).
  Symlinks, directories (so empty directories), device nodes and mount points
  below a path are not listed.
- Fingerprint is `sha256sum` of the content. If the guest has no `sha256sum`
  the fallback is `size:mtime` (`"mode": "stat"`), which misses a same-size
  rewrite that preserves the mtime.
- A file the agent user cannot read gets an `unreadable` fingerprint; it is
  reported as modified only if it becomes readable or vice versa.
- If any part of the walk fails (unreadable directory, path removed while
  listing) the request fails instead of returning a partial listing that
  would show false deletions.
- At most 200,000 files and 64 MiB of listing per request; narrow `paths`
  beyond that. The guest command has a 300 s limit.
- File names are compared as UTF-8; non-UTF-8 names are lossy in the JSON
  the guest agent returns.
- The baseline is one JSON file (`sandbox-baseline.json`) in the sandbox's
  workspace, next to `sandbox-proxy.json`; it goes away with the sandbox.
  It is not part of a VM snapshot, so restoring a snapshot does not restore
  the baseline that was current then.
- Files are read while the guest runs; a file written during the walk may be
  captured mid-write. Take the baseline and the changes at points where the
  agent is idle.

## Dry-run on a VM sandbox

`POST /v1/sandboxes/{id}/dry-run` `{ "command": "...", "paths": ["/work"] }`
runs the command, reports what it changed under `paths` and puts the guest back
exactly as it was: memory, running processes and the disk. Native flux-vm
(`fluxvm_engine = "kvm"`), QEMU and Firecracker sandboxes with the guest agent
enabled support it (Cloud Hypervisor is never reachable as a sandbox backend at
all -- see [Backend coverage](#backend-coverage) below);
`paths` is required (the guest root is too large to scan). The response is the
exec result plus `changes`, `discarded: true` and `reverted_via: "snapshot"`
(procbox sandboxes report `"workspace-copy"`).

Sequence: snapshot (tag `dryrun-<uuid>`), manifest, run, manifest, restore,
delete the tag. If the restore fails the call is an error that says the changes
may still be in the VM; it never reports `discarded: true` unless the restore
worked. A command that fails or times out still gets the guest restored.

### What restore reverts (findings)

- A hypervisor `SnapshotRestore` on a *running* VM restores memory, vCPU and
  device state in place (same pid and control socket), but the snapshot's
  metadata points the guest at the snapshot's own `snap.rootfs`. Used as is, the
  guest would keep writing into the snapshot, so the snapshot would drift and a
  second restore would not be the same state.
- FluxVM therefore pauses the guest, renames a fresh copy of `snap.rootfs` over
  the VM's own disk (the old inode stays open in the paused guest until the
  restore shuts it down) and restores from a private `snap.restore.json` naming
  the VM's disk. Memory and disk go back together, the snapshot stays immutable
  and can be restored again, and the VM keeps its disk path.
- Restore waits for the guest agent to answer again (a restored or just-paused
  guest refuses vsock for a moment), up to 60 s.

### Backend coverage

`create_sandbox` always forces flux-vm for a client-supplied `spec`; only an
operator-authored *template* may opt into QEMU or Firecracker. Cloud
Hypervisor is never selectable as a sandbox backend at all -- a template
cannot pick it either -- so `POST /v1/sandboxes/{id}/dry-run` can only ever
be called on a flux-vm, QEMU or Firecracker sandbox in practice, no matter
what this section says CloudHypervisor could theoretically do at the plain
`/v1/vms` level.

For QEMU and Firecracker, "restore" is not literally in-place the way
flux-vm's is. `restore_other_backend_by_relaunch` stops the VMM process and
relaunches it via the same `start_from_snapshot` path a stopped VM's restore
already uses (QEMU: internal qcow2 snapshot + `-loadvm`; Firecracker:
`/snapshot/load`). The new process gets a new pid and, for networked VMs, a
fresh tap/netns, but the VM id, workspace and vsock socket path are
unchanged, so the guest agent reconnects once boot completes and dry-run's
before/after semantics hold. This is only used internally by dry-run's own
restore step, on a VM dry-run has already put into a "may be mid-command"
state; it is not exposed as generic behavior on the explicit restore route
below.

### `POST /v1/vms/{id}/restore` `{ "tag": "..." }`

Admin-only, tenant-scoped. A running or paused flux-vm VM is restored in place
as above; a stopped VM (any backend) takes the existing start-from-snapshot
path. A *running* QEMU, Cloud Hypervisor or Firecracker VM is refused with
409 telling the caller to stop it first -- this route never silently stops
and relaunches a VM the caller didn't ask to stop, unlike dry-run's internal
relaunch above. 404 for an unknown VM or tag, 400 for a bad tag, 409 if
another restore or dry-run is already running on the VM, 501 if the backend
cannot snapshot at all.

### Limits

- Cost is a snapshot plus a restore: a full copy of the root disk each on
  filesystems without reflink (on the shared lab host a 2.2 GB image made a
  restore take 15-50 s and a dry-run about 25 s beyond the command itself), and
  the guest is paused while the snapshot is written. Not a per-call primitive for chatty agents.
- The guest clock jumps back to the snapshot instant; network connections that
  existed at snapshot time are gone from the host side. Nothing outside the VM
  is reverted: files on shared folders, volumes or remote services the command
  touched stay changed.
- Flux-vm, QEMU and Firecracker sandboxes support dry-run (Cloud Hypervisor
  sandboxes don't exist -- see [Backend coverage](#backend-coverage)). For
  QEMU/Firecracker the relaunch-based restore costs a full VMM restart (new
  pid, network re-prepared) each round, on top of the snapshot/restore cost
  above -- slower than flux-vm's true in-place restore.
- One restore or dry-run at a time per VM (409 otherwise).

## Example

```bash
curl -s -XPOST $FLUXVM/v1/sandboxes/$ID/baseline -d '{"paths":["/workspace"]}'
# ... let the agent work ...
curl -s -XPOST $FLUXVM/v1/sandboxes/$ID/changes | jq '{added, modified, deleted}'
```

## Verified live (2026-09-28)

On the lab host through the deployed service, with the Python SDK: a real VM
sandbox created from the golden `native-agent` guest (`spec`), then
`baseline(["/root/work"])`, a command that edited, deleted and created files
(including a name with a space), and `changes()` returned exactly one
added, one modified and one deleted path in `sha256` mode. The same flow ran against a procbox sandbox
(`docs/procbox-backend.md`); paths there are rooted at the workspace, so use
`/work`, not `work`.

Dry-run on a VM sandbox was verified live on the same host (2026-09-28) with
`scripts/test-vm-dry-run.sh`: its own throwaway daemon and state dirs, a golden
`native-agent` sandbox with a background counter (memory) writing to disk. Five
consecutive dry-runs each created a file, deleted a marker and let the counter
advance about 10 s; every time the response listed exactly those changes with
`discarded: true, reverted_via: "snapshot"`, the new file was gone, the marker
was back, the counter was rewound to the snapshot instant and kept counting, the
agent answered and the VM was `running`. The explicit `restore` route and its 404
for an unknown tag were checked in the same run, no `dryrun-*` snapshot was left
behind and the golden image's checksum was unchanged.

## Verified live (2026-09-29): QEMU and Firecracker sandboxes

Extended the same live pattern to QEMU and Firecracker with
`scripts/test-vm-dry-run-multi.sh`: an operator-template sandbox (client
specs can't pick these backends), `network.mode=none`, three consecutive
dry-runs each creating a file and deleting a marker, plus the explicit
`POST /v1/vms/{id}/restore` route exercised via an explicit stop first. For
both backends: every dry-run round reported the correct `changes` with
`discarded: true, reverted_via: "snapshot"`, the guest reverted, the agent
kept answering and the VM stayed `running`; a restore attempted on a
*running* VM through the explicit route correctly got 409; and the
stop -> snapshot -> mutate -> stop -> restore -> start sequence on the
explicit route correctly reverted the guest.

This surfaced and fixed three real bugs, none flux-vm-specific:

- `restore_other_backend_by_relaunch` checked for a
  `workspace/snapshots/<tag>` directory before restoring, which flux-vm
  snapshots have but QEMU (internal qcow2 snapshot) and Cloud Hypervisor
  (their own state/memory files) do not -- this made every non-flux-vm
  dry-run fail immediately with a false "snapshot not found". Removed; the
  existence check now happens where it belongs, inside each backend's own
  loader.
- Firecracker's `/snapshot/load` request body used the `uds_path` field
  name and shape from an older Firecracker API version. Firecracker 1.17
  (the version on this lab host) rejects it with a 400 and expects
  `vsock_override: { uds_path }` instead -- fixed in
  `fluxvm-firecracker/src/snapshot.rs`. This bug pre-dates this change and
  would have broken *any* Firecracker snapshot restore with the guest
  agent enabled, not just dry-run.
- The same restore path didn't remove the previous process's vsock Unix
  socket file before the new Firecracker process tried to bind it, so a
  second restore into the same workspace failed with `EADDRINUSE`. Fixed by
  unlinking it first, same as the existing API-socket cleanup right above
  it in the same function.

Not live-tested: Cloud Hypervisor. `create_sandbox` never selects it (see
[Backend coverage](#backend-coverage)), so there is no sandbox route to test
it through. A plain-VM probe against `/v1/vms` (create with
`backend: "cloud-hypervisor"`, not a sandbox) was attempted separately; see
that result before relying on CloudHypervisor's restore path for anything.
