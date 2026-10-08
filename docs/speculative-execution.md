# Speculative execution

Run a command in an isolated copy of a sandbox, look at what it changed, and only then decide whether
those changes reach the real sandbox. The result of a speculation is a **changeset**: the command's
output, a diff, the contents of every added or modified file, and a side-effects report.

## Roadmap and status

| Item | Implemented and type-checked | Verified on hardware |
|---|---|---|
| `speculate`, changeset list/get | yes (unit tests pass) | not yet |
| approve, reject, apply, conflict detection | yes (unit tests pass) | not yet |
| Procbox path (workspace copy) | yes | not yet |
| VM path via fork, snapshot-restore fallback | yes | not yet |
| TTL expiry and retention sweep | yes | not yet |
| Audit events | yes | not yet |
| `fluxctl sandbox speculate/changesets/changeset/approve/reject/apply` | yes | not yet |
| Egress enforcement during speculation | no (declared only, see below) | n/a |

Nothing in this batch has been run end-to-end on real VMs. Treat the behavior below as what the code
does, not as measured results.

## Flow

```text
fork/copy -> execute -> inspect -> approve -> apply
                          |-> reject
```

1. **Fork or copy.** The real sandbox is never touched by the speculative run.
   - A procbox sandbox runs on a throwaway copy of its workspace (`run_via: "workspace-copy"`). The
     copy is refused (413) if the workspace exceeds `[sandbox.procbox] max_workspace_mib`.
   - A flux-vm sandbox that is running and passes the fork checks runs on a one-off fork
     (`run_via: "fork"`). The fork is deleted afterwards.
   - Anything else (QEMU, Firecracker, a flux-vm that cannot be forked) uses the snapshot-and-restore
     path of the dry-run (`run_via: "snapshot"`): the guest is snapshotted, the command runs in it,
     the changes are captured, and the guest is restored.
   - VM sandboxes need the guest agent, and `paths` is mandatory because the guest root is too large
     to scan. Procbox defaults `paths` to `["/"]`.
2. **Execute.** The command runs with the usual exec timeout.
3. **Inspect.** The changeset records the diff (`added`, `modified`, `deleted`, `unchanged`), the
   staged file contents, 64 KiB of stdout and stderr each, and the side-effects report.
4. **Approve or reject.** Both are explicit calls. Nothing is applied automatically.
5. **Apply.** Only an `approved` changeset can be applied. Apply checks that the real files still
   match the base the speculation started from; on a mismatch nothing is written.

## States

```text
pending -> approved -> applied
   |          |-> failed          (apply started and did not finish)
   |-> rejected / expired         (expired is also reachable from approved)
```

| State | Meaning |
|---|---|
| `pending` | Created by `speculate`. Waiting for a decision until `expires_at`. |
| `approved` | Approved. Can be applied until `expires_at`. |
| `applied` | File changes were written to the real sandbox. Final. |
| `rejected` | Rejected (from `pending` or `approved`). Staged files are dropped. Final. |
| `expired` | Undecided past `expires_at`. Staged files are dropped. Final. |
| `failed` | Apply started and did not complete. The sandbox may hold part of the change. `error` says why. Final. |

Only these transitions are allowed: pending to approved, rejected or expired; approved to applied,
rejected, expired or failed. Anything else is a 409.

Lifetime: `ttl_seconds` defaults to 3600 and is clamped to 1..=86400. Expiry is evaluated lazily when
a changeset is read or decided and by a sweep that runs on `speculate`, list and get. A finished
changeset (applied, rejected, expired, failed) is kept for 24 hours and then deleted.

## Storage layout and size caps

Changesets live under `<state_dir>/changesets/<changeset-id>/`, in a directory created with mode
`0700`; files are written `0600`, fsynced, and renamed into place.

```text
changesets/<id>/
  meta.json     the changeset (state, command, output, diff, side effects, staged index)
  base.json     manifest of the files the command started from (path -> fingerprint)
  blobs/000000  staged contents of added or modified files, one blob per file
```

| Cap | Value |
|---|---|
| Largest staged file | 16 MiB |
| Largest total staged per changeset | 64 MiB |
| Captured stdout and stderr | 64 KiB each (`[truncated N bytes]` marker) |
| Maximum TTL | 24 hours |
| Retention of finished changesets | 24 hours |

A file over a cap, or one that cannot be read, is listed in `unstaged`. A changeset with any
`unstaged` file **cannot be applied** (422); reject it and narrow `paths` or reduce the output. Blobs
are deleted when the changeset is applied, rejected or expired.

## Conflict detection

At apply time the daemon takes a fresh manifest of the real sandbox over the changeset's `paths` and
compares it with `base.json`. Any file added, modified or deleted since the speculation started is a
conflict: apply returns **409** with the first ten paths, writes nothing, and records a
`changeset.conflict` audit event. The changeset stays `approved`, so you can resolve the drift and try
again, or reject it.

Other statuses:

| Status | Cause |
|---|---|
| 404 | Unknown changeset, or it belongs to another sandbox |
| 409 | Invalid transition, conflict, expired, or another request is working on this changeset |
| 422 | Not applicable (unstaged files) |
| 413 | Procbox workspace larger than `max_workspace_mib` |
| 400 | `paths` missing for a VM sandbox, guest agent not enabled, and similar |

If a previous apply started but did not finish (for example the daemon died mid-write), the next apply
marks the changeset `failed` instead of retrying blindly.

Apply writes staged files with their recorded mode (creating parent directories in VM sandboxes), then
removes deleted paths.

## Side-effects report

```json
{
  "egress": "allow_listed",
  "destinations": ["api.github.com"],
  "replayable": ["3 file change(s) under /work"],
  "non_replayable": ["possible traffic to allow-listed destination api.github.com: recorded, never replayed"]
}
```

- `replayable`: file changes inside the sandbox. This is all `apply` ever reproduces.
- `non_replayable`: anything that may have happened for real. Never replayed.
- `egress`:
  - `blocked`: VM sandbox with `network = none`, or a procbox sandbox with no `net_ports`.
  - `allow_listed`: a VM with a non-empty global `[sandbox] egress_allow_domains` (the domains are
    listed), or a procbox sandbox with `net_ports` (listed as `tcp/<port> (port allow-list only, any host)`).
  - `unrestricted`: a VM with networking and no allow-list. External effects are unknown.

**Limitation: egress is declared, not enforced.** The report is derived from the sandbox's network
spec and the daemon's allow-list configuration. The speculative run does not get a network of its own:
a fork keeps the parent's addressing and the snapshot path runs in the real guest, so a command can
still reach whatever the sandbox could reach, and those requests really happen. The report tells the
reviewer what was possible; it does not prove that nothing went out. For commands with external
effects (deploys, payments, posting messages), run the sandbox with `network = none` or do not
speculate. Only file changes are rolled back, because only they are replayable.

## Audit events

| Event | When |
|---|---|
| `changeset.create` | A speculation produced a changeset (`vm_id`, `changeset`, `via`, `changes`) |
| `changeset.approved` | Approved |
| `changeset.rejected` | Rejected |
| `changeset.applied` | Apply finished |
| `changeset.conflict` | Apply refused because the real files drifted (`files` = count) |
| `changeset.failed` | Apply started and did not finish (`reason`) |
| `changeset.expired` | Expired by the sweep or on access |

## CLI examples

Via the daemon's state directly or with `--server` (all six commands are supported over REST):

```bash
# Run a build in an isolated copy; VM sandboxes need --path
fluxctl sandbox speculate $SB --path /work --ttl-seconds 600 -- make build
# {"id": "<cs>", "state": "pending", "changes": {...}, "side_effects": {...}, ...}

fluxctl sandbox changesets $SB              # list
fluxctl sandbox changeset $SB $CS           # inspect one
fluxctl sandbox approve $SB $CS             # or: fluxctl sandbox reject $SB $CS
fluxctl sandbox apply $SB $CS               # approved only; 409 on conflict
```

REST equivalent:

```bash
curl -sS -X POST http://127.0.0.1:7788/v1/sandboxes/$SB/speculate \
  -H 'content-type: application/json' \
  -d '{"command":"make build","paths":["/work"],"ttl_seconds":600}'
curl -sS -X POST http://127.0.0.1:7788/v1/sandboxes/$SB/changesets/$CS/approve
curl -sS -X POST http://127.0.0.1:7788/v1/sandboxes/$SB/changesets/$CS/apply
```

All of these are admin-only. Request and response shapes are in [api.md](api.md#speculation-and-changesets).
See also [sandbox-changes.md](sandbox-changes.md) for the baseline and diff primitives this builds on.
