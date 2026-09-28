# Sandbox file change-set

See which files an agent changed inside a sandbox VM: record a **baseline**
of the regular files under some directories, run the agent, then ask for
the **changes** (added / modified / deleted). This is the same question
Sandlock's `--dry-run` answers for a process sandbox, answered for a guest.

It reports changes; it does not revert them. To roll a sandbox back, use
the existing snapshot/restore (`POST /v1/sandboxes/{id}/snapshot` and
restore), not this feature.

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
added, one modified and one deleted path in `sha256` mode. `dry-run` on the VM
returned 501 as documented. The same flow ran against a procbox sandbox
(`docs/procbox-backend.md`); paths there are rooted at the workspace, so use
`/work`, not `work`.
