# Rootless process sandboxes through `/v1/sandboxes`

`fluxvm-procbox` (see [procbox.md](procbox.md)) confines one process with
Landlock and seccomp. This page covers using it as a **sandbox kind** behind the
same `/v1/sandboxes` API as VM sandboxes, so an agent harness can pick the
lightweight tier without a second client.

A procbox sandbox shares the host kernel. It is a **weaker boundary than a
microVM** and is off by default; use a VM sandbox for untrusted code that must
not be able to attack the host kernel.

## Enable it

```toml
[sandbox.procbox]
enabled = true
```

Everything else has a default; see `config.example.toml` for the caps
(`max_memory_mib`, `max_timeout_secs`, `max_processes`, `max_workspace_mib`,
`allow_net`, `best_effort`). Without `enabled = true`, creating one returns
**403**.

Creation is checked against the real policy: unless `best_effort = true`, the
create call fails with **503** if the kernel cannot enforce it (Landlock too old
for the requested rules, no seccomp). It never silently runs weaker.

### Identity and isolation

```toml
[sandbox.procbox]
uid_base   = 200000     # pool of sandbox uids: uid_base .. uid_base + uid_count
uid_count  = 4096       # = the most procbox sandboxes at once (root daemon)
allow_root = false      # only matters when uid_count = 0
isolation  = "auto"     # "off" | "auto" | "strict"
```

When the daemon runs **as root**, every sandbox is given its own uid from the
pool at creation (recorded in `procbox.json`; a deleted sandbox frees it) and
each command is dropped to that uid and gid with no extra groups. `max_processes`
(`RLIMIT_NPROC`) is then really per sandbox, the workspace is owned by that uid,
and files written through the API are chowned to it. The uid needs to reach the
workspace, so `instances/` and the workspace are made searchable (`o+x`); any
directory above `state_dir` that is not raises **503** naming it. With
`uid_count = 0` a root daemon refuses to create or run a sandbox (**503**) unless
`allow_root = true`; a sandbox created before the pool existed has no uid and is
refused the same way. An **unprivileged daemon** cannot switch uid and runs
commands as itself, as before.

`isolation` puts each command in private mount, pid, ipc and uts namespaces with
a root holding only the granted system paths and the workspace, and with no
network namespace access at all when `net_ports` is empty. `strict` makes
creation fail with **503** where the host cannot do that; `auto` runs anyway and
appends `[procbox] not enforced: namespace isolation (...)` to the command's
stderr. See [procbox.md](procbox.md#namespace-isolation-uid-drop-and-socket-filters).

## Create

```http
POST /v1/sandboxes
{ "name": "agent-1", "ttl_seconds": 3600,
  "procbox": { "timeout_seconds": 60, "max_memory_mib": 512, "net_ports": [] } }
```

The presence of a `procbox` object (`{}` for defaults) selects this kind.
`template`, `spec`, `volumes`, `vcpus`, `confidential` and the HTTP-proxy ports
are rejected. Limits above the server caps are rejected (400), not lowered.
`net_ports` needs `allow_net`; empty means no network.

The result is an ordinary sandbox record: tenant-scoped, counted against
`max_vms_per_token` and `max_memory_mib_per_token`, listed by
`GET /v1/sandboxes`, expired by `ttl_seconds`, deleted with `DELETE /v1/vms/{id}`
(which removes the workspace).

## What each route does

| Route | procbox behaviour |
|---|---|
| `POST /v1/sandboxes/{id}/process` | Runs `/bin/sh -c command` confined, cwd = workspace. Same response shape as a VM (`result: "exec"`, `exit_code`, `stdout`, `stderr`). A timeout gives `exit_code` 124; a signal gives 128+signal. |
| `POST .../fs/read`, `.../fs/write` | Files inside the workspace only (below). Same shapes as a VM. |
| `POST .../baseline`, `.../changes` | Same API as [sandbox-changes.md](sandbox-changes.md), computed from the host workspace with no guest exec. Paths are relative to the workspace root, so `["/"]` is the whole workspace. |
| `POST .../dry-run` | Below. |
| `POST .../snapshot`, `/sandbox/{id}/...` and `.../http/{port}/...` (HTTP proxy), pause/resume, console | **501**: they need a guest. |

All of these are admin-only and tenant-scoped exactly like VM sandbox routes.

## The workspace and path rules

Each sandbox gets `<state_dir>/instances/<id>/files/`, mode `0700`. It is the
**only** writable location for commands, and the root for every API path. The
marker file that records the limits lives one level up, outside the writable
root, so a command cannot edit its own limits (tested).

API paths are resolved beneath that root by the kernel, with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`:

- relative paths, or absolute paths already inside the workspace, are accepted;
- `..`, absolute paths anywhere else, NUL bytes and empty paths are rejected
  (400) before opening;
- **any symlink on the path is refused**, even one pointing inside the
  workspace, and this is enforced at open time, so swapping a directory for a
  symlink between a check and the open (a TOCTOU race by the confined command)
  still fails. Reads reject non-regular files (FIFOs would block).
- It needs Linux 5.6+ (`openat2`); without it the call fails closed (503).

Writes create missing parent directories one component at a time under the same
rules and are capped at 64 MiB per file and `max_workspace_mib` per workspace.

## What a command may touch

Read-only and executable: `/usr`, `/lib*`, `/bin`, `/sbin`, plus a **fixed list**
of `/etc` files (`ld.so.*`, `passwd`, `group`, `nsswitch.conf`, `hosts`,
`resolv.conf`, `localtime`, CA certificates) and `/dev/urandom`, `/dev/random`,
`/dev/zero`. `/etc` is deliberately not granted whole: it holds `shadow`, SSH
keys and the daemon's own config with API tokens. Read-write: the workspace and
`/dev/null`. TCP connect is denied unless `net_ports` lists ports; TCP bind is
denied. seccomp denies the dangerous-syscall list, `PR_SET_NO_NEW_PRIVS` is set,
the environment is cleared (`PATH`, `HOME` and `WORKSPACE` only), and memory
(`RLIMIT_AS`), process count (`RLIMIT_NPROC`) and the wall-clock timeout are
applied; the timeout kills the whole process group.

## Dry-run

```http
POST /v1/sandboxes/{id}/dry-run
{ "command": "make build", "timeout_seconds": 120, "paths": ["/"] }
```

The workspace is copied to a throwaway directory beside it (symlinks recreated,
never followed), the command runs confined against the **copy**, the copy is
diffed against its own pre-run state, and the copy is deleted whether the
command succeeded or not. The real workspace is only read. Response:

```json
{ "changes": { "added": ["/out.bin"], "modified": [], "deleted": ["/tmp.txt"], "unchanged": 12 },
  "exit_code": 0, "stdout": "...", "stderr": "...", "discarded": true,
  "reverted_via": "workspace-copy", "paths": ["/"] }
```

`reverted_via` is `"workspace-copy"`. A workspace over `max_workspace_mib` is
refused (413) rather than copied. A native flux-vm **VM** sandbox is dry-run by
snapshot and restore instead (`reverted_via: "snapshot"`, see
[sandbox-changes.md](sandbox-changes.md#dry-run-on-a-vm-sandbox)); other VM
backends answer **501** rather than report changes without reverting them.

## Errors

| Status | Meaning |
|---|---|
| 400 | Bad path or arguments, limit above a server cap |
| 403 | procbox disabled, or not an admin token |
| 404 | Unknown sandbox, or another tenant's |
| 413 | Workspace or file over a size cap |
| 501 | The route needs a guest VM |
| 503 | The host cannot enforce the confinement (strict mode), a root daemon has no sandbox uid to give, the uid pool is exhausted, or a directory above the workspace is not searchable |

## Limits worth knowing

- **Shared kernel.** A kernel bug is a host bug. This is not a substitute for a
  microVM.
- **Unix sockets.** Landlock ABI 8 does not stop `connect()` to a *pathname* Unix
  socket, so procbox denies `socket(AF_UNIX)` with seccomp instead (a command
  cannot create the socket to connect with; `socketpair` still works). With
  isolation the host's socket files are not in the command's root at all.
  Abstract sockets and signals are scoped (ABI 6+).
- **UDP, raw, packet and netlink sockets** are denied by the same seccomp socket
  filters while the network is shared with the host, and unreachable when
  `net_ports` is empty and isolation is on (empty network namespace). With
  `net_ports` set, DNS over UDP is therefore not available to the command.
- **Identity.** A root daemon isolates each sandbox under its own uid (above); an
  unprivileged daemon runs commands as itself, so `RLIMIT_NPROC` counts all of
  that user's processes and is only a coarse fork-bomb bound. Enabling procbox
  under a root daemon without a uid pool is refused, not run as root.
- **Namespaces need kernel support.** A root daemon always can; an unprivileged
  daemon needs unprivileged user namespaces, which some distributions disable
  (Ubuntu 24.04+ with `apparmor_restrict_unprivileged_userns=1`, as on the lab
  host). Use `isolation = "auto"` to run anyway and see the gap, or `"strict"`
  to refuse.
- **Disk use by commands is not capped.** `max_workspace_mib` bounds API writes
  and dry-run copies; a command can still fill the disk.
- **Quota accounting** treats the memory cap as a VM of that size.

## Verification

Unit and integration tests run on a real Linux 7.0 host (Landlock ABI 8) as an
unprivileged user: path escapes (`..`, absolute, symlink to outside, symlink
swapped after the check), workspace lifecycle, a confined write outside the
workspace failing, dry-run leaving the original byte-identical, and an HTTP
end-to-end through the real router (create, files, process, baseline/changes,
dry-run, 501 routes, tenant scoping, delete). They skip cleanly when the host
cannot enforce Landlock with TCP rules (ABI 4+) and seccomp. The end-to-end
drives the in-process router and manager, not a deployed daemon.

## Verified live (2026-09-28)

With a daemon started by an unprivileged user (Linux 7.0, Landlock ABI 8) and
`[sandbox.procbox] enabled = true`, the Python and Go SDKs ran the whole flow
against it over HTTP: create, files, confined `process`, `baseline`/`changes`,
`dry-run` (workspace unchanged afterwards), a write outside the workspace
(denied), `..`, absolute and symlink path escapes (400), `snapshot` (501) and
delete. Both SDKs expose it as `procbox=` / `Procbox` on create and a
`dry_run` / `DryRun` method.

## Verified live with a root daemon (2026-09-28)

A private daemon (`fluxctl serve` as root on `127.0.0.1:17791`, its own config,
`state_dir=/tmp/ws3-state`, `[sandbox.procbox] enabled = true, uid_base = 231000,
uid_count = 16, isolation = "auto"`) was driven with the Python SDK
(`python/tests/live_procbox_uidpool.py`, plus the stock `live_procbox.py`) and
`curl`, on the Linux 7.0 lab host. The production service (port 7788,
`/var/lib/fluxvm`, `/etc/fluxvm.toml`) was not touched: same PID, start time,
config and binary hashes afterwards; the private daemon, sandboxes, state and
config were removed.

| Check | Result |
|---|---|
| Two sandboxes run as different uids from the pool, gid = uid, no extra groups, no capabilities | pass |
| Sandbox A cannot read sandbox B's `secret.txt` or list the state dir | pass |
| Workspace, dirs and files written through the API are owned by the sandbox uid (`231000:231000`, `files` mode 700, workspace 711, `instances/` 755) | pass |
| Fork bomb in A (`max_processes = 40`) hits `fork` failures in A only; B keeps forking and running | pass |
| write/read, baseline, changes, dry-run (workspace unchanged), snapshot 501 | pass |
| `..`, absolute and sandbox-created symlink escapes (`ln -s /etc/passwd`) rejected on read and write; a write to `/etc` from inside blocked | pass |
| 17th sandbox with `uid_count = 16` -> 503 "pool exhausted"; deleting one frees its uid | pass |
| Daemon with `uid_count = 0`, `allow_root = false`: create -> **503** ("refusing to run sandbox commands as root") | pass |
| Same daemon on an existing uid-less sandbox: exec -> **503** | pass |
| `allow_root = true`: create and exec work; the command is uid 0 in the private root with all capabilities dropped | pass |

The real unprivileged user-namespace path on this host (Ubuntu,
`kernel.apparmor_restrict_unprivileged_userns=1`, left as is): `fluxvm-procbox
probe` as an ordinary user reports `namespaces (isolation): no (writing the
uid/gid map failed: Permission denied (os error 13) (AppArmor restricts
unprivileged user namespaces ...))`; `--isolation strict` exits 2 with that
reason, and `--isolation auto` runs the command and lists it under
`enforcement.not_enforced`. A root daemon is not affected because it builds the
namespaces with its own privileges.
