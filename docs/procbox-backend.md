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
  "exit_code": 0, "stdout": "...", "stderr": "...", "discarded": true, "paths": ["/"] }
```

A workspace over `max_workspace_mib` is refused (413) rather than copied. For a
**VM** sandbox the route returns **501**: a real discard there needs a
snapshot-restore API, which this server does not expose, and it would not be
honest to report changes without reverting them.

## Errors

| Status | Meaning |
|---|---|
| 400 | Bad path or arguments, limit above a server cap |
| 403 | procbox disabled, or not an admin token |
| 404 | Unknown sandbox, or another tenant's |
| 413 | Workspace or file over a size cap |
| 501 | The route needs a guest VM |
| 503 | The host cannot enforce the confinement (strict mode) |

## Limits worth knowing

- **Shared kernel.** A kernel bug is a host bug. This is not a substitute for a
  microVM.
- **Unix sockets are not confined.** On Landlock ABI 8 (this lab's kernel) a
  confined command can still `connect()` to a *pathname* Unix socket anywhere on
  the host. Verified by test: a command with no access to the socket's
  directory reached a listener there. A host daemon socket (the container
  runtime's, or an API socket) is therefore reachable. Abstract sockets and
  signals are scoped (ABI 6+); pathname sockets are not until a newer ABI. Keep
  such sockets owned by a different user with mode `0600`.
- **Same user as the daemon.** Commands run as the daemon's own user. Run the
  daemon unprivileged when enabling procbox; as root, the sandboxed process is
  root-owned (still confined by Landlock and seccomp, but with more to lose if
  a rule is missed).
- **UDP is not filtered.** Landlock's network rules cover TCP only, so "no
  network" means no TCP.
- **`RLIMIT_NPROC` counts the daemon user's processes**, not just the sandbox's,
  so it is a coarse fork-bomb bound, and root is exempt from it.
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
