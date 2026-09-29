# fluxvm-procbox: rootless process sandbox

`fluxvm-procbox` confines an ordinary process with **Landlock** (filesystem,
TCP ports, IPC scoping), **seccomp-bpf** (a syscall denylist) and **rlimits**.
It needs no root, no KVM, no image and no cgroups, and starts in milliseconds.
It is the lightweight tier below FluxVM's microVMs and secure containers.

**It is a weaker boundary than a microVM.** The sandboxed process shares the
host kernel, so a kernel bug reachable through an allowed syscall is an escape.
Use a microVM (`backend: "flux-vm"`, Firecracker, Cloud Hypervisor, QEMU) for
hostile code or multi-tenant isolation, and procbox for cheap, fast, defence in
depth around code you mostly trust: build steps, tool calls, agent scripts.

> Status: a standalone CLI and library, and also selectable as a sandbox kind
> through `/v1/sandboxes` (opt-in `[sandbox.procbox]`, with a dry-run): see
> [procbox-backend.md](procbox-backend.md).

## Usage

```bash
fluxvm-procbox probe                       # what this kernel can enforce

fluxvm-procbox run \
  -r /usr -r /lib -r /lib64 -r /bin -r /etc \    # read-only + executable
  -w /tmp/work \                                 # read-write (implies read)
  --net-port 443 \                               # TCP connect to 443 only
  -m 256M -P 200 -t 30 \                         # memory, procs, wall clock
  --clean-env --json \
  -- python3 task.py
```

| Option | Meaning |
|---|---|
| `-r/--read PATH`, `-w/--write PATH` | Filesystem allow rules. Everything not listed is denied, including exec. |
| `--net-port P`, `--bind-port P`, `--no-net` | TCP connect / bind allowlists, or deny all TCP. Unset = deny all TCP; the CLI has no flag for unrestricted TCP (use a [profile](#profiles) with `net_connect = "any"` if you really want that). |
| `-p/--profile SPEC` | Start from a TOML [profile](#profiles) (path or name). Other flags are applied on top. |
| `-m`, `-P`, `-t`, `--cpu-seconds` | `RLIMIT_AS`, `RLIMIT_NPROC`, wall-clock timeout, `RLIMIT_CPU`. Core dumps are always off. |
| `--no-scope` | Do not scope abstract unix sockets and signals (scoping is on by default). |
| `--allow-namespaces` | Permit creating namespaces (denied by default). |
| `--isolation off\|auto\|strict` | Run in private user/mount/pid/ipc/uts namespaces with a root that holds only the granted paths (and no network namespace access when TCP is fully denied). See [Namespace isolation](#namespace-isolation-uid-drop-and-socket-filters). |
| `--run-as UID[:GID]` | Drop to this unprivileged id before confining (root caller). |
| `--allow-unix`, `--allow-udp` | Keep `socket(AF_UNIX)` / UDP-raw-netlink sockets when the network is restricted. |
| `--seccomp-kill`, `--no-seccomp` | Kill on a denied syscall instead of `EPERM`, or disable the denylist. |
| `--clean-env`, `--env K=V`, `--cwd DIR` | Empty environment (PATH, HOME only) plus explicit variables. |
| `--best-effort` | Run with what the kernel can enforce and report the rest. |
| `--max-abi N` | Treat the kernel's Landlock ABI as at most N. |
| `--json` | Capture output and print `{exit_code, signal, timed_out, stdout, stderr, wall_ms, enforcement}`. |

Without `--json` the child inherits stdio and the CLI exits with its status
(`124` on timeout, `128+signal` if killed, `2` for a sandbox error).

## Strict by default

If the kernel cannot enforce something the policy asks for, the run **fails
before starting**, naming each gap:

```
strict mode: this host cannot enforce the requested policy: TCP connect port
rules (needs Landlock ABI >= 4, have 3); ...; relax the policy, use a newer
kernel, or pass --best-effort to run with the gaps reported
```

`--best-effort` runs anyway and lists exactly what was **not** enforced in
`enforcement.not_enforced` (JSON) or on stderr. Strict mode needs Landlock
ABI >= 3 (so truncate and cross-directory rename are controlled) and, with the
default IPC scoping, ABI >= 6 (Linux 6.12+). Unrestricted TCP is a choice, not
a gap, and is not reported.

| Protection | Minimum Landlock ABI (kernel) |
|---|---|
| Filesystem rules | 1 (5.13); strict requires 3 (6.2) |
| TCP connect/bind port rules | 4 (6.7) |
| Abstract-unix-socket and signal scoping | 6 (6.12) |
| Device ioctl control | 5 (6.10), reported but not fatal |

## How confinement is applied

Everything fallible happens in the parent: the plan, the Landlock ruleset (rule
paths opened `O_PATH`), and the compiled seccomp programs. Between `fork` and
`exec` the child only makes syscalls, in this order: rlimits,
`PR_SET_NO_NEW_PRIVS`, `landlock_restrict_self`, seccomp last (so the filter
does not have to allow the setup calls). The parent is never confined. The
child runs in its own process group; on timeout, and when the child exits, the
whole group is `SIGKILL`ed so nothing outlives the run.

The seccomp denylist returns `EPERM` (or kills) for `ptrace`, `mount`,
`umount2`, `pivot_root`, `chroot`, `kexec_load`, `init_module`,
`finit_module`, `delete_module`, `bpf`, `perf_event_open`, `keyctl`,
`add_key`, `request_key`, `reboot`, `swapon`, `swapoff`, `open_by_handle_at`,
`userfaultfd`, `process_vm_readv` and `process_vm_writev`. Unless
`--allow-namespaces`, it also denies `unshare`, `setns`, and `clone` with any
`CLONE_NEW*` flag, and answers `clone3` with `ENOSYS` so libc falls back to
`clone` (seccomp cannot read `clone3`'s flags from user memory).

## Namespace isolation, uid drop and socket filters

Landlock alone leaves three gaps: a command still *sees* the host's paths (only
access is denied), pathname Unix sockets and UDP are outside its rules, and
`RLIMIT_NPROC` counts every process of the caller's uid. This section closes them.

**Isolation** (`--isolation auto|strict`, profile key `isolation`). The child
enters new mount, pid, ipc and uts namespaces (plus an empty network namespace
with only `lo` up when both TCP connect and bind are `deny`), assembles a tmpfs
root holding read-only bind mounts of the `-r` paths and read-write binds of the
`-w` paths, `pivot_root`s into it, detaches the old root and drops every
capability. Paths that were not granted do not exist (`ENOENT`, not `EACCES`),
the command is pid 1 of its namespace (so the whole tree dies with it), a granted
`/proc` is a fresh mount of that pid namespace, and the exit status and any
fatal signal are forwarded by a small intermediate process. Landlock and seccomp
are then applied exactly as without isolation (Landlock rules are inode based, so
they survive the bind mounts).

- A **root caller** builds the namespaces with its real privileges (no user
  namespace), then drops capabilities and switches to `--run-as`.
- A **non-root caller** uses an unprivileged user namespace with an identity uid
  and gid map. Hosts can forbid that: `probe` reports it, and Ubuntu 24.04+ with
  `kernel.apparmor_restrict_unprivileged_userns=1` blocks writing the id map.
  `auto` then runs without namespaces and lists the gap in
  `enforcement.not_enforced`; `strict` refuses to run.

**Uid drop** (`--run-as UID[:GID]`, root caller only). The command runs as an
unprivileged uid with no supplementary groups, so `RLIMIT_NPROC` and file
ownership are per sandbox. Every directory from `/` to the granted paths must be
searchable by that uid.

**Socket filters.** When TCP is restricted and the network is shared with the
host, seccomp argument filters on `socket()` deny `SOCK_DGRAM`/`SOCK_RAW` (UDP,
ICMP, raw IP), `AF_PACKET` and `AF_NETLINK` unless `--allow-udp`, and `AF_UNIX`
unless `--allow-unix` (seccomp cannot read a `sockaddr`, so a pathname socket is
stopped at creation; `socketpair` is a different syscall and still works). The
filters are skipped where they are redundant: unrestricted TCP is a deliberate
choice, and an empty network namespace has nothing to reach.
`enforcement` reports `uid_dropped`, `namespaces`, `network_isolated` and
`seccomp_sockets`.

## Profiles

A profile is a saved, reviewable policy in TOML. Every key is optional and
**unknown keys are rejected** (a typo like `fs_reed` is an error, not a silent
no-op); filesystem paths must be absolute.

```toml
fs_read  = ["/usr", "/lib", "/lib64", "/bin", "/etc/hostname"]
fs_write = ["/tmp/work"]
net_connect = [443]            # "any" | "deny" | [ports]
net_bind    = "deny"
scope_ipc   = true
seccomp     = "errno"          # "errno" | "kill" | "off"
syscall_deny  = ["chmod"]      # denied on top of the default denylist
syscall_allow = ["ptrace"]     # removed from the default denylist
max_memory  = "256M"           # bytes or a size string
max_processes = 200
cpu_seconds = 30
timeout_secs = 30
clean_env   = true
cwd         = "/tmp/work"
best_effort = false
allow_namespaces = false
max_abi     = 6

[env]
FOO = "bar"
```

```bash
fluxvm-procbox profile validate build.toml     # parse, check paths/ports/syscalls, summarize
fluxvm-procbox run -p build.toml -- make -j4
fluxvm-procbox run -p build -- make            # a name: $XDG_CONFIG_HOME/fluxvm-procbox/profiles/build.toml
                                               # (falls back to ~/.config/...)
```

`-p SPEC` is a path if it contains `/` or ends in `.toml`, otherwise a name
(letters, digits, `.`, `_`, `-`). **CLI flags override the profile:** list
options (`-r`, `-w`, `--env`) are added to the profile's lists, scalars
(`-m`, `-P`, `-t`, `--cpu-seconds`, `--cwd`, `--max-abi`) replace, `--net-port`/
`--bind-port`/`--no-net` replace that network rule, and the switches
`--best-effort`, `--clean-env`, `--no-scope`, `--allow-namespaces`,
`--no-seccomp`, `--seccomp-kill` can turn a behaviour on but not back off (edit
the profile for that).

Library: `Profile::load(spec)`, `Profile::from_toml_str`, `profile.apply(&mut
policy, &mut overrides)`, and `run_with(&policy, &SyscallOverrides, argv,
opts)`, which takes the profile's seccomp `syscall_deny`/`syscall_allow` edits.
`run()` and `Policy` are unchanged.

## Learning a profile

```bash
fluxvm-procbox learn --out build.toml -- make            # observe a real run
fluxvm-procbox learn -t 120 --cwd /tmp/scratch -- python3 task.py > task.toml
fluxvm-procbox run -p build.toml -- make                 # now confined
```

`learn` runs the command **unconfined, for real, with its real side effects**
(files it writes are written; requests it sends are sent) while tracing its
syscalls, then emits the smallest profile that would allow exactly that. **Run
it in a disposable directory, container or VM.** It needs no root. With
`--out` the program's stdout stays on the terminal; without it the program's
stdout goes to stderr so stdout is only the profile. `--json` prints the full
observation and the profile. Exit status: `0` if the traced program exited 0,
`3` if it did not (the profile is still written, with a warning at the top),
`2` for a learn error. `--out` refuses to overwrite without `--force`. With
`--out`, the raw observations are also saved next to the profile as
`<profile>.observed.json` (for `build.toml`: `build.toml.observed.json`), which
is what makes [merging runs](#merging-runs-across-invocations) lossless.

What is recorded (successful calls only, so ENOENT probes do not widen the
profile): files opened read-only, files opened for writing or truncated, files
created (`O_CREAT` on a path that did not exist), directories where entries were
created, removed or renamed (`mkdir`, `unlink`, `rename`, `link`, `symlink`,
`mknod`, `O_TMPFILE`, unix `bind`), executed files, the interpreter and every
mapped library of each new image, and TCP `connect`/`bind` ports (the socket
type is checked with `pidfd_getfd`, so UDP does not become a TCP rule). Paths
are canonicalized (symlinks resolved), so `/bin/sh` is recorded as
`/usr/bin/dash`.

How it generalizes (each step is listed in the `# Generalized:` header):

- Anything under `/usr`, `/lib`, `/lib32`, `/lib64`, `/bin`, `/sbin` becomes
  that directory (libraries and binaries are stable and numerous).
- Three or more sibling files in a directory become the directory, **unless**
  it is too broad: `/`, `/home`, `/home/<user>`, `/root`, `/etc`, `/var`,
  `/tmp`, `/proc`, `/sys`, `/dev`, `/run`, `/boot`, `/opt`, `/mnt`, `/media`,
  `/srv`. Those are kept as individual files.
- Writes stay narrow: an existing file that was written keeps its own rule. A
  file that was *created* needs write access to its **directory** (Landlock
  cannot name a file that does not exist yet). If that directory is too broad
  (`/etc`, `/home/<user>`, ...) the grant is refused and listed under
  `# Needs human review`; `/tmp`, `/var/tmp` and `/dev/shm` are granted but
  flagged, because other processes share them. Never `/` or `/home`.
- Network: no connect observed means `net_connect = "deny"`, likewise for bind.
- Entries covered by a broader grant are dropped.

Review these before trusting a profile: the header lists granted shared
scratch directories, refused writes, that Landlock restricts TCP **ports, not
hosts** (the observed `ip:port` list is printed), AF_UNIX connects (not
restricted by Landlock filesystem rules before ABI 9) and non-TCP endpoints
(unrestricted), and per-process `/proc/<pid>` paths (see below).

### Merging runs across invocations

One run only sees the code paths it takes. To cover several, learn them one
after another into the same profile, or all at once:

```bash
fluxvm-procbox learn --label build --out p.toml -- make                    # run 1
fluxvm-procbox learn --label tests --merge p.toml --out p.toml -- make test  # run 2, in place
fluxvm-procbox learn --out q.toml --cmd 'make' --cmd 'sh -c "make test"'   # both in one go
fluxvm-procbox learn --merge p.toml --out p.toml --forget build -- true    # drop run "build"
```

- **The observation file.** Every `learn --out P` also writes
  `P.observed.json` (versioned, runs sorted by label, `deny_unknown_fields`,
  size-bounded): one record per run with its label, exit status and everything
  it touched. `--merge P` loads it, unions it with the new runs, and
  **re-runs generalization over the union**, so directory collapsing reflects all
  runs (two files from run 1 plus one from run 2 in the same directory become
  that directory, exactly as if one run had touched all three).
- **Labels.** A run's label is its command line, or `--label` for the command
  after `--` (`--cmd` runs are labelled by their text). A run with a label that
  is already recorded **replaces** it; an identical run changes nothing.
  `--forget LABEL` removes a recorded run (checked before anything is executed).
- **What is preserved.** The learned keys (`fs_read`, `fs_write`, `net_connect`,
  `net_bind`) are regenerated from all runs. Every other key (limits, syscall
  overrides, `env`, `seccomp`, ...) is kept from the prior profile. **Comments
  in the prior file are not preserved**; the header is regenerated and lists the
  runs and what the merge did. Paths and ports you added by hand to the learned
  keys are kept (recorded as the run `prior-edited`); paths you removed by hand
  come back, because the observations still say they were needed (use `--forget`).
  A hand-set `net_connect = "any"` is kept and flagged.
- **No observation file.** `--merge` refuses a profile without one, unless you
  pass `--merge-profile-only`: its grants then become observations labelled
  `prior`. Grants too broad for `learn` to ever produce (`/`, `/home`, `/etc`,
  ...) are **not** carried over, so merging never grants more than generalizing
  the same observations would.
- **Exit status** reflects only the commands run in this invocation. Writing the
  profile and its observation file are two atomic renames (observations first).

Limits: this is still **not a proof of completeness**. More runs cover more
paths, and a path no run executed is still missing. Observations are stored per
run without timing, so re-learning a command whose earlier output file now
exists legitimately records a write to that file rather than a create.

### Why ptrace, and its limits

Two mechanisms work for an unprivileged user: ptrace syscall tracing and
seccomp user-notification (`SECCOMP_RET_USER_NOTIF`). `learn` uses ptrace
(`PTRACE_TRACEME` in the child, `PTRACE_O_TRACEFORK|VFORK|CLONE|EXEC|EXITKILL`,
`PTRACE_GET_SYSCALL_INFO`) because it reports each call's **return value**, which
is how failed probes are ignored and `existed`/`created` is decided; it
auto-attaches to every fork, thread and exec; it needs no descriptor handoff or
per-notification `NOTIF_ID_VALID` bookkeeping; and it works on any child of the
tracer under `ptrace_scope <= 1`. User-notification only sees the syscalls the
filter lists and never sees results. Arguments are read from the tracee with
`process_vm_readv`.

Limits, honestly:

- **Real side effects.** The program runs for real. See above.
- **One run is not a proof.** Code paths that did not execute are not in the
  profile; run representative workloads, then review.
- **TOCTOU.** Paths are read from the tracee at syscall entry and could change
  before the kernel uses them; a hostile program can lie to `learn`. Use `learn`
  on code you already trust to be cooperative; the resulting profile is what
  protects you against it later.
- **ptrace is visible.** Programs that ptrace themselves (debuggers, `strace`)
  fail under `learn`, programs that check `TracerPid` may behave differently,
  and tracing slows the program (two stops per syscall).
- **`/proc/<pid>` and `/proc/self` cannot be expressed.** Landlock rules bind to
  inodes when procbox applies them in the launcher, so `/proc/self` would name
  procbox rather than the child. They are reported, not granted.
- **Needs Linux 5.3+** (`PTRACE_GET_SYSCALL_INFO`, `pidfd_getfd`) and ptrace not
  blocked (container seccomp profiles and `ptrace_scope=3` block it; `learn`
  says so). Decoding is written for x86_64 and aarch64 but only x86_64 was run.
- **Mount namespaces and chroots.** Paths are resolved in `learn`'s own view of
  the filesystem, so a traced program that changes its root is misreported.
- Not captured: environment, stdin, inherited descriptors, `stat`-only access
  (Landlock does not control it), and `chmod`/`chown`/`utimes`.

## Limits you should know about

- **Shared kernel.** See the top of this page. A denylist is also weaker than
  an allowlist: an unlisted dangerous syscall is allowed.
- **Landlock's network rules are TCP only.** UDP, ICMP, raw and pathname Unix
  sockets are handled by the seccomp socket filters (or an empty network
  namespace), which only apply when TCP is restricted and are off with
  `--no-seccomp`.
- **`RLIMIT_NPROC` is per real user.** Without `--run-as` it counts every
  process of your UID, so a limit below your current process count makes `fork`
  fail immediately. Use `--run-as` (root) for a per-sandbox count.
- **Isolation needs namespaces.** Unprivileged user namespaces can be disabled by
  the distribution; a root caller is unaffected. The private root is a tmpfs of
  4 MiB holding only mountpoints, and there is no `/tmp`, `/dev` or `/etc`
  unless granted.
- **`RLIMIT_AS` limits address space, not resident memory.** Runtimes that
  reserve large virtual ranges (Go, JVM, some allocators) need a generous value.
- **`/dev/null` and friends are not implicit.** A shell running a background
  job opens `/dev/null`; grant it (`-r /dev/null` or `-w /dev/null`), as with
  any other path.
- **No** HTTP-level egress rules, copy-on-write working directory,
  `/proc` virtualization, per-syscall policy callbacks, or cgroup accounting.

## Verification

On Linux 7.0 (Landlock ABI 8), as an unprivileged user, `cargo test -p
fluxvm-procbox` passes: 39 unit tests, 18 confinement integration tests and 9
learn/profile integration tests. The confinement tests sandbox a real child and
check the kernel's answer (write outside an allowed directory `EACCES`, write
inside works, unlisted directory unreadable, TCP connect to a non-allowed port
`EACCES` and to an allowed one works, `ptrace`/`keyctl`/`process_vm_readv`
return `EPERM` confined and work unconfined, kill mode delivers `SIGSYS`,
memory cap `ENOMEM`, timeout kills the whole process group, signal and
abstract-socket scoping blocked, strict mode fails closed, and best-effort
reports the gap). The learn tests:

- learn `sh -c 'cat /etc/hostname >/dev/null; echo x > $DIR/result.txt'`, delete
  the created file, and the same command succeeds confined by the generated
  profile (proving the directory grant) while a write to an unlearned
  directory and a read of `/etc/passwd` fail;
- learn a `python3` loopback connect: the profile is exactly that port, the
  same run passes confined and a different listening port is blocked;
- a subshell child and a Python thread each write to a different directory and
  both are in the profile (fork/clone tracing);
- `learn` reports a failing program (exit `3`, warning header), refuses to
  overwrite, and `-t` kills a runaway trace;
- `profile validate` accepts good files and rejects unknown keys, relative
  paths and port 0; named profiles resolve through `XDG_CONFIG_HOME`; CLI flags
  override profile scalars; profile `syscall_allow`/`syscall_deny` change the
  seccomp denylist;
- merging: learn script A (reads `/etc/hostname`, writes into one directory),
  then merge script B (reads `/etc/os-release`, connects to a loopback port,
  writes into another) into the same profile in place: both scripts pass
  confined by the merged profile while a write to an unlearned directory and a
  connect to an unlearned port fail; re-learning a run leaves the parsed
  profile unchanged; `--forget` drops a run and its directory grant; several
  `--cmd` runs in one invocation give the same profile as merging them one by
  one; `--merge` without an observation file needs `--merge-profile-only` and
  keeps non-learned keys. Unit tests cover idempotency, order independence,
  generalization over the union, hand edits, the broad-grant refusal, the
  observation file schema (round trip, unknown fields, wrong version,
  duplicates, relative paths, size limits) and the command splitter.

Isolation, uid drop and the socket filters have their own suite
(`tests/isolate.rs`, 17 tests). On the lab host (Ubuntu with
`apparmor_restrict_unprivileged_userns=1`) the root-caller tests run under
`sudo` (private root shows only granted paths and `ENOENT` elsewhere, pid 1,
read-only binds, exit code and `SIGSYS` forwarding, timeout kill, empty network
namespace with only `lo` and a datagram that never reaches a host listener,
capabilities all zero, fresh `/proc`, uid switch, root-only files unreadable to
the sandbox uid, per-uid `RLIMIT_NPROC`); the unprivileged user-namespace path
is exercised on the same host by running the suite as root with
`FLUXVM_PROCBOX_FORCE_USERNS=1` (a testing knob that makes a root caller take
that path; `--run-as` is ignored then), and skips as a plain user there. The
socket-filter tests run unprivileged.

Tests skip, rather than fail, when the host kernel lacks the needed ABI, ptrace
is blocked, or `python3` is missing (none skipped on the lab host).
Older-kernel behaviour is covered by the planner unit tests and `--max-abi`
simulation, not by running on an old kernel. `cargo check` for non-Linux
targets was not run.
