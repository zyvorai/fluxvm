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

> Status: standalone crate and CLI. It is **not** wired into `/v1/sandboxes`
> or the scheduler yet; that integration is not done.

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
| `--net-port P`, `--bind-port P`, `--no-net` | TCP connect / bind allowlists, or deny all TCP. Unset = unrestricted. |
| `-p/--profile SPEC` | Start from a TOML [profile](#profiles) (path or name). Other flags are applied on top. |
| `-m`, `-P`, `-t`, `--cpu-seconds` | `RLIMIT_AS`, `RLIMIT_NPROC`, wall-clock timeout, `RLIMIT_CPU`. Core dumps are always off. |
| `--no-scope` | Do not scope abstract unix sockets and signals (scoping is on by default). |
| `--allow-namespaces` | Permit creating namespaces (denied by default). |
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
`2` for a learn error. `--out` refuses to overwrite without `--force`.

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
- **TCP only.** Landlock's network rules cover TCP connect and bind. UDP,
  ICMP and raw sockets are not restricted by them.
- **`RLIMIT_NPROC` is per real user, not per sandbox.** It counts every process
  of your UID, so a limit below your current process count makes `fork` fail
  immediately. Pick it above what you already run.
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
  seccomp denylist.

Tests skip, rather than fail, when the host kernel lacks the needed ABI, ptrace
is blocked, or `python3` is missing (none skipped on the lab host).
Older-kernel behaviour is covered by the planner unit tests and `--max-abi`
simulation, not by running on an old kernel. `cargo check` for non-Linux
targets was not run.
