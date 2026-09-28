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
fluxvm-procbox` passes: 16 unit tests plus 18 integration tests that sandbox a
real child and check the kernel's answer (write outside an allowed directory
`EACCES`, write inside works, unlisted directory unreadable, TCP connect to a
non-allowed port `EACCES` and to an allowed one works, `ptrace`/`keyctl`/
`process_vm_readv` return `EPERM` confined and work unconfined, kill mode
delivers `SIGSYS`, memory cap `ENOMEM`, timeout kills the whole process group,
signal and abstract-socket scoping blocked, strict mode fails closed, and
best-effort reports the gap). Tests skip, rather than fail, when the host
kernel lacks the needed ABI. Older-kernel behaviour is covered by the planner
unit tests and `--max-abi` simulation, not by running on an old kernel.
`cargo check` for non-Linux targets was not run.
