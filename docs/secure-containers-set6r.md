# FluxVM Secure Containers — Set 6 (Runtime): namespace isolation

Set 6 (Runtime track) closes the top P0 gate carried since Set 1: containers
in a Pod VM no longer share the guest's PID, mount, IPC and UTS namespaces by
default. Through Set 5, `spawn_gated` did a bare `fork()` + `chroot()` — the
QEMU VM boundary was the *only* isolation between containers in the same Pod.

## What changed

- **Mount namespace: always private, `pivot_root` replaces `chroot`.** Every
  container gets `CLONE_NEWNS`. The forked process bind-mounts its rootfs onto
  itself, `pivot_root`s into it, lazily detaches the old root, and remounts a
  fresh `/proc` (needed because a PID namespace's `/proc` view depends on
  which PID namespace is active, and a private mount namespace otherwise
  inherits whatever `/proc` was mounted at unshare time).
- **PID namespace: private per container by default, shareable via
  `shareProcessNamespace`.** The shim detects Kubernetes'
  `shareProcessNamespace: true` the same cross-runtime way Kata/runc do:
  containerd's CRI plugin only sets a `path` on the OCI `linux.namespaces` PID
  entry when the Pod requested a shared PID namespace. We only check
  *presence* of that path, never its value (it is host-meaningless from
  FluxVM's guest-side perspective) — the shared namespace itself is tracked
  guest-side.
- **Sandbox/pause-container convention.** The shim marks the container whose
  id equals its containerd shim group (`is_sandbox`) — the CRI
  pause/sandbox-equivalent. That container's IPC and UTS namespaces (and PID,
  when shared) are recorded in the guest agent; every sibling container in the
  same Pod VM joins them via `setns()`, matching runc/Kata's "join the pause
  container" model. IPC/UTS are always Pod-shared (standard Kubernetes/CRI
  behavior, no separate flag needed).
- **User namespace: opt-in, off by default.** Set `FLUXVM_CONTAINER_USERNS=1`
  in the container-agent's environment to enable `CLONE_NEWUSER` per
  container, with a full identity uid/gid map (`0 0 4294967295`) — this buys a
  distinct capability-scoping namespace without shifting uids against
  virtiofs ACLs. Off by default because it is new and unproven under real
  multi-container Pod load; see "Remaining gates" below.

## Why an outer/inner process split

`unshare(CLONE_NEWPID)` (and `setns()` into an existing PID namespace) has a
well-known asymmetry: the calling process is **not** itself moved into the
namespace — only its *future children* are. To land the actual OCI process
inside the target PID namespace, `spawn_gated` now forks twice:

1. **Outer** (the pid the agent already tracked pre-Set-6): establishes
   namespaces (`unshare`/`setns`), then forks the inner process, then reaps it
   and exits with its translated status. No protocol change was needed —
   `fluxvm-container-protocol` was already keyed by container/exec id strings,
   never raw pid, and the agent already only ever `waitpid()`s this outer pid.
2. **Inner**: becomes PID 1 of a fresh PID namespace (or a plain member of a
   joined one), performs `pivot_root`, then the existing uid/gid/capabilities/
   seccomp/`execve` sequence, unchanged from Set 5.

A `pid_for_children`-shaped correctness bug was caught during validation:
`/proc/<outer_pid>/ns/pid` does **not** reflect the new namespace after
`unshare(CLONE_NEWPID)` (it keeps showing the outer's own, ambient
namespace, forever — see pid_namespaces(7)). The correct handle for "the
namespace future children land in" is the dedicated
`/proc/<outer_pid>/ns/pid_for_children` magic symlink (Linux 4.12+),
confirmed against this exact fork/unshare sequence on a real 6.8 kernel: it
matches the inner process's actual namespace id, while plain `ns/pid` does
not. `mnt`/`ipc`/`uts`/`user` have no such split (unshare/setns move the
caller immediately), so their plain `ns/<type>` files are correct as-is.

A second synchronization pipe (`ns_ready`) signals "the outer process has
finished unshare/setns and successfully forked the inner process" back to the
request-handling thread, so it only opens `/proc/<outer_pid>/ns/*` once those
are guaranteed to reflect post-unshare state — reading them any earlier could
observe the wrong (pre-unshare) namespaces.

## Exec

`Exec` always joins the target container's own recorded namespaces (mount,
pid, ipc, uts, and user if enabled) rather than creating anything fresh. Once
joined, "/" is already the container's pivoted rootfs — exec skips
`pivot_root`/`chroot` entirely in the normal case, falling back to a bare
`chroot` only if a namespace fd could not be recorded (defense in depth, not
the expected path).

## Validation performed

- `cargo build`/`cargo test` for `fluxvm-container-protocol`,
  `fluxvm-container-agent` and `fluxvm-containerd-shim` on a real Linux 6.8
  (Ubuntu 24.04) host — all existing unit tests plus the updated
  `create_round_trip` protocol test pass.
- A standalone probe (fork → `unshare(CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWIPC|
  CLONE_NEWUTS)` → inner fork → `pivot_root`), run as root on that host,
  confirming: the inner process is PID 1 of a distinct namespace; the outer's
  `pid_for_children` handle matches it exactly while plain `ns/pid` does not;
  `mnt`/`ipc`/`uts` differ from the ambient namespace immediately upon
  `unshare` (no split, as expected); and the `pivot_root` sequence correctly
  exposes the new root and makes the old one unreachable.
- **Not yet run**: a full KVM/containerd/Kubernetes multi-container Pod
  end-to-end pass (see `scripts/e2e-secure-containers-namespaces.sh`, added
  alongside this Set but not yet exercised against a live cluster) and
  `shareProcessNamespace: true` under real Pod churn.

## Remaining gates

- Device-cgroup enforcement (a real `BPF_PROG_TYPE_CGROUP_DEVICE` allow/deny
  list) — namespace isolation is not device isolation.
- `CLONE_NEWUSER` validation under real multi-container Pod load before
  considering a default-on flip.
- Full KVM/containerd/Kubernetes end-to-end coverage of this Set on a
  self-hosted node (`scripts/e2e-secure-containers-namespaces.sh`).

## Test on a real KVM/containerd/Kubernetes node

```bash
./scripts/e2e-secure-containers-namespaces.sh
```
