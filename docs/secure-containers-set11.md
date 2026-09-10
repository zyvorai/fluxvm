# Secure Containers Set 11 — seccomp notification + SELinux mount labels

Set 11 extends the guest security layer delivered in Set 10. It adds a bounded
in-guest supervisor for explicit seccomp user-notification rules, applies OCI
`linux.mountLabel` to OCI-created mounts, and exposes aggregate security
counters through the container-agent lifecycle protocol.

This is an additive delta over Set 10. When replaying onto the current FluxVM
`main`, retain the newer namespace/Sentinel work already upstream and replay the
Set 11 guest-security changes rather than replacing those files wholesale.

## Seccomp user notification

Explicit syscall rules using `SCMP_ACT_NOTIFY` are now accepted. The listener
fd created by libseccomp is transferred with `SCM_RIGHTS` over a private Unix
socketpair to a supervisor thread that stays in the guest container-agent
process, outside the workload's chroot and seccomp filter. The supervisor uses
libseccomp's notification API to receive, validate, and respond to requests.

The default policy is fail closed:

- `io.zyvor.seccomp.notify.mode=deny` (default) returns `EPERM`.
- `io.zyvor.seccomp.notify.errno=<1..4095>` changes the denial errno.
- `io.zyvor.seccomp.notify.mode=continue` explicitly opts into
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

`continue` must be treated as a privileged policy choice. The kernel resumes the
original syscall after the supervisor replies and path/fd arguments can change
between inspection and execution; Set 11 deliberately does not claim that
CONTINUE provides a TOCTOU-safe syscall emulation boundary. No syscall argument
values are exported in the audit line.

Two filter shapes fail closed during OCI parsing: `SCMP_ACT_NOTIFY` as
`defaultAction`, and an explicit NOTIFY rule for `sendmsg`. Both are required to
avoid deadlocking the listener bootstrap path before the supervisor owns the
notification fd. Set 11 also does not implement remote policy RPC or
`SECCOMP_IOCTL_NOTIF_ADDFD`; decisions are local and bounded to deny/continue.

Guest requirements for this feature are kernel seccomp user notification
(kernel 5.0+) and a `libseccomp.so.2` exposing the v2.5-era notification API.
Use `scripts/preflight-secure-containers-set11.sh` inside the guest image before
enabling NOTIFY profiles.

## SELinux `linux.mountLabel`

When OCI `linux.mountLabel` is present, Set 11 validates that SELinux is enabled
and `libselinux.so.1` is available, then appends the standard
`context="<label>"` option to each OCI-created mount. Existing SELinux context
options (`context`, `fscontext`, `defcontext`, or `rootcontext`) conflict with a
separate `mountLabel` and are rejected rather than merged ambiguously. Invalid
control characters and mount-option escaping characters fail closed.

The support boundary is intentionally precise: the label is applied to mounts
created by the guest OCI setup path. The Pod rootfs arrives through the existing
virtiofs staging design before OCI mount setup, so Set 11 does not claim to
retroactively relabel that already-mounted virtiofs superblock. Process
`selinuxLabel` remains Set 10 behavior.

## Security observability

The lifecycle protocol adds `SecurityStats`, returning VM-local cumulative
counters for:

- seccomp notifications received;
- notifications denied;
- notifications continued;
- broker errors;
- successfully created OCI mounts carrying `mountLabel`;
- agent-side LSM preflight failures.

The shim logs a snapshot when an init container/task is deleted. The
`lsm_apply_failures` counter is intentionally described as an agent/preflight
counter: failures that occur only in a forked child after copy-on-write cannot
be reliably reflected in the parent's in-memory counter. Container creation
still fails closed in those cases.

## Validation gates

Host-independent validation in the release bundle covers protocol round-trips,
NOTIFY policy parsing, bootstrap-deadlock rejection, mount-label formatting,
shell/TOML/YAML parsing, Rust lexical checks, seccomp notification C ABI sizes,
patch replay, byte comparison, manifest verification, and ZIP integrity.

The real-node gate must still validate:

1. A guest with a NOTIFY profile receives the event and returns the configured
   denial errno without hanging.
2. Explicit `continue` resumes the syscall and increments the continued counter.
3. Killing the notified process/container does not leave the broker blocked or
   leak listener fds.
4. A valid SELinux mount label is visible on a supported OCI-created tmpfs or
   bind mount in an enforcing guest.
5. Invalid/unloaded LSM state fails container creation.
6. Set 10 seccomp argument filters and device-cgroup BPF still pass unchanged.
7. Existing Set 8/9 raw-block/VFIO and Set 6 namespace/Sentinel behavior remain
   intact after rebase onto current `main`.

This packaging environment does not have Rust, KVM, containerd, Kubernetes,
libseccomp development headers, or an SELinux-enabled guest, so those live
runtime gates are not claimed here.
