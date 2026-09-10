# FluxVM Secure Containers — Set 9S (Sentinel): in-guest eBPF LSM MAC

Set 9S adds a third, complementary Secure Containers control layer, in-guest
and per-container:

1. **Namespaces** (Set 6R) — process/mount/IPC/UTS isolation between
   containers in one Pod VM.
2. **Network policy** (Set 6S host, Set 8S guest) — Kubernetes-NetworkPolicy-
   shaped CIDR/L4 allow/deny, enforced at the VM edge and per-container
   cgroup.
3. **eBPF LSM MAC** (this set) — mandatory access control for a handful of
   security-relevant operations that neither namespaces nor classic seccomp
   can express: *which file* a write targets, and whether a page becomes
   simultaneously writable and executable.

## Why LSM, and why this doesn't replace namespaces

BPF-LSM cannot fabricate namespace isolation — it mandatorily restricts what
an *unconfined* process may do, it does not create a boundary between
processes the way `CLONE_NEWPID`/`CLONE_NEWNS` do. It is valuable as a
complement, not a substitute: classic seccomp filters by syscall
name/argument only, so it cannot express "deny writes outside this
container's declared OCI mounts" or "deny a page becoming writable and
executable at the same time" — both of which the guest LSM hooks below add.

## What's enforced

`bpf/fluxvm_guest_lsm.bpf.c` attaches three LSM hooks, globally, once per
guest boot (`fluxvm-container-agent` process lifetime):

- `lsm/bprm_check_security` — optional `execve()` lock (`FLUXVM_LSM_DENY_EXEC`
  in the kernel program; not wired to any automatic policy source yet —
  reserved for a future "freeze this container after startup" control).
- `lsm/file_mprotect` — denies a page transitioning to `PROT_WRITE|PROT_EXEC`
  simultaneously. On by default whenever Set 9S is enabled for a container
  (`FLUXVM_CONTAINER_LSM_DENY_WX=0` to disable).
- `lsm/file_open` — denies regular-file writes (`FMODE_WRITE`) outside a
  bounded per-container allow-list of path prefixes, derived from the
  container's OCI `mounts[].destination` entries. **Only enabled when the
  OCI spec's `root.readonly` is `true`** — otherwise nearly every ordinary
  write inside the container's own image layers would be denied, which is
  not what "restrict writes to declared mounts" is supposed to mean for a
  normal writable-rootfs container. The same hook also supports an exact
  char/block device allow-list (`FLUXVM_LSM_RESTRICT_DEVICES`), present in
  the kernel program but not populated by `fluxvm-container-agent` yet — OCI
  device nodes are already gated by Set 4/7's guest-attached-device checks,
  so this is deliberately dormant until a concrete gap justifies it.

Every hook resolves `bpf_get_current_cgroup_id()` against `fluxvm_lsmpol`
first: a cgroup with no policy entry (any process not in one of this Pod
VM's own per-container cgroups) is always allowed. Set 9S never touches
processes outside FluxVM's own container cgroups.

## Off by default

Set 9S is opt-in, like Set 6R's `CLONE_NEWUSER`:

- `FLUXVM_CONTAINER_LSM=1` — enable. Off (`0`) is the default; a guest kernel
  without `CONFIG_BPF_LSM=y` + `CONFIG_DEBUG_INFO_BTF=y` and `bpf` in the
  active `lsm=` boot parameter list still runs containers normally, just
  without this layer (attach failure is logged, not fatal — the same
  best-effort posture as Set 8S's network policy).
- `FLUXVM_CONTAINER_LSM_ENFORCE=1` — required to actually deny. Without it,
  Set 9S runs in **audit-only** mode: every would-be denial is recorded to
  the `fluxvm_lsmevents` ring buffer instead of returning `-EPERM`. Audit is
  the default specifically because this is new territory for the codebase —
  see the same audit-first posture in `bpf/fluxvm_guard.bpf.c` (the *host*-
  side analogue, Set 5 of the eBPF Sentinel/Runtime-Intelligence stack).
- `FLUXVM_CONTAINER_LSM_DENY_WX=0` — disable the W+X `mprotect()` denial
  specifically (on by default whenever Set 9S itself is enabled).

## Container identity

`fluxvm-container-agent` mints a stable `container_identity: u32` per
container at create time: an FNV-1a hash of the container's own `id` string
with the top bit set (`CONTAINER_IDENTITY_TAG_BIT`), so it can never collide
with the host VM-hash space, Service Fabric's reserved/local identity space,
or Set 6S's Pod-id space — all already-separate identity spaces in this
codebase. Unlike Set 6S's Pod identity, no host-assigned Pod component is
folded in: this VM only ever hosts one Kubernetes Pod's containers, so the
container's own `id` is already unique within it. `container_identity` is
returned in the `Created` lifecycle RPC response so host-side audit can
correlate a `fluxvm_lsmevents` denial (keyed by the in-guest, not
host-visible, cgroup id) back to `(container_id, container_identity)`.

## Testability

`guest_lsm_policy_attaches_and_enforces` in
`crates/fluxvm-container-agent/src/main.rs` exercises the real
attach/configure/enforce/cleanup flow against a throwaway cgroup v2
subtree — not a mock: it moves the test's own process into the cgroup and
proves both the write-prefix allow-list and the W+X `mprotect()` denial with
real syscalls. It skips itself (rather than failing) on a host that isn't
root, has no cgroup v2, or doesn't have `bpf` active in
`/sys/kernel/security/lsm`:

```bash
sudo cargo test -p fluxvm-container-agent guest_lsm_policy_attaches_and_enforces -- --nocapture
```

This has been run successfully against a real Linux 6.8 host with BPF LSM
active: the loaded object attached 3 live LSM links, a write outside the
declared mount prefix was denied, a write inside it stayed allowed, and a
W+X `mprotect()` was denied with `EPERM`. It has also intermittently failed
purely at the `Ebpf::load()` step on the same host with "error parsing ELF
data" despite the embedded object bytes being independently confirmed
correct — traced to a version/feature-unification interaction between `aya`
0.13.1 (which unconditionally requires `object`'s `write` feature family)
and this workspace's pinned `object 0.36.7`, not a logic bug in this Set's
Rust or BPF C code (see the test's own doc comment for the full trace). A
newer `aya`/`aya-obj`/`object` pin is the likely fix and is tracked as a
follow-up rather than blocking this Set.

## Guest-image prerequisite

The guest kernel must ship `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, and
boot with `bpf` in its `lsm=` parameter list, with `bpffs` mounted — tracked
as a small gating task outside these crates, the same prerequisite the host
VMM Guard (eBPF Sentinel Set 5) already documents for the host kernel.
