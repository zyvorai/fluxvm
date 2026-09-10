# FluxVM Secure Containers — Set 7 (Sentinel): QEMU cgroup hardening

Set 7 (Sentinel track) adds host-side eBPF hardening for the QEMU/VMM process
itself, closing the "what if QEMU is compromised" gap that Set 6S's Pod-edge
network policy does not cover (Set 6S governs *guest* traffic crossing the
TAP device; this Set governs the *QEMU process's own* device access and
outbound IP traffic).

**Scope note:** unlike Set 6S/6R, this applies to every FluxVM VM whose
dataplane mode is not `legacy` — Secure Containers Pod VMs included, but not
exclusively. It's documented under the Secure Containers/Sentinel series
because it was designed as part of that initiative's defense-in-depth story,
not because the mechanism itself is Secure-Containers-specific.

## Decision: no general host-process LSM

The brief this Set was scoped from asked whether an eBPF LSM confining the
whole `qemu-system-x86_64` process is worth building, given the VM boundary
and the existing classic seccomp-bpf VMM allowlist
(`crates/fluxvm-hypervisor/src/seccomp.rs`) already exist. **Decision: no.**
A correct, maintainable LSM policy for a process as I/O-varied as QEMU
(virtiofs, multiple vsock/TAP fds, disk images, optional vhost-user) is high
effort for marginal defense-in-depth value the seccomp filter and VM
isolation already mostly buy. Two narrow, high-leverage cgroup-attached
programs instead, reusing scaffolding that already exists:

## What was built

`crates/fluxvm-cgroup::CgroupManager::create_and_migrate` already puts every
VM's QEMU process into its own `fluxvm.slice/{id}.scope` cgroup for
cpu/memory/pids/io control. Two new eBPF programs attach to that same
cgroup, right after it's created (`VmManager::attach_cgroup`):

- **`bpf/fluxvm_qemu_device.bpf.c`** (`BPF_CGROUP_DEVICE`): allows only
  `/dev/kvm`, `/dev/vhost-vsock`, `/dev/net/tun`, plus `/dev/vfio/<group>`
  for any PCI address in the VM's `vfio_devices`. Major:minor numbers are
  resolved at attach time by the userspace loader
  (`fluxvm-network::qemu_cgroup`) via `stat()`, not compiled in — `/dev/kvm`
  and `/dev/vhost-vsock` are misc chardevs with *dynamically* assigned minor
  numbers, so hardcoding them in the BPF object would be wrong on some
  systems. Fails closed: an unconfigured cgroup (loader crashed between
  attach and map population) denies all device access.
- **`bpf/fluxvm_qemu_egress.bpf.c`** (`BPF_CGROUP_INET_EGRESS`): allows only
  loopback-destined IP traffic. `cgroup_skb` only ever sees IP-family socket
  traffic — QEMU's virtiofsd/vhost-user/QMP control channels are `AF_UNIX`
  and its guest VSOCK channel is `AF_VSOCK`, neither reachable over the
  network in the first place and neither visible to this hook type at all.
  What this actually restricts is a compromised QEMU process originating
  arbitrary *outbound IP connections* directly — a channel completely
  separate from guest network traffic (which crosses the TAP device and is
  governed by `fluxvm_tc.bpf.c`/`fluxvm_pod_policy.bpf.h` instead).

Both attach/detach through `crates/fluxvm-network/src/qemu_cgroup.rs`,
reusing `fluxvm-network::ebpf`'s `bpftool`-based loader primitives
(`run`/`bpftool_map_update`/`require_bpftool`, now `pub(crate)`) and the
per-VM pin-dir convention (`<pin_root>/vms/<id>/qemu/{progs,maps}`), attached
via `bpftool cgroup attach <path> device|egress pinned <prog>`. Detach runs
before cgroup removal in both the normal `stop()` path and the reconcile
teardown path.

Best-effort, like the cgroup creation it's layered on: a VM whose Set 7S
attach fails still launches — it just runs without this extra hardening,
logged as a warning, not a launch failure.

## Validation performed

- **Kernel verifier**: both objects compile and load cleanly on a real Linux
  6.8 host (`bpftool prog load ... type cgroup/dev` /
  `type cgroup_skb/egress`).
- **Real functional enforcement**, not just "loads": attached both programs
  to a throwaway cgroup, moved a real shell process into it, and confirmed:
  - Writing `/dev/null` (in the allowlist) succeeds.
  - Reading `/dev/zero` (not in the allowlist) fails with the OS reporting
    exactly `EPERM` ("Operation not permitted") — the expected device-cgroup
    denial, not a crash or a silent pass-through.
  - Connecting to `127.0.0.1:22` (loopback) succeeds.
  - Connecting to `8.8.8.8:53` (external) hangs until the client's own
    timeout — the SYN is silently dropped by the egress hook, exactly the
    expected `cgroup_skb` verdict-0 behavior (no RST, since the packet never
    left the sending side).
- **Rust**: `cargo test -p fluxvm-network -p fluxvm-scheduler` passes,
  including three new `qemu_cgroup` tests — one of which
  (`major_minor_matches_known_devices`) validated the glibc
  major/minor-decoding logic against this host's *real* `/dev/null`
  (1:3) and `/dev/zero` (1:5), not just synthetic values.
- **Not yet run**: a live VM launch with these programs actually attached via
  the full `VmManager::attach_cgroup` path (as opposed to the standalone
  cgroup test above) — deliberately not performed against the already-running
  FluxVM host used for validation, since that requires installing the
  rebuilt daemon binary and restarting a live service.

## Remaining gates

- Live end-to-end validation: launch a real VM, confirm both programs show
  up attached to its `fluxvm.slice/{id}.scope` cgroup
  (`bpftool cgroup tree`), and that QEMU itself still functions correctly
  under the device allowlist (no unexpected `/dev` access QEMU actually
  needs was missed).
- VFIO passthrough path is implemented but untested on real hardware with an
  actual IOMMU group to resolve.
