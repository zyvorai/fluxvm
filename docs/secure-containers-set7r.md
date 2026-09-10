# FluxVM Secure Containers — Set 7 (Runtime): boot pipelining

Set 7 (Runtime track) starts closing the P1 performance gap
`docs/secure-containers.md` has tracked since Set 1: Secure Containers cold
boots a fresh QEMU VM for every Pod group, with no warm-pool reuse. This
first increment removes one real cost from the critical path rather than
just shrinking it; full warm-pool integration is a larger, separate
follow-up (see "Remaining gates" below).

## What changed

Through Set 6, `stage_rootfs_and_config` ran strictly sequentially:
`sandbox_paths` → `ensure_sandbox` (mints/boots the Pod's QEMU VM, cold-boot
cost included, `POST /v1/vms` then poll until `Running`) → *then* the
host-side rootfs mount + `cp -a` copy into the virtiofs staging directory.
But the copy has no data dependency on the VM at all — it only needs a
deterministic staging path
(`share_dir()`/`containers/<safe_name(id)>`, computable purely from the
shim's own config/namespace/group, no VM involved), and the guest doesn't
read that path via virtiofs until the container-agent actually starts the
container, well after both steps are long done. `stage_rootfs_and_config`
now runs `ensure_sandbox` and the rootfs mount+copy concurrently via
`tokio::try_join!`, computing `host_ctr`/`guest_ctr` upfront via a new
`share_dir()` helper instead of waiting on `ensure_sandbox`'s return value
(`sandbox_paths`, which does wait on it, is unchanged and still used by the
`Exec` path, where the VM is already running by definition).

This is a pure reordering — no new locking, no change to `ensure_sandbox`'s
own per-group mutex (it still serializes concurrent containers in the same
Pod correctly), and no change to what gets copied or where.

## Validation performed

- `cargo build`/`cargo test -p fluxvm-containerd-shim` on a real Linux host
  — all 5 existing unit tests pass unchanged.
- **Not yet run**: a live `ctr run` timing comparison (before/after this
  change) against a real containerd + FluxVM stack — `scripts/bench-secure-
  containers.sh` is added for this but wasn't run against the already-live
  FluxVM host used for other Set 6/7 validation, since that requires
  installing the rebuilt shim binary. The actual latency win from this
  change scales with how large a container's rootfs copy is relative to VM
  boot time — for a `busybox`-sized image it's a smaller fraction of total
  latency than for realistic multi-hundred-MB application images, where the
  copy can plausibly rival or exceed cold-boot time.

## Remaining gates

- **Full warm-pool integration** (the larger part of the original P1 gate):
  wire Secure Containers into `fluxvm-scheduler`'s existing
  `create_pool`/`claim_from_pool`/`backfill_pool` primitives so a Pod VM can
  claim a pre-booted, paused VM instead of cold-booting, with a post-claim
  NIC/virtiofs hotplug step (QMP `device_add`, extending the pattern
  `fluxvm-qemu` already uses for CPU/memory/disk hotplug) to attach the
  Pod's actual CNI identity and rootfs/volume shares. This is materially
  larger than the pipelining above — new pool-member template shape (zero
  pre-attached NICs, generic reserved virtiofs slots), new QMP hotplug
  functions, and shim-side claim-then-cold-boot-fallback logic — and is
  intentionally scoped as a separate follow-up rather than bundled into this
  Set.
- Lazy/guest-pull imagery (full guest-pull parity with Kata) remains
  explicitly out of scope for the whole performance track; this Set's
  pipelining is the right-sized first step, not a step toward guest-pull.
- Published before/after latency numbers once a live run is done (see
  "Not yet run" above).
