# Density roadmap: fork and restore efficiency

Status of Phase 3 work on the in-tree KVM engine.

## Done

- `MAP_PRIVATE` file-backed restore of `snap.mem`
  (`GuestMemory::remap_private_file`, called from `kvm_snap::load_memory_into`).
  The existing anonymous RAM mapping is replaced in place with `MAP_FIXED`, so
  the host address and the KVM memslot registration do not change. Children
  forked from one snapshot share every clean page through the page cache and
  copy only what they write. Falls back to the eager `read_exact` copy when
  `FLUXVM_KVM_LOCK_MEM=1`, `FLUXVM_HUGEPAGES=1`, `FLUXVM_KVM_EAGER_RESTORE=1`,
  on a size mismatch, or on any mmap error. Constraint: do not truncate or
  rewrite `snap.mem` in place while a restored guest runs (SIGBUS); unlinking is
  fine.
- Child identity: `AgentRequest::ResetIdentity` (hostname, machine-id, entropy
  via `RNDADDENTROPY`, neighbour-cache flush), sent by `fork_child` after resume.
  Failure is logged at error level and audited, not fatal.
- `scripts/bench-fork.sh`: p50/p95 per-child ready time, PSS/private/RSS per
  child, disk bytes per child. Use `FLUXVM_KVM_EAGER_RESTORE=1` on the daemon for
  the "before" numbers.

## TODO: userfaultfd demand-paged restore (`FLUXVM_KVM_UFFD=1`)

Not implemented. Only worth doing if `MAP_PRIVATE` does not meet the target
(it already avoids the eager copy; uffd mainly helps when the snapshot lives on
remote or non-page-cacheable storage). Design:

1. Allocate guest RAM anonymous as today, `userfaultfd(O_CLOEXEC|O_NONBLOCK)`,
   `UFFDIO_API`, `UFFDIO_REGISTER` the whole range in `MISSING` mode.
2. A handler thread polls the uffd and answers each fault with `UFFDIO_COPY`
   from `snap.mem` (pread into a page-aligned buffer), optionally prefetching a
   window around the fault and a background fill for the remainder.
3. The handler must start before any vCPU or device thread runs and outlive
   the VM; KVM's own EPT-violation faults on unpopulated pages go through the
   same path, so no KVM changes are needed.
4. Needs unprivileged-uffd sysctl (`vm.unprivileged_userfaultfd`) or
   `CAP_SYS_PTRACE`; fall back to the `MAP_PRIVATE` path when unavailable.

## TODO: KVM dirty-log incremental snapshots

Not implemented (needs a Linux/KVM host to validate; the pause interplay with
`snapshot.rs` is the risky part). Design:

1. Full snapshot as today, then re-register RAM with `KVM_MEM_LOG_DIRTY_PAGES`
   (`KVM_SET_USER_MEMORY_REGION` with the flag on the existing slot) and call
   `KVM_GET_DIRTY_LOG` once to clear the bitmap right after the full dump, while
   the VM is still paused.
2. Incremental snapshot: pause (existing epoch/quiesce handshake), call
   `KVM_GET_DIRTY_LOG` (one bit per 4 KiB page, `mem_len/4096/8` bytes), write
   only those pages. Devices that write RAM outside vCPUs (virtio queues, tap and
   blk workers) write through the same host mapping, so they are covered by
   the dirty log only when KVM sees the write: host-side writes via
   `host_ptr()` are NOT tracked. Every virtio completion path must also set the
   bit in a software bitmap, or the delta must conservatively include all
   guest pages touched by queue service since the last snapshot.
3. Delta file layout: header (magic `FLUXKVMD`, parent snapshot id, page count),
   then `(gfn: u64, 4096 bytes)` records, or a bitmap plus packed pages.
4. `FLUXKVM1` vmstate version bump (current is 5, so 6) adding a
   `parent` reference and `delta` flag. `load_cpu` already branches on
   `version`, so older files keep loading; a v6 reader applies the base `snap.mem`
   (privately mapped) and then patches the delta pages over it.
5. Costs of the log (write-protection faults on first write per page) mean it
   should only be enabled on VMs that opt in to incremental snapshots.

## TODO: warm pool backfilled by fork

Not implemented. `backfill_pool` boots members and waits for the agent. A
fork-backed backfill would hold one parked "template" VM per `PoolSpec`, call
`fork_vm` for each missing member and rely on `ResetIdentity` for uniqueness.
Open issues: forked children keep the parent's MAC and IP, so the pool needs
per-VM netns (the same restriction `check_forkable` enforces), and the template
must be quiesced after the agent is ready so children do not inherit in-flight
requests.

## Update 2026-10-08: what the latest batch changed

Honest status. Everything below is **implemented and type-checked, with unit
tests passing. Nothing here has been run end to end on real VMs.** No density,
latency or throughput number has been measured, and none is claimed.

### Shipped in code (unverified on hardware)

- Fork and restore, described from the code in
  [fork-and-restore.md](fork-and-restore.md): journaled all-or-nothing fork,
  `MAP_PRIVATE` restore with an eager fallback, `ResetIdentity` for each child,
  `?ready=exec` first-command timing on create, fork and pool claim.
- Crash-safe lifecycle ([crash-recovery.md](crash-recovery.md)): fsynced writes,
  an operation journal for create/delete/snapshot/fork/restore, orphan sweep with
  grace periods, `Idempotency-Key`. Fork's cleanup now rides on it.
- Memory density, in `fluxvm-scheduler/src/density.rs`:
  - balloon control for the KVM engine: `GET|POST /v1/vms/{id}/balloon`;
  - per-VM memory report (PSS from `/proc/<pid>/smaps_rollup`, split private and
    shared): `GET /v1/vms/{id}/memory`;
  - idle reclaim: `[sandbox] idle_balloon_secs` (0 = off) and
    `idle_balloon_percent` (default 50) inflate an idle Running KVM sandbox's
    balloon and deflate it on activity;
  - pressure-aware admission, all off by default: `[policy]`
    `min_host_mem_available_mib`, `max_host_mem_psi_some_avg10`,
    `max_host_mem_psi_full_avg10`, `pressure_defer_secs`.
- Bench scripts: `bench-fork.sh` (per-child ready time, PSS, disk),
  `bench-first-command.sh`, `bench-density-count.sh` (consumes host memory; needs
  `FLUXVM_BENCH_CONFIRM=1`), and `bench-kvm-vhost.sh` for the network datapath
  ([native-io-performance.md](native-io-performance.md)).
- Speculative execution (changesets) uses fork for flux-vm sandboxes when
  `check_forkable` passes; see NEXT-FEATURES for the API.

### Not verified on hardware

- Whether `MAP_PRIVATE` restore actually shares pages between children, and how
  many. The bench scripts are the way to find out; run them once with
  `FLUXVM_KVM_EAGER_RESTORE=1` and once without.
- That `ResetIdentity` succeeds against the real golden guest agent image, and
  what happens to a child's open connections (they are not reset).
- The idle balloon's effect on host memory and on guest latency after deflate.
- Any fork-time or first-command figure. The previous density archive
  ([benchmarks/evidence/density-20260918-80.79.5.173.txt](benchmarks/evidence/density-20260918-80.79.5.173.txt))
  predates all of this and must not be quoted for it.

### Still to do

The three TODO sections above are unchanged and still unimplemented:
userfaultfd demand paging, dirty-log incremental snapshots, and a warm pool
backfilled by fork. They remain designs. `MAP_PRIVATE` is the only lazy restore
that exists, and the dirty-log design is the riskiest because host-side device
writes through `host_ptr()` are not tracked by KVM.
