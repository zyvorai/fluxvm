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
