# FluxVM Sentinel Set 11E — VM-aware `sched_ext` scheduler

Set 11E is an **opt-in** VM-vCPU scheduler. It does not replace CFS/fair scheduling for the host. The BPF `sched_ext_ops` object sets `SCX_OPS_SWITCH_PARTIAL`, and FluxVM explicitly changes only recognized VMM vCPU TIDs to `SCHED_EXT` after a guarded plan/apply transaction.

## Why 11E?

The FluxVM repository already uses “Set 11” for the Secure Containers seccomp-notify milestone. `11E` means the next **eBPF/Sentinel** set and avoids confusing the two release lines.

## Inputs

The planner consumes:

- Set-8 topology intelligence when it is loaded: vCPU CPU residency, NUMA locality and IRQ/softirq cost;
- Runtime Intelligence runnable-delay telemetry when available;
- the live vCPU affinity mask and current scheduler policy for every target TID;
- an operator-selected class: `latency`, `balanced`, `throughput`, or `background`.

If Set-8 telemetry is unavailable, the planner does not invent topology. It preserves one CPU from each vCPU's current allowed affinity and emits a warning.

## Scheduling model

The BPF scheduler uses a shared weighted virtual-time DSQ. Idle-CPU direct dispatch uses the kernel default `select_cpu` helper. Contended vCPUs enter the shared DSQ with a per-VM weight and slice. Runtime is charged inversely by configured weight, while queue delay is measured from enqueue to running.

Default classes:

| Class | Weight | Slice | Queue-delay target |
|---|---:|---:|---:|
| latency | 200 | 0.5 ms | 2 ms |
| balanced | 100 | 1 ms | 5 ms |
| throughput | 120 | 2 ms | 10 ms |
| background | 50 | 2 ms | 20 ms |

If Runtime Intelligence reports max runnable delay above 2x the requested target, latency/balanced plans boost weight (bounded to 400) and cap the slice at 0.5 ms. This is still a **plan-time** change, never an uncontrolled feedback loop.

## Safety invariants

1. Only vCPU threads recognized by `topology::discover_vcpus()` are eligible.
2. TID profiles carry the owning VMM TGID. BPF ignores a profile if the TID has been reused by another process.
3. Existing RT/deadline policies are rejected rather than overwritten.
4. The target CPU must remain inside the task's pre-apply affinity.
5. Every plan records original policy, priority and affinity and preflights for drift before changing anything.
6. Apply is transactional across vCPUs. On failure, converted threads are restored best-effort and newly created BPF state is removed.
7. Another active `sched_ext` scheduler is never replaced.
8. The scheduler uses partial switching. Normal host tasks remain with the fair scheduler.
9. The kernel's sched_ext watchdog/error path remains authoritative: if the BPF scheduler fails, tasks fall back to fair scheduling.
10. Kernel upgrades require rebuilding the BPF object against the target kernel's `tools/sched_ext/include` headers. FluxVM refuses to pretend this unstable ABI is portable across arbitrary kernels.

## Build

A target kernel with `CONFIG_SCHED_CLASS_EXT`, BTF, clang, bpftool and libbpf is required. The matching kernel source's sched_ext include directory must be installed or supplied explicitly:

```bash
export FLUXVM_SCX_INCLUDE=/path/to/linux/tools/sched_ext/include
./scripts/build-scx-scheduler.sh dist/bpf dist/bin
```

The script generates `vmlinux.h` from the running kernel BTF and compiles `fluxvm_scx.bpf.o` against the matching sched_ext helper headers.

## Workflow

```bash
fluxvm-scx probe
fluxvm-scx verify

fluxvm-scx plan <vm-uuid> <vmm-pid> \
  --class latency \
  --output scx-plan.json

sudo fluxvm-scx apply scx-plan.json
fluxvm-scx status <vm-uuid>
fluxvm-scx events <vm-uuid> 10 128
fluxvm-scx metrics <vm-uuid>

sudo fluxvm-scx rollback <vm-uuid>
```

Optional explicit overrides are available on `plan`:

```bash
--weight 25..400
--slice-us 100..10000
--latency-target-us N
```

## API

`fluxvm-scx serve 127.0.0.1:7797` is read-only and does **not** activate the scheduler.

- `GET /healthz`
- `GET /v1/scx/status`
- `GET /v1/scx/vms`
- `GET /v1/scx/vms/{uuid}`
- `GET /metrics`

All mutations remain explicit CLI/root operations.

## Recovery

`fluxvm-scx reconcile` removes stale receipts/profile entries for VMMs that exited. `rollback` restores the exact recorded scheduler policy/priority and affinity. When no FluxVM receipts remain, the pinned struct_ops link is removed and the host returns to its normal scheduler state.

## Kernel ABI note

`sched_ext` is upstream from Linux 6.12, but its BPF-facing API intentionally has no stable ABI guarantee. Treat the compiled scheduler object as a target-kernel artifact, not as a universal binary. The CI/static gates validate source structure everywhere; the privileged host test is the authoritative runtime gate for each kernel family you certify.
