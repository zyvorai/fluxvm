# FluxVM Set 7 — Memory Pressure + Boot/Snapshot Profiler

Set 7 adds a VM-aware memory and lifecycle profiler on top of Runtime Intelligence. It is deliberately host-local: it does not own distributed routing, Cilium state, migration orchestration, or guest memory inspection.

## What is measured

The eBPF object reuses the existing Runtime Intelligence VM attribution maps and records:

- `handle_mm_fault` latency and major-fault classification when the kernel exposes the probe;
- direct reclaim duration through the paired `vmscan/mm_vmscan_direct_reclaim_begin/end` tracepoints;
- the first KVM entry observed for a VM;
- the first `vhost_poll_wakeup` activity observed for a VM;
- bounded live anomaly events and lost-event accounting.

Userspace reads cgroup-v2 directly for the authoritative memory controller view: `memory.current`, `memory.peak`, `memory.max`, `memory.stat`, `memory.events`, and `memory.pressure`. OOM, `memory.high`, and controller-limit events therefore do not depend on unstable task-structure offsets or kernel-internal OOM call paths.

## Boot and snapshot markers

Lifecycle markers use `CLOCK_MONOTONIC`, matching `bpf_ktime_get_ns()`'s time domain. Supported markers are:

`guest-ready`, `pause-request`, `paused`, `resume-request`, `resumed`, `snapshot-begin`, `snapshot-end`, `restore-begin`, and `restore-end`.

Examples:

```bash
fluxvm-memprof mark <uuid> guest-ready
fluxvm-memprof mark <uuid> snapshot-begin
# take snapshot
fluxvm-memprof mark <uuid> snapshot-end
fluxvm-memprof snapshot <uuid> <vmm-pid> /sys/fs/cgroup/fluxvm/<uuid>
```

The snapshot reports process-start → first-KVM, process-start → first-vhost, process-start → guest-ready, pause/resume control latency, snapshot duration, and restore duration when the corresponding markers exist. Missing markers are reported as unavailable rather than estimated.

## Loader contract

`fluxvm-memprof-loader` requires Set 1/4 Runtime Intelligence to be loaded first. It reuses these pinned maps:

- `tracked_tgids`
- `tracked_tids`
- `tracked_cgroups`

Set-7-owned maps live under `/sys/fs/bpf/fluxvm/intelligence/memprof/maps`. Links live under `.../memprof/links`. Optional probes are soft-failed individually. Page-fault and direct-reclaim timing are paired; a half-attached pair is disabled because it cannot provide correct durations.

## HTTP and metrics

`fluxvm-memprof serve 127.0.0.1:7793` exposes:

- `GET /healthz`
- `GET /v1/memprof/status`
- `GET /v1/memprof/vms`
- `GET /v1/memprof/vms/{uuid}`
- `POST /v1/memprof/vms/{uuid}/mark` with `{"phase":"snapshot-begin"}`
- `GET /metrics`

Prometheus includes cgroup memory usage/limits, OOM and high-limit counters, memory PSI, eBPF fault/reclaim counters and latency histograms, plus boot/snapshot/restore timing gauges.

## Operational boundaries

Set 7 never reads guest RAM. It does not infer an OOM kill from a generic kernel tracepoint; `memory.events` is authoritative. It also never labels an unobserved guest-ready point as boot completion. For a fully instrumented launch flow, mark `guest-ready` from GuestKit or the orchestration layer when the guest has actually reached the desired readiness contract.
