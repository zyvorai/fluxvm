# FluxVM VM Flight Recorder (eBPF Set 4)

Set 4 extends Runtime Intelligence without changing the VM-edge policy/map ABI introduced by Set 3. The recorder is VM-local: FluxVM attributes host runtime events to a stable VM key while Zyvor Fabric remains responsible for distributed placement, routing and migration orchestration.

## Signals

### KVM exit profile

`kvm_exit_hist` is keyed by `{vm_key, vcpu_tid, exit_reason}` and stores count, total guest-run nanoseconds and maximum guest-run nanoseconds. The vCPU thread ID is intentionally the portable vCPU identity: it does not depend on an architecture-specific tracepoint vCPU field. On x86_64, userspace decorates common exit numbers such as CPUID, HLT, I/O, MSR and EPT exits; unknown/other architectures remain numeric rather than being mislabeled.

### Latency histograms

`latency_hist` records mutually exclusive log2 buckets for:

- `kvm-run`: KVM entry to KVM exit guest-run interval;
- `runnable`: scheduler wakeup to actual switch-in delay;
- `block-io`: attributed block request start to completion latency.

Buckets start at <=1us and double through bucket 23; bucket 24 is `+Inf`. Each bucket retains count, sum and max so Prometheus histogram output can be constructed without exporting individual events.

### Block I/O attribution

Optional `blk_mq_start_request` and `blk_account_io_done` kprobes correlate request pointers. The recorder does not dereference `struct request`, avoiding kernel request-layout dependencies. Attribution first checks a registered TID/TGID, then a registered VM cgroup id. This captures direct VMM I/O and many async helper paths. Work that has already escaped to an unrelated global block kworker before the start probe is intentionally left unattributed instead of guessed.

### vhost activity

Optional `vhost_work_queue` and `vhost_poll_wakeup` probes count VM-attributed queue/wakeup activity. Registration also discovers `vhost-<vmm-pid>` helper threads where the host exposes them.

### Live ring buffer

`flight_events` is a 4 MiB bounded ring buffer. It emits:

- sampled/slow KVM exits;
- runnable delays >=5ms;
- attributed block completions;
- sampled vhost queue/wakeup events.

A full ring buffer never blocks the VM. Loss is counted in `flight_counts` and surfaced as `fluxvm_intel_flight_events_lost_total` plus a runtime finding.

## CLI

Summary is included in Runtime Intelligence snapshots and available from:

```bash
curl http://127.0.0.1:7790/v1/intelligence/vms/<uuid>/flight
```

Live trace from the normal FluxVM CLI:

```bash
fluxvm trace <uuid> --seconds 5 --limit 128
fluxvm trace <uuid> --seconds 10 --limit 500 --output jsonl
```

The companion binary also supports:

```bash
fluxvm-intelligence trace <uuid> 5 128
```

`fluxvm trace` consumes the live Flight Recorder ring buffer. Use one active live consumer per node/stream when complete event delivery matters; the persistent histogram/counter maps are the canonical summary metrics.

## Prometheus

Set 4 adds:

- `fluxvm_intel_kvm_exit_reason_total{vm,vcpu_tid,reason,reason_name}`
- `fluxvm_intel_latency_seconds_bucket{vm,kind,le}`
- `fluxvm_intel_latency_seconds_count{vm,kind}`
- `fluxvm_intel_latency_seconds_sum{vm,kind}`
- `fluxvm_intel_block_started_total`
- `fluxvm_intel_block_completed_total`
- `fluxvm_intel_block_orphan_completions_total`
- `fluxvm_intel_vhost_queued_total`
- `fluxvm_intel_vhost_wakeups_total`
- `fluxvm_intel_flight_events_lost_total`

## Kernel compatibility

KVM and scheduler tracepoints retain Set 1's soft probing. Block/vhost kprobes are explicitly optional: the loader checks `/proc/kallsyms` when available and soft-skips missing/unsupported optional symbols. Permission or verifier failures are not hidden as compatibility skips.

The production build still requires clang with the BPF target and libbpf development headers. Block and vhost coverage depends on the target kernel exposing the probed symbols.

## Security boundary

The recorder reads host timing/identity only. It does not inspect guest memory, packet payloads, secrets, Cilium private maps or Zyvor Fabric state. `tracked_cgroups` and helper-TID mappings are removed when a VM registration is removed to reduce stale attribution risk after PID/cgroup reuse.
