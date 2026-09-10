// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM Runtime Intelligence v2 — VM Flight Recorder.
//
// VM-aware KVM, scheduler, block-I/O and vhost telemetry. Userspace registers
// VMM TGIDs/TIDs (and, when available, the VM cgroup id) to a stable FluxVM
// vm_key. No guest memory is inspected and no Cilium/private CNI map is read
// or mutated. Optional kprobes are soft-attached by the userspace loader.

#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define FLUXVM_EVENT_KVM_EXIT        1
#define FLUXVM_EVENT_SCHED_DELAY     2
#define FLUXVM_EVENT_BLOCK_COMPLETE  3
#define FLUXVM_EVENT_VHOST_QUEUE     4
#define FLUXVM_EVENT_VHOST_WAKEUP    5

#define FLUXVM_LAT_KVM_RUN     1
#define FLUXVM_LAT_RUNNABLE    2
#define FLUXVM_LAT_BLOCK_IO    3
#define FLUXVM_LAT_BUCKETS     25

#define FLUXVM_COUNT_BLOCK_STARTED       1
#define FLUXVM_COUNT_BLOCK_COMPLETED     2
#define FLUXVM_COUNT_BLOCK_ORPHAN_DONE   3
#define FLUXVM_COUNT_VHOST_QUEUED        4
#define FLUXVM_COUNT_VHOST_WAKEUPS       5
#define FLUXVM_COUNT_RINGBUF_LOST        6

#define FLUXVM_SLOW_RUNNABLE_NS 5000000ULL
#define FLUXVM_SLOW_KVM_RUN_NS  1000000ULL

struct vm_stats {
    __u64 kvm_exits;
    __u64 guest_run_ns;
    __u64 sched_wakeups;
    __u64 runnable_delay_ns;
    __u64 runnable_delay_max_ns;
    __u64 migrations;
    __u64 last_event_ns;
    __u64 reserved;
};
_Static_assert(sizeof(struct vm_stats) == 64, "vm_stats ABI");

struct sched_wakeup_ctx {
    __u64 common;
    char comm[TASK_COMM_LEN];
    __s32 pid;
    __s32 prio;
    __s32 target_cpu;
};

struct sched_switch_ctx {
    __u64 common;
    char prev_comm[TASK_COMM_LEN];
    __s32 prev_pid;
    __s32 prev_prio;
    __s64 prev_state;
    char next_comm[TASK_COMM_LEN];
    __s32 next_pid;
    __s32 next_prio;
};

struct sched_migrate_ctx {
    __u64 common;
    char comm[TASK_COMM_LEN];
    __s32 pid;
    __s32 prio;
    __s32 orig_cpu;
    __s32 dest_cpu;
};

/* The tracepoint common header is 8 bytes. exit_reason is the first KVM
 * event field on supported x86 KVM tracepoint ABI. TID remains the portable
 * per-vCPU identity; userspace may decorate it with the thread name. */
struct kvm_exit_ctx {
    __u64 common;
    __u32 exit_reason;
    __u32 pad0;
};

struct kvm_exit_key {
    __u64 vm_key;
    __u32 vcpu_tid;
    __u32 reason;
};

struct flight_value {
    __u64 count;
    __u64 total_ns;
    __u64 max_ns;
};

struct latency_key {
    __u64 vm_key;
    __u32 kind;
    __u32 bucket;
};

struct counter_key {
    __u64 vm_key;
    __u32 kind;
    __u32 pad;
};

struct block_request_state {
    __u64 vm_key;
    __u64 start_ns;
    __u32 submit_tid;
    __u32 pad;
};

struct flight_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u64 duration_ns;
    __u64 arg0;
    __u64 arg1;
    __u32 tid;
    __u32 cpu;
    __u32 event_type;
    __u32 reserved;
};
_Static_assert(sizeof(struct flight_event) == 56, "flight_event ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} tracked_tgids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} tracked_tids SEC(".maps");

/* cgroup inode id -> vm_key. This catches io_uring helpers and other worker
 * contexts that remain charged to the VM cgroup even when the userspace TID
 * itself was not known when the VM was registered. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u64);
} tracked_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} wakeup_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} kvm_entry_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct vm_stats);
} vm_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct kvm_exit_key);
    __type(value, struct flight_value);
} kvm_exit_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct latency_key);
    __type(value, struct flight_value);
} latency_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct block_request_state);
} block_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct counter_key);
    __type(value, __u64);
} flight_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} flight_events SEC(".maps");

static __always_inline struct vm_stats *stats_for(__u64 vm_key)
{
    struct vm_stats zero = {};
    struct vm_stats *stats = bpf_map_lookup_elem(&vm_stats, &vm_key);
    if (!stats) {
        bpf_map_update_elem(&vm_stats, &vm_key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&vm_stats, &vm_key);
    }
    return stats;
}

static __always_inline void touch(struct vm_stats *stats, __u64 now)
{
    if (stats)
        stats->last_event_ns = now;
}

static __always_inline void max_u64(__u64 *slot, __u64 value)
{
    __u64 old = *slot;
#pragma unroll
    for (int i = 0; i < 8 && value > old; i++) {
        __u64 seen = __sync_val_compare_and_swap(slot, old, value);
        if (seen == old)
            break;
        old = seen;
    }
}

static __always_inline __u64 *current_vm_key(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __u64 *key = bpf_map_lookup_elem(&tracked_tids, &tid);
    if (key)
        return key;
    key = bpf_map_lookup_elem(&tracked_tgids, &tgid);
    if (key)
        return key;
    __u64 cgroup = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&tracked_cgroups, &cgroup);
}

static __always_inline __u32 latency_bucket(__u64 ns)
{
    __u64 limit = 1000ULL; /* <= 1 us */
#pragma unroll
    for (int i = 0; i < FLUXVM_LAT_BUCKETS - 1; i++) {
        if (ns <= limit)
            return i;
        limit <<= 1;
    }
    return FLUXVM_LAT_BUCKETS - 1;
}

static __always_inline void flight_value_add(struct flight_value *v, __u64 ns)
{
    if (!v)
        return;
    __sync_fetch_and_add(&v->count, 1);
    __sync_fetch_and_add(&v->total_ns, ns);
    max_u64(&v->max_ns, ns);
}

static __always_inline void latency_add(__u64 vm_key, __u32 kind, __u64 ns)
{
    struct latency_key key = {
        .vm_key = vm_key,
        .kind = kind,
        .bucket = latency_bucket(ns),
    };
    struct flight_value *v = bpf_map_lookup_elem(&latency_hist, &key);
    if (!v) {
        struct flight_value zero = {};
        bpf_map_update_elem(&latency_hist, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&latency_hist, &key);
    }
    flight_value_add(v, ns);
}

static __always_inline void count_kind(__u64 vm_key, __u32 kind)
{
    struct counter_key key = {.vm_key = vm_key, .kind = kind};
    __u64 *v = bpf_map_lookup_elem(&flight_counts, &key);
    if (v) {
        __sync_fetch_and_add(v, 1);
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(&flight_counts, &key, &one, BPF_NOEXIST);
}

static __always_inline void emit_event(
    __u64 vm_key,
    __u32 event_type,
    __u64 duration_ns,
    __u64 arg0,
    __u64 arg1)
{
    struct flight_event *event = bpf_ringbuf_reserve(&flight_events, sizeof(*event), 0);
    if (!event) {
        count_kind(vm_key, FLUXVM_COUNT_RINGBUF_LOST);
        return;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->vm_key = vm_key;
    event->duration_ns = duration_ns;
    event->arg0 = arg0;
    event->arg1 = arg1;
    event->tid = (__u32)pid_tgid;
    event->cpu = bpf_get_smp_processor_id();
    event->event_type = event_type;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/kvm/kvm_entry")
int fluxvm_intel_kvm_entry(void *ctx)
{
    (void)ctx;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 *vm_key = bpf_map_lookup_elem(&tracked_tgids, &tgid);
    if (!vm_key)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&kvm_entry_ts, &tid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/kvm/kvm_exit")
int fluxvm_intel_kvm_exit(struct kvm_exit_ctx *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 *vm_key = bpf_map_lookup_elem(&tracked_tgids, &tgid);
    if (!vm_key)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 duration = 0;
    struct vm_stats *stats = stats_for(*vm_key);
    if (!stats)
        return 0;
    __sync_fetch_and_add(&stats->kvm_exits, 1);
    __u64 *start = bpf_map_lookup_elem(&kvm_entry_ts, &tid);
    if (start && now >= *start) {
        duration = now - *start;
        __sync_fetch_and_add(&stats->guest_run_ns, duration);
        latency_add(*vm_key, FLUXVM_LAT_KVM_RUN, duration);
    }
    bpf_map_delete_elem(&kvm_entry_ts, &tid);

    __u32 exit_reason = 0xffffffffu;
#if defined(__TARGET_ARCH_x86)
    exit_reason = ctx->exit_reason;
#else
    (void)ctx;
#endif
    struct kvm_exit_key key = {
        .vm_key = *vm_key,
        .vcpu_tid = tid,
        .reason = exit_reason,
    };
    struct flight_value *v = bpf_map_lookup_elem(&kvm_exit_hist, &key);
    if (!v) {
        struct flight_value zero = {};
        bpf_map_update_elem(&kvm_exit_hist, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&kvm_exit_hist, &key);
    }
    flight_value_add(v, duration);
    if (duration >= FLUXVM_SLOW_KVM_RUN_NS || (bpf_get_prandom_u32() & 1023u) == 0)
        emit_event(*vm_key, FLUXVM_EVENT_KVM_EXIT, duration, exit_reason, tid);
    touch(stats, now);
    return 0;
}

static __always_inline int handle_sched_wakeup(struct sched_wakeup_ctx *ctx)
{
    __u32 tid = (__u32)ctx->pid;
    __u64 *vm_key = bpf_map_lookup_elem(&tracked_tids, &tid);
    if (!vm_key)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &tid, &now, BPF_ANY);
    struct vm_stats *stats = stats_for(*vm_key);
    if (stats) {
        __sync_fetch_and_add(&stats->sched_wakeups, 1);
        touch(stats, now);
    }
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int fluxvm_intel_sched_wakeup(struct sched_wakeup_ctx *ctx)
{
    return handle_sched_wakeup(ctx);
}

SEC("tracepoint/sched/sched_wakeup_new")
int fluxvm_intel_sched_wakeup_new(struct sched_wakeup_ctx *ctx)
{
    return handle_sched_wakeup(ctx);
}

SEC("tracepoint/sched/sched_switch")
int fluxvm_intel_sched_switch(struct sched_switch_ctx *ctx)
{
    __u32 tid = (__u32)ctx->next_pid;
    __u64 *vm_key = bpf_map_lookup_elem(&tracked_tids, &tid);
    if (!vm_key)
        return 0;
    __u64 *start = bpf_map_lookup_elem(&wakeup_ts, &tid);
    if (!start)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    if (now >= *start) {
        __u64 delay = now - *start;
        struct vm_stats *stats = stats_for(*vm_key);
        if (stats) {
            __sync_fetch_and_add(&stats->runnable_delay_ns, delay);
            max_u64(&stats->runnable_delay_max_ns, delay);
            latency_add(*vm_key, FLUXVM_LAT_RUNNABLE, delay);
            if (delay >= FLUXVM_SLOW_RUNNABLE_NS)
                emit_event(*vm_key, FLUXVM_EVENT_SCHED_DELAY, delay, tid, 0);
            touch(stats, now);
        }
    }
    bpf_map_delete_elem(&wakeup_ts, &tid);
    return 0;
}

SEC("tracepoint/sched/sched_migrate_task")
int fluxvm_intel_sched_migrate(struct sched_migrate_ctx *ctx)
{
    __u32 tid = (__u32)ctx->pid;
    __u64 *vm_key = bpf_map_lookup_elem(&tracked_tids, &tid);
    if (!vm_key)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    struct vm_stats *stats = stats_for(*vm_key);
    if (stats) {
        __sync_fetch_and_add(&stats->migrations, 1);
        touch(stats, now);
    }
    return 0;
}

/* Optional block probes. We intentionally never dereference struct request;
 * request-pointer identity is sufficient to correlate start/completion and
 * keeps this object portable across request-layout changes. */
struct request;

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(fluxvm_intel_blk_start, struct request *rq)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key || !rq)
        return 0;
    struct block_request_state state = {
        .vm_key = *vm_key,
        .start_ns = bpf_ktime_get_ns(),
        .submit_tid = (__u32)bpf_get_current_pid_tgid(),
    };
    __u64 key = (__u64)rq;
    bpf_map_update_elem(&block_requests, &key, &state, BPF_ANY);
    count_kind(*vm_key, FLUXVM_COUNT_BLOCK_STARTED);
    return 0;
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(fluxvm_intel_blk_done, struct request *rq)
{
    (void)ctx;
    if (!rq)
        return 0;
    __u64 key = (__u64)rq;
    struct block_request_state *state = bpf_map_lookup_elem(&block_requests, &key);
    if (!state) {
        __u64 *vm_key = current_vm_key();
        if (vm_key)
            count_kind(*vm_key, FLUXVM_COUNT_BLOCK_ORPHAN_DONE);
        return 0;
    }
    __u64 now = bpf_ktime_get_ns();
    __u64 vm_key = state->vm_key;
    __u64 duration = now >= state->start_ns ? now - state->start_ns : 0;
    __u32 submit_tid = state->submit_tid;
    latency_add(vm_key, FLUXVM_LAT_BLOCK_IO, duration);
    count_kind(vm_key, FLUXVM_COUNT_BLOCK_COMPLETED);
    emit_event(vm_key, FLUXVM_EVENT_BLOCK_COMPLETE, duration, key, submit_tid);
    bpf_map_delete_elem(&block_requests, &key);
    return 0;
}

/* Optional vhost probes. Attribution succeeds when the caller/worker TID was
 * registered by userspace or remains charged to the registered VM cgroup. */
SEC("kprobe/vhost_work_queue")
int fluxvm_intel_vhost_queue(struct pt_regs *ctx)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key)
        return 0;
    count_kind(*vm_key, FLUXVM_COUNT_VHOST_QUEUED);
    if ((bpf_get_prandom_u32() & 255u) == 0)
        emit_event(*vm_key, FLUXVM_EVENT_VHOST_QUEUE, 0, 0, 0);
    return 0;
}

SEC("kprobe/vhost_poll_wakeup")
int fluxvm_intel_vhost_wakeup(struct pt_regs *ctx)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key)
        return 0;
    count_kind(*vm_key, FLUXVM_COUNT_VHOST_WAKEUPS);
    if ((bpf_get_prandom_u32() & 255u) == 0)
        emit_event(*vm_key, FLUXVM_EVENT_VHOST_WAKEUP, 0, 0, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
