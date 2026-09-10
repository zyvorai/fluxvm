// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM Runtime Intelligence v1
// VM-aware KVM + scheduler telemetry. Userspace registers the VMM TGID and
// all vCPU/helper TIDs into tracked_tgids/tracked_tids. The programs never
// inspect guest memory and never mutate Cilium/private CNI state.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16

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
int fluxvm_intel_kvm_exit(void *ctx)
{
    (void)ctx;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 *vm_key = bpf_map_lookup_elem(&tracked_tgids, &tgid);
    if (!vm_key)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    struct vm_stats *stats = stats_for(*vm_key);
    if (!stats)
        return 0;
    __sync_fetch_and_add(&stats->kvm_exits, 1);
    __u64 *start = bpf_map_lookup_elem(&kvm_entry_ts, &tid);
    if (start && now >= *start)
        __sync_fetch_and_add(&stats->guest_run_ns, now - *start);
    bpf_map_delete_elem(&kvm_entry_ts, &tid);
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

char LICENSE[] SEC("license") = "GPL";
