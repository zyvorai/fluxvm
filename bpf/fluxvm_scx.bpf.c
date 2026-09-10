// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// FluxVM Sentinel Set 11E — VM-aware sched_ext scheduler.
//
// This object deliberately uses SCX_OPS_SWITCH_PARTIAL: only tasks which
// userspace explicitly places in SCHED_EXT are handled here. FluxVM's
// userspace controller limits that to recognized VMM vCPU threads.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <scx/common.bpf.h>

char LICENSE[] SEC("license") = "GPL";

#define FLUXVM_SCX_DSQ 0x46584d31ULL /* "FXM1" */
#define FLUXVM_SCX_MIN_SLICE_NS 100000ULL
#define FLUXVM_SCX_MAX_SLICE_NS 10000000ULL
#define FLUXVM_SCX_DEFAULT_SLICE_NS 1000000ULL
#define FLUXVM_SCX_DEFAULT_WEIGHT 100U
#define FLUXVM_SCX_MIN_WEIGHT 25U
#define FLUXVM_SCX_MAX_WEIGHT 400U
#define FLUXVM_SCX_EVENT_GAP_NS 100000000ULL

struct fluxvm_scx_task_profile {
    __u64 vm_key;
    __u32 tgid;
    __u32 weight;
    __u64 slice_ns;
    __u64 latency_target_ns;
    __u32 flags;
    __u32 reserved;
};

struct fluxvm_scx_vm_stats {
    __u64 enqueues;
    __u64 direct_dispatches;
    __u64 shared_dispatches;
    __u64 dispatch_calls;
    __u64 running_calls;
    __u64 stopping_calls;
    __u64 runtime_ns;
    __u64 queue_delay_ns;
    __u64 queue_delay_max_ns;
    __u64 latency_violations;
    __u64 fallback_enqueues;
};

struct fluxvm_scx_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u32 tid;
    __u32 cpu;
    __u64 queue_delay_ns;
    __u64 latency_target_ns;
    __u32 weight;
    __u32 event_type;
};

enum fluxvm_scx_event_type {
    FLUXVM_SCX_EVENT_LATENCY = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct fluxvm_scx_task_profile);
} scx_task_profiles SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct fluxvm_scx_vm_stats);
} scx_vm_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} scx_enqueue_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} scx_last_event_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} scx_events SEC(".maps");

static volatile __u64 vtime_now;
static volatile __u64 exit_kind;

static __always_inline struct fluxvm_scx_task_profile *profile_for(struct task_struct *p)
{
    __u32 tid = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);
    struct fluxvm_scx_task_profile *profile = bpf_map_lookup_elem(&scx_task_profiles, &tid);

    /* TID reuse is fail-open to default SCX behavior, never to stale VM policy. */
    if (!profile || profile->tgid != tgid)
        return NULL;
    return profile;
}

static __always_inline struct fluxvm_scx_vm_stats *stats_for(__u64 vm_key)
{
    /* Userspace pre-creates one entry per managed VM before SCHED_EXT switch. */
    return bpf_map_lookup_elem(&scx_vm_stats, &vm_key);
}

static __always_inline __u64 bounded_slice(const struct fluxvm_scx_task_profile *profile)
{
    __u64 slice = profile ? profile->slice_ns : FLUXVM_SCX_DEFAULT_SLICE_NS;

    if (slice < FLUXVM_SCX_MIN_SLICE_NS)
        slice = FLUXVM_SCX_MIN_SLICE_NS;
    if (slice > FLUXVM_SCX_MAX_SLICE_NS)
        slice = FLUXVM_SCX_MAX_SLICE_NS;
    return slice;
}

static __always_inline __u32 bounded_weight(const struct fluxvm_scx_task_profile *profile)
{
    __u32 weight = profile ? profile->weight : FLUXVM_SCX_DEFAULT_WEIGHT;

    if (weight < FLUXVM_SCX_MIN_WEIGHT)
        weight = FLUXVM_SCX_MIN_WEIGHT;
    if (weight > FLUXVM_SCX_MAX_WEIGHT)
        weight = FLUXVM_SCX_MAX_WEIGHT;
    return weight;
}

static __always_inline void record_enqueue(struct task_struct *p,
                                            struct fluxvm_scx_task_profile *profile,
                                            bool direct)
{
    __u32 tid = BPF_CORE_READ(p, pid);
    __u64 now = bpf_ktime_get_ns();

    bpf_map_update_elem(&scx_enqueue_ts, &tid, &now, BPF_ANY);
    if (profile) {
        struct fluxvm_scx_vm_stats *stats = stats_for(profile->vm_key);
        if (stats) {
            __sync_fetch_and_add(&stats->enqueues, 1);
            if (direct)
                __sync_fetch_and_add(&stats->direct_dispatches, 1);
            else
                __sync_fetch_and_add(&stats->shared_dispatches, 1);
        }
    }
}

static __always_inline void maybe_latency_event(struct task_struct *p,
                                                 struct fluxvm_scx_task_profile *profile,
                                                 __u64 delay_ns)
{
    __u32 tid;
    __u64 now, *last;
    struct fluxvm_scx_event *event;

    if (!profile || !profile->latency_target_ns || delay_ns <= profile->latency_target_ns)
        return;

    tid = BPF_CORE_READ(p, pid);
    now = bpf_ktime_get_ns();
    last = bpf_map_lookup_elem(&scx_last_event_ns, &tid);
    if (last && now - *last < FLUXVM_SCX_EVENT_GAP_NS)
        return;
    bpf_map_update_elem(&scx_last_event_ns, &tid, &now, BPF_ANY);

    event = bpf_ringbuf_reserve(&scx_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = now;
    event->vm_key = profile->vm_key;
    event->tid = tid;
    event->cpu = bpf_get_smp_processor_id();
    event->queue_delay_ns = delay_ns;
    event->latency_target_ns = profile->latency_target_ns;
    event->weight = bounded_weight(profile);
    event->event_type = FLUXVM_SCX_EVENT_LATENCY;
    bpf_ringbuf_submit(event, 0);
}

s32 BPF_STRUCT_OPS(fluxvm_scx_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
{
    bool direct = false;
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &direct);
    struct fluxvm_scx_task_profile *profile = profile_for(p);

    if (direct) {
        record_enqueue(p, profile, true);
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, bounded_slice(profile), 0);
    }
    return cpu;
}

void BPF_STRUCT_OPS(fluxvm_scx_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct fluxvm_scx_task_profile *profile = profile_for(p);
    __u64 slice = bounded_slice(profile);

    record_enqueue(p, profile, false);
    if (profile) {
        __u64 vtime = p->scx.dsq_vtime;
        __u64 floor = vtime_now > slice ? vtime_now - slice : 0;

        if (vtime < floor)
            vtime = floor;
        scx_bpf_dsq_insert_vtime(p, FLUXVM_SCX_DSQ, slice, vtime, enq_flags);
    } else {
        scx_bpf_dsq_insert(p, FLUXVM_SCX_DSQ, slice, enq_flags);
    }
}

void BPF_STRUCT_OPS(fluxvm_scx_dispatch, s32 cpu, struct task_struct *prev)
{
    (void)cpu;
    (void)prev;
    scx_bpf_dsq_move_to_local(FLUXVM_SCX_DSQ, 0);
}

void BPF_STRUCT_OPS(fluxvm_scx_running, struct task_struct *p)
{
    struct fluxvm_scx_task_profile *profile = profile_for(p);
    __u64 now = bpf_ktime_get_ns();
    __u32 tid = BPF_CORE_READ(p, pid);
    __u64 *enqueued = bpf_map_lookup_elem(&scx_enqueue_ts, &tid);

    if (profile) {
        struct fluxvm_scx_vm_stats *stats = stats_for(profile->vm_key);
        __u64 task_vtime = p->scx.dsq_vtime;

        if (task_vtime > vtime_now)
            vtime_now = task_vtime;
        if (stats) {
            __sync_fetch_and_add(&stats->running_calls, 1);
            if (enqueued && now >= *enqueued) {
                __u64 delay = now - *enqueued;
                __sync_fetch_and_add(&stats->queue_delay_ns, delay);
                if (delay > stats->queue_delay_max_ns)
                    stats->queue_delay_max_ns = delay;
                if (profile->latency_target_ns && delay > profile->latency_target_ns)
                    __sync_fetch_and_add(&stats->latency_violations, 1);
                maybe_latency_event(p, profile, delay);
            }
        }
    }
    if (enqueued)
        bpf_map_delete_elem(&scx_enqueue_ts, &tid);
}

void BPF_STRUCT_OPS(fluxvm_scx_stopping, struct task_struct *p, bool runnable)
{
    struct fluxvm_scx_task_profile *profile = profile_for(p);
    __u64 slice = bounded_slice(profile);
    __u64 remaining = p->scx.slice;
    __u64 used = remaining < slice ? slice - remaining : slice;
    __u32 weight = bounded_weight(profile);
    __u64 charge = used * FLUXVM_SCX_DEFAULT_WEIGHT / weight;

    (void)runnable;
    if (!charge)
        charge = 1;
    scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime + charge);
    if (profile) {
        struct fluxvm_scx_vm_stats *stats = stats_for(profile->vm_key);
        if (stats) {
            __sync_fetch_and_add(&stats->stopping_calls, 1);
            __sync_fetch_and_add(&stats->runtime_ns, used);
        }
    }
}

void BPF_STRUCT_OPS(fluxvm_scx_enable, struct task_struct *p)
{
    scx_bpf_task_set_dsq_vtime(p, vtime_now);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fluxvm_scx_init)
{
    return scx_bpf_create_dsq(FLUXVM_SCX_DSQ, -1);
}

void BPF_STRUCT_OPS(fluxvm_scx_exit, struct scx_exit_info *ei)
{
    exit_kind = ei->kind;
}

SCX_OPS_DEFINE(fluxvm_scx_ops,
    .select_cpu = (void *)fluxvm_scx_select_cpu,
    .enqueue = (void *)fluxvm_scx_enqueue,
    .dispatch = (void *)fluxvm_scx_dispatch,
    .running = (void *)fluxvm_scx_running,
    .stopping = (void *)fluxvm_scx_stopping,
    .enable = (void *)fluxvm_scx_enable,
    .init = (void *)fluxvm_scx_init,
    .exit = (void *)fluxvm_scx_exit,
    .flags = SCX_OPS_SWITCH_PARTIAL,
    .name = "fluxvm_scx");
