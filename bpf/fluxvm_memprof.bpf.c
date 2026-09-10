// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM Set 7 — VM memory pressure + boot/snapshot profiler.
//
// This object reuses Runtime Intelligence's tracked_tgids/tracked_tids/
// tracked_cgroups maps. It does not inspect guest memory and does not touch
// Cilium/Fabric maps. Optional tracepoints/kprobes are attached by userspace
// only when the host exposes them.

#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define FLUXVM_MEM_EVENT_PAGE_FAULT    1
#define FLUXVM_MEM_EVENT_RECLAIM       2
#define FLUXVM_MEM_EVENT_FIRST_KVM     3
#define FLUXVM_MEM_EVENT_FIRST_VHOST   4

#define FLUXVM_MEM_HIST_FAULT          1
#define FLUXVM_MEM_HIST_RECLAIM        2
#define FLUXVM_MEM_HIST_BUCKETS       25

#define FLUXVM_VM_FAULT_MAJOR 0x000004u
#define FLUXVM_SLOW_FAULT_NS   2000000ULL
#define FLUXVM_SLOW_RECLAIM_NS 5000000ULL

struct start_state {
    __u64 vm_key;
    __u64 start_ns;
};

struct mem_stats {
    __u64 faults;
    __u64 major_faults;
    __u64 fault_total_ns;
    __u64 fault_max_ns;
    __u64 reclaim_events;
    __u64 reclaim_total_ns;
    __u64 reclaim_max_ns;
    __u64 ringbuf_lost;
};
_Static_assert(sizeof(struct mem_stats) == 64, "mem_stats ABI");

struct hist_key {
    __u64 vm_key;
    __u32 kind;
    __u32 bucket;
};

struct hist_value {
    __u64 count;
    __u64 total_ns;
    __u64 max_ns;
};

struct boot_first {
    __u64 first_kvm_entry_ns;
    __u64 first_vhost_activity_ns;
    __u64 first_major_fault_ns;
    __u64 first_reclaim_ns;
};
_Static_assert(sizeof(struct boot_first) == 32, "boot_first ABI");

struct mem_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u64 duration_ns;
    __u64 arg0;
    __u32 tid;
    __u32 cpu;
    __u32 event_type;
    __u32 reserved;
};
_Static_assert(sizeof(struct mem_event) == 48, "mem_event ABI");

/* Reused by fluxvm-memprof-loader from Runtime Intelligence. */
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u64);
} tracked_cgroups SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct start_state);
} memprof_fault_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct start_state);
} memprof_reclaim_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct mem_stats);
} memprof_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct hist_key);
    __type(value, struct hist_value);
} memprof_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct boot_first);
} memprof_first SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);
} memprof_events SEC(".maps");

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

static __always_inline struct mem_stats *stats_for(__u64 vm_key)
{
    struct mem_stats zero = {};
    struct mem_stats *stats = bpf_map_lookup_elem(&memprof_stats, &vm_key);
    if (!stats) {
        bpf_map_update_elem(&memprof_stats, &vm_key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&memprof_stats, &vm_key);
    }
    return stats;
}

static __always_inline struct boot_first *first_for(__u64 vm_key)
{
    struct boot_first zero = {};
    struct boot_first *first = bpf_map_lookup_elem(&memprof_first, &vm_key);
    if (!first) {
        bpf_map_update_elem(&memprof_first, &vm_key, &zero, BPF_NOEXIST);
        first = bpf_map_lookup_elem(&memprof_first, &vm_key);
    }
    return first;
}

static __always_inline __u32 hist_bucket(__u64 ns)
{
    __u64 limit = 1000ULL; /* 1 us */
#pragma unroll
    for (int i = 0; i < FLUXVM_MEM_HIST_BUCKETS - 1; i++) {
        if (ns <= limit)
            return i;
        limit <<= 1;
    }
    return FLUXVM_MEM_HIST_BUCKETS - 1;
}

static __always_inline void hist_add(__u64 vm_key, __u32 kind, __u64 ns)
{
    struct hist_key key = {
        .vm_key = vm_key,
        .kind = kind,
        .bucket = hist_bucket(ns),
    };
    struct hist_value *v = bpf_map_lookup_elem(&memprof_hist, &key);
    if (!v) {
        struct hist_value zero = {};
        bpf_map_update_elem(&memprof_hist, &key, &zero, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&memprof_hist, &key);
    }
    if (!v)
        return;
    __sync_fetch_and_add(&v->count, 1);
    __sync_fetch_and_add(&v->total_ns, ns);
    max_u64(&v->max_ns, ns);
}

static __always_inline void emit(__u64 vm_key, __u32 type, __u64 duration_ns, __u64 arg0)
{
    struct mem_event *event = bpf_ringbuf_reserve(&memprof_events, sizeof(*event), 0);
    if (!event) {
        struct mem_stats *stats = stats_for(vm_key);
        if (stats)
            __sync_fetch_and_add(&stats->ringbuf_lost, 1);
        return;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->vm_key = vm_key;
    event->duration_ns = duration_ns;
    event->arg0 = arg0;
    event->tid = (__u32)pid_tgid;
    event->cpu = bpf_get_smp_processor_id();
    event->event_type = type;
    event->reserved = 0;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void set_first(__u64 vm_key, __u64 *slot, __u32 event_type)
{
    if (!slot || *slot != 0)
        return;
    __u64 now = bpf_ktime_get_ns();
    if (__sync_val_compare_and_swap(slot, 0, now) == 0)
        emit(vm_key, event_type, 0, 0);
}

SEC("tracepoint/kvm/kvm_entry")
int fluxvm_memprof_kvm_entry(void *ctx)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key)
        return 0;
    struct boot_first *first = first_for(*vm_key);
    if (first)
        set_first(*vm_key, &first->first_kvm_entry_ns, FLUXVM_MEM_EVENT_FIRST_KVM);
    return 0;
}

SEC("kprobe/handle_mm_fault")
int fluxvm_memprof_fault_enter(struct pt_regs *ctx)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_state start = {.vm_key = *vm_key, .start_ns = bpf_ktime_get_ns()};
    bpf_map_update_elem(&memprof_fault_start, &pid_tgid, &start, BPF_ANY);
    return 0;
}

SEC("kretprobe/handle_mm_fault")
int fluxvm_memprof_fault_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_state *start = bpf_map_lookup_elem(&memprof_fault_start, &pid_tgid);
    if (!start)
        return 0;
    struct start_state saved = *start;
    bpf_map_delete_elem(&memprof_fault_start, &pid_tgid);
    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now >= saved.start_ns ? now - saved.start_ns : 0;
    struct mem_stats *stats = stats_for(saved.vm_key);
    if (stats) {
        __sync_fetch_and_add(&stats->faults, 1);
        __sync_fetch_and_add(&stats->fault_total_ns, duration);
        max_u64(&stats->fault_max_ns, duration);
    }
#ifdef PT_REGS_RC
    unsigned long rc = PT_REGS_RC(ctx);
#else
    unsigned long rc = 0;
    (void)ctx;
#endif
    int major = (rc & FLUXVM_VM_FAULT_MAJOR) != 0;
    if (major) {
        if (stats)
            __sync_fetch_and_add(&stats->major_faults, 1);
        struct boot_first *first = first_for(saved.vm_key);
        if (first && first->first_major_fault_ns == 0) {
            __u64 stamp = now;
            __sync_val_compare_and_swap(&first->first_major_fault_ns, 0, stamp);
        }
    }
    hist_add(saved.vm_key, FLUXVM_MEM_HIST_FAULT, duration);
    if (major || duration >= FLUXVM_SLOW_FAULT_NS)
        emit(saved.vm_key, FLUXVM_MEM_EVENT_PAGE_FAULT, duration, major ? 1 : 0);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int fluxvm_memprof_reclaim_begin(void *ctx)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_state start = {.vm_key = *vm_key, .start_ns = bpf_ktime_get_ns()};
    bpf_map_update_elem(&memprof_reclaim_start, &pid_tgid, &start, BPF_ANY);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int fluxvm_memprof_reclaim_end(void *ctx)
{
    (void)ctx;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_state *start = bpf_map_lookup_elem(&memprof_reclaim_start, &pid_tgid);
    if (!start)
        return 0;
    struct start_state saved = *start;
    bpf_map_delete_elem(&memprof_reclaim_start, &pid_tgid);
    __u64 now = bpf_ktime_get_ns();
    __u64 duration = now >= saved.start_ns ? now - saved.start_ns : 0;
    struct mem_stats *stats = stats_for(saved.vm_key);
    if (stats) {
        __sync_fetch_and_add(&stats->reclaim_events, 1);
        __sync_fetch_and_add(&stats->reclaim_total_ns, duration);
        max_u64(&stats->reclaim_max_ns, duration);
    }
    struct boot_first *first = first_for(saved.vm_key);
    if (first && first->first_reclaim_ns == 0) {
        __u64 stamp = now;
        __sync_val_compare_and_swap(&first->first_reclaim_ns, 0, stamp);
    }
    hist_add(saved.vm_key, FLUXVM_MEM_HIST_RECLAIM, duration);
    if (duration >= FLUXVM_SLOW_RECLAIM_NS)
        emit(saved.vm_key, FLUXVM_MEM_EVENT_RECLAIM, duration, 0);
    return 0;
}

SEC("kprobe/vhost_poll_wakeup")
int fluxvm_memprof_vhost_wakeup(struct pt_regs *ctx)
{
    (void)ctx;
    __u64 *vm_key = current_vm_key();
    if (!vm_key)
        return 0;
    struct boot_first *first = first_for(*vm_key);
    if (first)
        set_first(*vm_key, &first->first_vhost_activity_ns, FLUXVM_MEM_EVENT_FIRST_VHOST);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
