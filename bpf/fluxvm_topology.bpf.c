// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Set 8: VM topology / IRQ intelligence. This program is observation-only.
// It never rewrites Cilium, Fabric, IRQ affinity, RPS/XPS or scheduler state.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TOPO_EVENT_MIGRATION 1
#define TOPO_EVENT_HARDIRQ_LONG 2
#define TOPO_EVENT_SOFTIRQ_LONG 3
#define TOPO_EVENT_VCPU_SLICE_LONG 4
#define TOPO_LONG_NS 1000000ULL
#define TOPO_MAX_CPUS 4096
#define TOPO_NET_TX_SOFTIRQ 2
#define TOPO_NET_RX_SOFTIRQ 3

struct tracked_vcpu {
    __u64 vm_key;
    __u32 vcpu;
    __u32 tgid;
};

struct vcpu_cpu_key {
    __u64 vm_key;
    __u32 vcpu;
    __u32 cpu;
};

struct vcpu_cpu_stat {
    __u64 run_ns;
    __u64 switches;
    __u64 migrations;
    __u64 max_slice_ns;
    __u64 last_seen_ns;
};

struct cpu_irq_stat {
    __u64 hardirq_count;
    __u64 hardirq_ns;
    __u64 hardirq_max_ns;
    __u64 softirq_count;
    __u64 softirq_ns;
    __u64 softirq_max_ns;
    __u64 net_rx_ns;
    __u64 net_tx_ns;
};

struct irq_start {
    __u64 timestamp_ns;
    __u32 vector;
    __u32 reserved;
};

struct topo_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u64 duration_ns;
    __u32 event_type;
    __u32 tid;
    __u32 vcpu;
    __u32 cpu;
    __u32 from_cpu;
    __u32 to_cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct tracked_vcpu);
} topo_tracked_vcpus SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} topo_run_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct vcpu_cpu_key);
    __type(value, struct vcpu_cpu_stat);
} topo_vcpu_cpu SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TOPO_MAX_CPUS);
    __type(key, __u32);
    __type(value, struct cpu_irq_stat);
} topo_cpu_irq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TOPO_MAX_CPUS);
    __type(key, __u32);
    __type(value, struct irq_start);
} topo_hardirq_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TOPO_MAX_CPUS);
    __type(key, __u32);
    __type(value, struct irq_start);
} topo_softirq_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} topo_events SEC(".maps");

struct trace_sched_switch {
    __u64 pad;
    char prev_comm[16];
    __s32 prev_pid;
    __s32 prev_prio;
    __s64 prev_state;
    char next_comm[16];
    __s32 next_pid;
    __s32 next_prio;
};

struct trace_sched_migrate {
    __u64 pad;
    char comm[16];
    __s32 pid;
    __s32 prio;
    __s32 orig_cpu;
    __s32 dest_cpu;
};

struct trace_irq_entry {
    __u64 pad;
    __s32 irq;
    __u32 reserved;
    __u64 name;
};

struct trace_irq_exit {
    __u64 pad;
    __s32 irq;
    __s32 ret;
};

struct trace_softirq {
    __u64 pad;
    __u32 vec;
};

static __always_inline void emit(__u32 type, __u64 vm_key, __u32 tid,
                                 __u32 vcpu, __u32 cpu, __u32 from_cpu,
                                 __u32 to_cpu, __u64 duration_ns)
{
    struct topo_event *e = bpf_ringbuf_reserve(&topo_events, sizeof(*e), 0);
    if (!e)
        return;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->vm_key = vm_key;
    e->duration_ns = duration_ns;
    e->event_type = type;
    e->tid = tid;
    e->vcpu = vcpu;
    e->cpu = cpu;
    e->from_cpu = from_cpu;
    e->to_cpu = to_cpu;
    bpf_ringbuf_submit(e, 0);
}

static __always_inline struct vcpu_cpu_stat *vcpu_stat(__u64 vm_key,
                                                        __u32 vcpu,
                                                        __u32 cpu)
{
    struct vcpu_cpu_key key = {
        .vm_key = vm_key,
        .vcpu = vcpu,
        .cpu = cpu,
    };
    struct vcpu_cpu_stat *s = bpf_map_lookup_elem(&topo_vcpu_cpu, &key);
    if (s)
        return s;
    struct vcpu_cpu_stat zero = {};
    bpf_map_update_elem(&topo_vcpu_cpu, &key, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&topo_vcpu_cpu, &key);
}

SEC("tracepoint/sched/sched_switch")
int fluxvm_topo_sched_switch(struct trace_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();

    if (ctx->prev_pid > 0) {
        __u32 tid = (__u32)ctx->prev_pid;
        struct tracked_vcpu *t = bpf_map_lookup_elem(&topo_tracked_vcpus, &tid);
        __u64 *start = bpf_map_lookup_elem(&topo_run_start, &tid);
        if (t && start && now >= *start) {
            __u64 delta = now - *start;
            struct vcpu_cpu_stat *s = vcpu_stat(t->vm_key, t->vcpu, cpu);
            if (s) {
                __sync_fetch_and_add(&s->run_ns, delta);
                if (delta > s->max_slice_ns)
                    s->max_slice_ns = delta;
                s->last_seen_ns = now;
            }
            if (delta >= TOPO_LONG_NS)
                emit(TOPO_EVENT_VCPU_SLICE_LONG, t->vm_key, tid,
                     t->vcpu, cpu, cpu, cpu, delta);
        }
        bpf_map_delete_elem(&topo_run_start, &tid);
    }

    if (ctx->next_pid > 0) {
        __u32 tid = (__u32)ctx->next_pid;
        struct tracked_vcpu *t = bpf_map_lookup_elem(&topo_tracked_vcpus, &tid);
        if (t) {
            bpf_map_update_elem(&topo_run_start, &tid, &now, BPF_ANY);
            struct vcpu_cpu_stat *s = vcpu_stat(t->vm_key, t->vcpu, cpu);
            if (s) {
                __sync_fetch_and_add(&s->switches, 1);
                s->last_seen_ns = now;
            }
        }
    }
    return 0;
}

SEC("tracepoint/sched/sched_migrate_task")
int fluxvm_topo_sched_migrate(struct trace_sched_migrate *ctx)
{
    if (ctx->pid <= 0)
        return 0;
    __u32 tid = (__u32)ctx->pid;
    struct tracked_vcpu *t = bpf_map_lookup_elem(&topo_tracked_vcpus, &tid);
    if (!t)
        return 0;
    __u32 dest = ctx->dest_cpu < 0 ? 0 : (__u32)ctx->dest_cpu;
    struct vcpu_cpu_stat *s = vcpu_stat(t->vm_key, t->vcpu, dest);
    if (s) {
        __sync_fetch_and_add(&s->migrations, 1);
        s->last_seen_ns = bpf_ktime_get_ns();
    }
    emit(TOPO_EVENT_MIGRATION, t->vm_key, tid, t->vcpu,
         bpf_get_smp_processor_id(), (__u32)ctx->orig_cpu, dest, 0);
    return 0;
}

SEC("tracepoint/irq/irq_handler_entry")
int fluxvm_topo_irq_enter(struct trace_irq_entry *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (cpu >= TOPO_MAX_CPUS)
        return 0;
    struct irq_start *s = bpf_map_lookup_elem(&topo_hardirq_start, &cpu);
    if (s) {
        s->timestamp_ns = bpf_ktime_get_ns();
        s->vector = ctx->irq < 0 ? 0 : (__u32)ctx->irq;
    }
    return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int fluxvm_topo_irq_exit(struct trace_irq_exit *ctx)
{
    (void)ctx;
    __u32 cpu = bpf_get_smp_processor_id();
    if (cpu >= TOPO_MAX_CPUS)
        return 0;
    struct irq_start *start = bpf_map_lookup_elem(&topo_hardirq_start, &cpu);
    struct cpu_irq_stat *s = bpf_map_lookup_elem(&topo_cpu_irq, &cpu);
    if (!start || !s || !start->timestamp_ns)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now >= start->timestamp_ns ? now - start->timestamp_ns : 0;
    __sync_fetch_and_add(&s->hardirq_count, 1);
    __sync_fetch_and_add(&s->hardirq_ns, delta);
    if (delta > s->hardirq_max_ns)
        s->hardirq_max_ns = delta;
    if (delta >= TOPO_LONG_NS)
        emit(TOPO_EVENT_HARDIRQ_LONG, 0, 0, 0, cpu, cpu, cpu, delta);
    start->timestamp_ns = 0;
    return 0;
}

SEC("tracepoint/irq/softirq_entry")
int fluxvm_topo_softirq_enter(struct trace_softirq *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (cpu >= TOPO_MAX_CPUS)
        return 0;
    struct irq_start *s = bpf_map_lookup_elem(&topo_softirq_start, &cpu);
    if (s) {
        s->timestamp_ns = bpf_ktime_get_ns();
        s->vector = ctx->vec;
    }
    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int fluxvm_topo_softirq_exit(struct trace_softirq *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    if (cpu >= TOPO_MAX_CPUS)
        return 0;
    struct irq_start *start = bpf_map_lookup_elem(&topo_softirq_start, &cpu);
    struct cpu_irq_stat *s = bpf_map_lookup_elem(&topo_cpu_irq, &cpu);
    if (!start || !s || !start->timestamp_ns)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now >= start->timestamp_ns ? now - start->timestamp_ns : 0;
    __u32 vec = start->vector;
    __sync_fetch_and_add(&s->softirq_count, 1);
    __sync_fetch_and_add(&s->softirq_ns, delta);
    if (delta > s->softirq_max_ns)
        s->softirq_max_ns = delta;
    if (vec == TOPO_NET_RX_SOFTIRQ)
        __sync_fetch_and_add(&s->net_rx_ns, delta);
    if (vec == TOPO_NET_TX_SOFTIRQ)
        __sync_fetch_and_add(&s->net_tx_ns, delta);
    if (delta >= TOPO_LONG_NS)
        emit(TOPO_EVENT_SOFTIRQ_LONG, 0, 0, 0, cpu, cpu, ctx->vec, delta);
    start->timestamp_ns = 0;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
