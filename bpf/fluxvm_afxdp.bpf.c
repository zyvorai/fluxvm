// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Set 9: AF_XDP dedicated-interface queue fast path.
// Safe default: packets PASS unless a queue has an active XSK gate.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define AFXDP_MAX_QUEUES 64
#define AFXDP_MAX_SLOTS 2
#define AFXDP_MAX_KEYS (AFXDP_MAX_QUEUES * AFXDP_MAX_SLOTS)
#define AFXDP_IFACE_ENABLED (1u << 0)

struct afxdp_iface_cfg {
    __u64 vm_key;
    __u32 generation;
    __u16 slot;
    __u16 flags;
    __u32 sample_rate;
    __u32 reserved;
};
_Static_assert(sizeof(struct afxdp_iface_cfg) == 24, "afxdp iface ABI");

struct afxdp_xdp_stat {
    __u64 seen_packets;
    __u64 seen_bytes;
    __u64 redirect_attempts;
    __u64 pass_inactive;
    __u64 pass_queue_disabled;
};

struct afxdp_runtime_stat {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 dropped_packets;
    __u64 tx_ring_full;
    __u64 fill_deferred;
    __u64 poll_wakeups;
    __u64 multibuf_drops;
    __u64 last_update_ns;
    __u32 zero_copy;
    __u32 worker_pid;
};
_Static_assert(sizeof(struct afxdp_runtime_stat) == 88, "afxdp runtime ABI");

struct afxdp_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u32 ifindex;
    __u32 queue_id;
    __u32 bytes;
    __u32 key;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct afxdp_iface_cfg);
} afxdp_ifaces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, AFXDP_MAX_KEYS);
    __type(key, __u32);
    __type(value, __u32);
} afxdp_xsks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, AFXDP_MAX_KEYS);
    __type(key, __u32);
    __type(value, __u32);
} afxdp_queue_enabled SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, AFXDP_MAX_KEYS);
    __type(key, __u32);
    __type(value, struct afxdp_xdp_stat);
} afxdp_xdp_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, AFXDP_MAX_KEYS);
    __type(key, __u32);
    __type(value, struct afxdp_runtime_stat);
} afxdp_runtime SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} afxdp_events SEC(".maps");

static __always_inline struct afxdp_xdp_stat *stat_for(__u32 key)
{
    return bpf_map_lookup_elem(&afxdp_xdp_stats, &key);
}

SEC("xdp")
int fluxvm_afxdp(struct xdp_md *ctx)
{
    __u32 ifindex = ctx->ingress_ifindex;
    struct afxdp_iface_cfg *cfg = bpf_map_lookup_elem(&afxdp_ifaces, &ifindex);
    if (!cfg || !(cfg->flags & AFXDP_IFACE_ENABLED))
        return XDP_PASS;

    __u32 q = ctx->rx_queue_index;
    if (q >= AFXDP_MAX_QUEUES)
        return XDP_PASS;
    __u32 key = ((__u32)cfg->slot * AFXDP_MAX_QUEUES) + q;
    struct afxdp_xdp_stat *s = stat_for(key);
    __u64 bytes = (__u64)((void *)(long)ctx->data_end - (void *)(long)ctx->data);
    if (s) {
        s->seen_packets++;
        s->seen_bytes += bytes;
    }

    __u32 *enabled = bpf_map_lookup_elem(&afxdp_queue_enabled, &key);
    if (!enabled || !*enabled) {
        if (s)
            s->pass_queue_disabled++;
        return XDP_PASS;
    }

    if (s)
        s->redirect_attempts++;
    if (cfg->sample_rate && (bpf_get_prandom_u32() % cfg->sample_rate) == 0) {
        struct afxdp_event *e = bpf_ringbuf_reserve(&afxdp_events, sizeof(*e), 0);
        if (e) {
            e->timestamp_ns = bpf_ktime_get_ns();
            e->vm_key = cfg->vm_key;
            e->ifindex = ifindex;
            e->queue_id = q;
            e->bytes = (__u32)bytes;
            e->key = key;
            bpf_ringbuf_submit(e, 0);
        }
    }

    // If userspace has removed the XSK or it is bound to the wrong queue,
    // bpf_redirect_map() returns the low-bit fallback action: XDP_PASS.
    // This is deliberate fail-open continuity for the optional fast path.
    return bpf_redirect_map(&afxdp_xsks, key, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
