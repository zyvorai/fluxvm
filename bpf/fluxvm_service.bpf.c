// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM Service Fabric v5 (v4 BPF ABI retained): dual-stack VM-edge + host-uplink TC dataplane.
//
// fvm_svc_vm is attached to ingress of every host-visible VM edge for
// frontend selection. fvm_svc_host serves physical-uplink ingress. The
// fvm_svc_rev program is attached to egress of the same interface and uses
// the same maps to restore NAT return traffic. Host ingress also restores
// remote-backend replies. Optional XDP acceleration shares the host maps.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "fluxvm_service_maps.bpf.h"

#define FLUXVM_SVC_BACKEND_READY 1u
#define FLUXVM_SVC_BACKEND_DRAINING 2u
#define FLUXVM_SVC_BACKEND_UNHEALTHY 4u
#define FLUXVM_CT_UDP_NS 60000000000ULL
#define FLUXVM_CT_TCP_SYN_NS 30000000000ULL
#define FLUXVM_CT_TCP_EST_NS 300000000000ULL
#define FLUXVM_CT_TCP_FIN_NS 15000000000ULL
#define FLUXVM_CT_TCP_RST_NS 2000000000ULL
#define FLUXVM_SVC_MODE_NAT 1u
#define FLUXVM_SVC_MODE_DSR 2u
#define FLUXVM_NAT_F_SNAT 1u
#define FLUXVM_NAT_PORT_MIN 32768u
#define FLUXVM_NAT_PORT_SPAN 28232u
#define FLUXVM_NAT_PORT_PROBES 16
#define FLUXVM_AF_INET 2
#define FLUXVM_AF_INET6 10
#define FLUXVM_SVC_F_HOST_ROUTING 1u
#define FLUXVM_FLOW_ALLOW 1u
#define FLUXVM_FLOW_DROP 0u
#define FLUXVM_REASON_NONE 0u
#define FLUXVM_REASON_UPDATE_GUARD 1u
#define FLUXVM_REASON_NO_MAGLEV 2u
#define FLUXVM_REASON_NO_BACKEND 3u
#define FLUXVM_REASON_BACKEND_UNHEALTHY 4u
#define FLUXVM_REASON_NAT_EXHAUSTED 5u
#define FLUXVM_REASON_REWRITE_FAILED 6u
#define FLUXVM_REASON_FIB_FALLBACK 7u
#define FLUXVM_REASON_BAD_MODE 8u
#define FLUXVM_REASON_CT_STALE 9u

struct svc4_key {
    __u32 address;
    __u16 port;
    __u8 protocol;
    __u8 pad;
};

struct svc6_key {
    __u8 address[16];
    __u16 port;
    __u8 protocol;
    __u8 pad;
};

struct svc_value {
    __u32 service_id;
    __u32 table_size;
    __u64 rate_bytes_per_sec;
    __u32 flow_sample_rate;
    __u8 mode;
    __u8 flags;
    __u16 pad;
};

struct backend_key {
    __u32 service_id;
    __u32 backend_id;
};

struct backend4_value {
    __u32 address;
    __u16 port;
    __u16 flags;
};

struct backend6_value {
    __u8 address[16];
    __u16 port;
    __u16 flags;
};

struct maglev_key {
    __u32 service_id;
    __u32 slot;
};

struct snat4_value {
    __u32 address;
    __u32 enabled;
};

struct snat6_value {
    __u8 address[16];
    __u32 enabled;
};

struct nat4_key {
    __u32 backend_address;
    __u32 reply_address;
    __u16 backend_port;
    __u16 reply_port;
    __u8 protocol;
    __u8 pad[3];
};

struct nat4_value {
    __u32 service_id;
    __u32 backend_id;
    __u32 client_address;
    __u32 vip_address;
    __u64 last_seen_ns;
    __u16 vip_port;
    __u16 client_port;
    __u32 pad;
};

struct nat6_key {
    __u8 backend_address[16];
    __u8 reply_address[16];
    __u16 backend_port;
    __u16 reply_port;
    __u8 protocol;
    __u8 pad[3];
};

struct nat6_value {
    __u32 service_id;
    __u32 backend_id;
    __u8 client_address[16];
    __u8 vip_address[16];
    __u64 last_seen_ns;
    __u16 vip_port;
    __u16 client_port;
    __u32 pad;
};

struct fct4_key {
    __u32 client_address;
    __u32 vip_address;
    __u16 client_port;
    __u16 vip_port;
    __u8 protocol;
    __u8 pad[3];
};

struct fct6_key {
    __u8 client_address[16];
    __u8 vip_address[16];
    __u16 client_port;
    __u16 vip_port;
    __u8 protocol;
    __u8 pad[3];
};

struct fct_value {
    __u32 service_id;
    __u32 backend_id;
    __u64 last_seen_ns;
    __u64 expires_at_ns;
};

struct backend_stat {
    __u64 forwarded;
    __u64 failures;
    __u64 last_success_ns;
    __u64 last_failure_ns;
};

struct service_stat {
    __u64 forward_packets;
    __u64 forward_bytes;
    __u64 reverse_packets;
    __u64 backend_misses;
    __u64 dsr_packets;
    __u64 snat_packets;
    __u64 xdp_packets;
    __u64 conntrack_hits;
    __u64 conntrack_misses;
    __u64 conntrack_expired;
    __u64 passive_failures;
    __u64 edt_packets;
    __u64 host_routed_packets;
    __u64 host_route_fallbacks;
    __u64 flow_events;
};

struct svc_flow_key {
    __u32 service_id;
    __u32 backend_id;
    __u8 src[16];
    __u8 dst[16];
    __u16 sport;
    __u16 dport;
    __u8 family;
    __u8 protocol;
    __u8 verdict;
    __u8 reason;
};

struct svc_flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

struct edt_state {
    struct bpf_spin_lock lock;
    __u32 pad;
    __u64 next_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_SVC);
    __type(key, struct svc4_key);
    __type(value, struct svc_value);
} fluxvm_svc4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_SVC);
    __type(key, struct svc6_key);
    __type(value, struct svc_value);
} fluxvm_svc6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} fluxvm_sguard SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_BACKEND);
    __type(key, struct backend_key);
    __type(value, struct backend4_value);
} fluxvm_backend4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_BACKEND);
    __type(key, struct backend_key);
    __type(value, struct backend6_value);
} fluxvm_backend6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_MAGLEV);
    __type(key, struct maglev_key);
    __type(value, __u32);
} fluxvm_maglev SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLUXVM_MAX_CT);
    __type(key, struct fct4_key);
    __type(value, struct fct_value);
} fluxvm_fct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLUXVM_MAX_CT);
    __type(key, struct fct6_key);
    __type(value, struct fct_value);
} fluxvm_fct6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLUXVM_MAX_NAT);
    __type(key, struct nat4_key);
    __type(value, struct nat4_value);
} fluxvm_nat4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLUXVM_MAX_NAT);
    __type(key, struct nat6_key);
    __type(value, struct nat6_value);
} fluxvm_nat6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_SVC);
    __type(key, __u32);
    __type(value, struct snat4_value);
} fluxvm_snat4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_SVC);
    __type(key, __u32);
    __type(value, struct snat6_value);
} fluxvm_snat6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FLUXVM_MAX_SVC);
    __type(key, __u32);
    __type(value, struct service_stat);
} fluxvm_sstats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FLUXVM_MAX_BACKEND);
    __type(key, struct backend_key);
    __type(value, struct backend_stat);
} fluxvm_bstat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLUXVM_MAX_SFLOWS);
    __type(key, struct svc_flow_key);
    __type(value, struct svc_flow_value);
} fluxvm_sflows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_SVC);
    __type(key, __u32);
    __type(value, struct edt_state);
} fluxvm_edt SEC(".maps");

/* TC-private per-CPU scratch so large locals fit the kernel 512B stack. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_fib_lookup);
} fluxvm_fib_scratch SEC(".maps");

static __always_inline struct bpf_fib_lookup *fib_scratch(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&fluxvm_fib_scratch, &zero);
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct svc_flow_key);
} fluxvm_flow_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct svc_flow_value);
} fluxvm_flow_val_scratch SEC(".maps");

static __always_inline struct svc_flow_key *flow_key_scratch(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&fluxvm_flow_scratch, &zero);
}

static __always_inline struct svc_flow_value *flow_val_scratch(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&fluxvm_flow_val_scratch, &zero);
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nat6_key);
} fluxvm_nat6_key_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nat6_value);
} fluxvm_nat6_val_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fct6_key);
} fluxvm_fct6_key_scratch SEC(".maps");

static __always_inline struct nat6_key *nat6_key_scratch(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&fluxvm_nat6_key_scratch, &zero);
}

static __always_inline struct nat6_value *nat6_val_scratch(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&fluxvm_nat6_val_scratch, &zero);
}

static __always_inline struct fct6_key *fct6_key_scratch(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&fluxvm_fct6_key_scratch, &zero);
}

#include "fluxvm_service_v6.bpf.h"

static __always_inline int update_guard_enabled(void)
{
    __u32 key = 0;
    __u32 *value = bpf_map_lookup_elem(&fluxvm_sguard, &key);
    return value && *value;
}

static __always_inline struct service_stat *stat_for(__u32 service_id)
{
    struct service_stat *s = bpf_map_lookup_elem(&fluxvm_sstats, &service_id);
    if (s)
        return s;
    struct service_stat zero = {};
    bpf_map_update_elem(&fluxvm_sstats, &service_id, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_sstats, &service_id);
}

static __always_inline void count_forward(__u32 sid, __u32 bytes, int dsr, int snat)
{
    struct service_stat *s = stat_for(sid);
    if (!s)
        return;
    s->forward_packets += 1;
    s->forward_bytes += bytes;
    if (dsr)
        s->dsr_packets += 1;
    if (snat)
        s->snat_packets += 1;
}

static __always_inline void count_reverse(__u32 sid)
{
    struct service_stat *s = stat_for(sid);
    if (s)
        s->reverse_packets += 1;
}

static __always_inline void count_miss(__u32 sid)
{
    struct service_stat *s = stat_for(sid);
    if (s)
        s->backend_misses += 1;
}

static __always_inline void count_ct(__u32 sid, int hit, int expired)
{
    struct service_stat *s = stat_for(sid);
    if (!s)
        return;
    if (hit)
        s->conntrack_hits += 1;
    else
        s->conntrack_misses += 1;
    if (expired)
        s->conntrack_expired += 1;
}

static __always_inline struct backend_stat *backend_stat_for(__u32 sid, __u32 bid)
{
    struct backend_key key = {.service_id = sid, .backend_id = bid};
    struct backend_stat *s = bpf_map_lookup_elem(&fluxvm_bstat, &key);
    if (s)
        return s;
    struct backend_stat zero = {};
    bpf_map_update_elem(&fluxvm_bstat, &key, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_bstat, &key);
}

static __always_inline void backend_success(__u32 sid, __u32 bid)
{
    struct backend_stat *s = backend_stat_for(sid, bid);
    if (!s)
        return;
    s->forwarded += 1;
    s->last_success_ns = bpf_ktime_get_ns();
}

static __always_inline void backend_failure(__u32 sid, __u32 bid)
{
    struct backend_stat *s = backend_stat_for(sid, bid);
    if (s) {
        s->failures += 1;
        s->last_failure_ns = bpf_ktime_get_ns();
    }
    struct service_stat *svc = stat_for(sid);
    if (svc)
        svc->passive_failures += 1;
}

static __always_inline void count_host_route(__u32 sid, int routed)
{
    struct service_stat *s = stat_for(sid);
    if (!s) return;
    if (routed) s->host_routed_packets += 1;
    else s->host_route_fallbacks += 1;
}

static __always_inline void apply_edt(
    struct __sk_buff *skb, __u32 sid, const struct svc_value *svc)
{
    if (!svc->rate_bytes_per_sec) return;
    struct edt_state *state = bpf_map_lookup_elem(&fluxvm_edt, &sid);
    if (!state) {
        struct edt_state zero = {};
        bpf_map_update_elem(&fluxvm_edt, &sid, &zero, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&fluxvm_edt, &sid);
        if (!state) return;
    }
    __u64 now = bpf_ktime_get_ns();
    __u64 delta = ((__u64)skb->len * 1000000000ULL) / svc->rate_bytes_per_sec;
    if (!delta) delta = 1;
    __u64 depart;
    bpf_spin_lock(&state->lock);
    depart = state->next_ns > now ? state->next_ns : now;
    state->next_ns = depart + delta;
    bpf_spin_unlock(&state->lock);
    skb->tstamp = depart;
    struct service_stat *stat = stat_for(sid);
    if (stat) stat->edt_packets += 1;
}

static __always_inline int should_record(__u8 verdict, __u32 sample_rate)
{
    if (verdict == FLUXVM_FLOW_DROP) return 1;
    if (!sample_rate) return 0;
    return (bpf_get_prandom_u32() % sample_rate) == 0;
}

static __always_inline void record_flow4_raw(
    struct __sk_buff *skb, const struct svc_value *svc, __u32 bid,
    __u32 src, __u32 dst, __u16 sport, __u16 dport, __u8 protocol,
    __u8 verdict, __u8 reason)
{
    if (!should_record(verdict, svc->flow_sample_rate)) return;
    struct svc_flow_key *key = flow_key_scratch();
    if (!key) return;
    __builtin_memset(key, 0, sizeof(*key));
    key->service_id = svc->service_id;
    key->backend_id = bid;
    key->sport = sport;
    key->dport = dport;
    key->family = 4;
    key->protocol = protocol;
    key->verdict = verdict;
    key->reason = reason;
    __builtin_memcpy(key->src, &src, 4);
    __builtin_memcpy(key->dst, &dst, 4);
    struct svc_flow_value *v = bpf_map_lookup_elem(&fluxvm_sflows, key);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, skb->len);
        v->last_seen_ns = bpf_ktime_get_ns();
    } else {
        struct svc_flow_value *first = flow_val_scratch();
        if (!first) return;
        first->packets = 1;
        first->bytes = skb->len;
        first->last_seen_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&fluxvm_sflows, key, first, BPF_NOEXIST);
    }
    struct service_stat *stat = stat_for(svc->service_id);
    if (stat) stat->flow_events += 1;
}

static __always_inline void record_flow4(
    struct __sk_buff *skb, const struct svc_value *svc, __u32 bid,
    struct iphdr *iph, __u16 sport, __u16 dport, __u8 verdict, __u8 reason)
{
    record_flow4_raw(skb, svc, bid, iph->saddr, iph->daddr, sport, dport,
                     iph->protocol, verdict, reason);
}

static __always_inline void record_flow6_raw(
    struct __sk_buff *skb, const struct svc_value *svc, __u32 bid,
    const __u8 *src, const __u8 *dst, __u16 sport, __u16 dport, __u8 protocol,
    __u8 verdict, __u8 reason)
{
    if (!should_record(verdict, svc->flow_sample_rate)) return;
    struct svc_flow_key *key = flow_key_scratch();
    if (!key) return;
    __builtin_memset(key, 0, sizeof(*key));
    key->service_id = svc->service_id;
    key->backend_id = bid;
    key->sport = sport;
    key->dport = dport;
    key->family = 6;
    key->protocol = protocol;
    key->verdict = verdict;
    key->reason = reason;
    __builtin_memcpy(key->src, src, 16);
    __builtin_memcpy(key->dst, dst, 16);
    struct svc_flow_value *v = bpf_map_lookup_elem(&fluxvm_sflows, key);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, skb->len);
        v->last_seen_ns = bpf_ktime_get_ns();
    } else {
        struct svc_flow_value *first = flow_val_scratch();
        if (!first) return;
        first->packets = 1;
        first->bytes = skb->len;
        first->last_seen_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&fluxvm_sflows, key, first, BPF_NOEXIST);
    }
    struct service_stat *stat = stat_for(svc->service_id);
    if (stat) stat->flow_events += 1;
}

static __always_inline void record_flow6(
    struct __sk_buff *skb, const struct svc_value *svc, __u32 bid,
    struct ipv6hdr *ip6, __u16 sport, __u16 dport, __u8 verdict, __u8 reason)
{
    record_flow6_raw(skb, svc, bid, ip6->saddr.in6_u.u6_addr8,
                     ip6->daddr.in6_u.u6_addr8, sport, dport, ip6->nexthdr,
                     verdict, reason);
}

static __always_inline __u64 timeout4(struct iphdr *iph, void *data_end)
{
    if (iph->protocol == IPPROTO_UDP)
        return FLUXVM_CT_UDP_NS;
    if (iph->protocol != IPPROTO_TCP)
        return FLUXVM_CT_TCP_EST_NS;
    struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return FLUXVM_CT_TCP_SYN_NS;
    if (tcp->rst)
        return FLUXVM_CT_TCP_RST_NS;
    if (tcp->fin)
        return FLUXVM_CT_TCP_FIN_NS;
    if (tcp->syn && !tcp->ack)
        return FLUXVM_CT_TCP_SYN_NS;
    return FLUXVM_CT_TCP_EST_NS;
}

static __always_inline __u64 timeout6(struct ipv6hdr *ip6, void *data_end)
{
    if (ip6->nexthdr == IPPROTO_UDP)
        return FLUXVM_CT_UDP_NS;
    if (ip6->nexthdr != IPPROTO_TCP)
        return FLUXVM_CT_TCP_EST_NS;
    struct tcphdr *tcp = (void *)(ip6 + 1);
    if ((void *)(tcp + 1) > data_end)
        return FLUXVM_CT_TCP_SYN_NS;
    if (tcp->rst)
        return FLUXVM_CT_TCP_RST_NS;
    if (tcp->fin)
        return FLUXVM_CT_TCP_FIN_NS;
    if (tcp->syn && !tcp->ack)
        return FLUXVM_CT_TCP_SYN_NS;
    return FLUXVM_CT_TCP_EST_NS;
}

static __always_inline int affinity4(
    __u32 sid, struct iphdr *iph, void *data_end, __u16 sport, __u16 dport,
    __u32 *backend_id)
{
    struct fct4_key key = {
        .client_address = iph->saddr,
        .vip_address = iph->daddr,
        .client_port = sport,
        .vip_port = dport,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };
    struct fct_value *ct = bpf_map_lookup_elem(&fluxvm_fct4, &key);
    __u64 now = bpf_ktime_get_ns();
    if (!ct || ct->service_id != sid) {
        count_ct(sid, 0, 0);
        return 0;
    }
    if (ct->expires_at_ns <= now) {
        bpf_map_delete_elem(&fluxvm_fct4, &key);
        count_ct(sid, 0, 1);
        return 0;
    }
    struct backend_key bk = {.service_id = sid, .backend_id = ct->backend_id};
    struct backend4_value *be = bpf_map_lookup_elem(&fluxvm_backend4, &bk);
    if (!be || !(be->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING)) ||
        (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY)) {
        bpf_map_delete_elem(&fluxvm_fct4, &key);
        count_ct(sid, 0, 0);
        return 0;
    }
    ct->last_seen_ns = now;
    ct->expires_at_ns = now + timeout4(iph, data_end);
    *backend_id = ct->backend_id;
    count_ct(sid, 1, 0);
    return 1;
}

static __always_inline void learn_affinity4(
    __u32 sid, __u32 bid, struct iphdr *iph, void *data_end, __u16 sport, __u16 dport)
{
    __u64 now = bpf_ktime_get_ns();
    struct fct4_key key = {
        .client_address = iph->saddr,
        .vip_address = iph->daddr,
        .client_port = sport,
        .vip_port = dport,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };
    struct fct_value value = {
        .service_id = sid,
        .backend_id = bid,
        .last_seen_ns = now,
        .expires_at_ns = now + timeout4(iph, data_end),
    };
    if (bpf_map_update_elem(&fluxvm_fct4, &key, &value, BPF_ANY) == 0)
        fluxvm_ha_fct4(sid, bid, FLUXVM_HA_OP_UPSERT, iph->protocol, &key, &value);
}

static __always_inline void delete_affinity4(
    __u32 client, __u32 vip, __u16 sport, __u16 dport, __u8 protocol)
{
    struct fct4_key key = {
        .client_address = client,
        .vip_address = vip,
        .client_port = sport,
        .vip_port = dport,
        .protocol = protocol,
        .pad = {0, 0, 0},
    };
    bpf_map_delete_elem(&fluxvm_fct4, &key);
}

static __always_inline int affinity6(
    __u32 sid, struct ipv6hdr *ip6, void *data_end, __u16 sport, __u16 dport,
    __u32 *backend_id)
{
    struct fct6_key *key = fct6_key_scratch();
    if (!key)
        return 0;
    __builtin_memset(key, 0, sizeof(*key));
    key->client_port = sport;
    key->vip_port = dport;
    key->protocol = ip6->nexthdr;
    __builtin_memcpy(key->client_address, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(key->vip_address, ip6->daddr.in6_u.u6_addr8, 16);
    struct fct_value *ct = bpf_map_lookup_elem(&fluxvm_fct6, key);
    __u64 now = bpf_ktime_get_ns();
    if (!ct || ct->service_id != sid) {
        count_ct(sid, 0, 0);
        return 0;
    }
    if (ct->expires_at_ns <= now) {
        bpf_map_delete_elem(&fluxvm_fct6, key);
        count_ct(sid, 0, 1);
        return 0;
    }
    struct backend_key bk = {.service_id = sid, .backend_id = ct->backend_id};
    struct backend6_value *be = bpf_map_lookup_elem(&fluxvm_backend6, &bk);
    if (!be || !(be->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING)) ||
        (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY)) {
        bpf_map_delete_elem(&fluxvm_fct6, key);
        count_ct(sid, 0, 0);
        return 0;
    }
    ct->last_seen_ns = now;
    ct->expires_at_ns = now + timeout6(ip6, data_end);
    *backend_id = ct->backend_id;
    count_ct(sid, 1, 0);
    return 1;
}

static __always_inline void learn_affinity6(
    __u32 sid, __u32 bid, struct ipv6hdr *ip6, void *data_end, __u16 sport, __u16 dport)
{
    __u64 now = bpf_ktime_get_ns();
    struct fct6_key *key = fct6_key_scratch();
    if (!key)
        return;
    __builtin_memset(key, 0, sizeof(*key));
    key->client_port = sport;
    key->vip_port = dport;
    key->protocol = ip6->nexthdr;
    __builtin_memcpy(key->client_address, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(key->vip_address, ip6->daddr.in6_u.u6_addr8, 16);
    struct fct_value value = {
        .service_id = sid,
        .backend_id = bid,
        .last_seen_ns = now,
        .expires_at_ns = now + timeout6(ip6, data_end),
    };
    if (bpf_map_update_elem(&fluxvm_fct6, key, &value, BPF_ANY) == 0)
        fluxvm_ha_fct6(sid, bid, FLUXVM_HA_OP_UPSERT, ip6->nexthdr, key, &value);
}

static __always_inline void delete_affinity6(
    const __u8 *client, const __u8 *vip, __u16 sport, __u16 dport, __u8 protocol)
{
    struct fct6_key *key = fct6_key_scratch();
    if (!key)
        return;
    __builtin_memset(key, 0, sizeof(*key));
    key->client_port = sport;
    key->vip_port = dport;
    key->protocol = protocol;
    __builtin_memcpy(key->client_address, client, 16);
    __builtin_memcpy(key->vip_address, vip, 16);
    bpf_map_delete_elem(&fluxvm_fct6, key);
}

static __always_inline __u32 mix32(__u32 x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

static __always_inline __u32 flow_hash4(
    __u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 protocol)
{
    __u32 ports = ((__u32)sport << 16) | dport;
    return mix32(saddr ^ mix32(daddr) ^ mix32(ports) ^ ((__u32)protocol << 24));
}

static __always_inline __u32 hash_words6(
    const __u8 *src, const __u8 *dst, __u16 sport, __u16 dport, __u8 protocol)
{
    __u32 h = ((__u32)sport << 16) | dport;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 a = 0, b = 0;
        __builtin_memcpy(&a, src + i * 4, 4);
        __builtin_memcpy(&b, dst + i * 4, 4);
        h = mix32(h ^ a ^ mix32(b));
    }
    return mix32(h ^ ((__u32)protocol << 24));
}


static __always_inline int addr6_equal(const __u8 *a, const __u8 *b)
{
#pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 x = 0, y = 0;
        __builtin_memcpy(&x, a + i * 4, 4);
        __builtin_memcpy(&y, b + i * 4, 4);
        if (x != y)
            return 0;
    }
    return 1;
}

static __always_inline int nat4_same(
    const struct nat4_value *v, __u32 client, __u16 client_port,
    __u32 vip, __u16 vip_port, __u32 sid, __u32 bid)
{
    return v->client_address == client && v->client_port == client_port &&
           v->vip_address == vip && v->vip_port == vip_port &&
           v->service_id == sid && v->backend_id == bid;
}

static __always_inline int nat6_same(
    const struct nat6_value *v, const __u8 *client, __u16 client_port,
    const __u8 *vip, __u16 vip_port, __u32 sid, __u32 bid)
{
    return v->client_port == client_port && v->vip_port == vip_port &&
           v->service_id == sid && v->backend_id == bid &&
           addr6_equal(v->client_address, client) &&
           addr6_equal(v->vip_address, vip);
}

/* Reserve a reply tuple. Preserve the original source port when possible;
 * on collision use a bounded deterministic high-port probe. */
static __always_inline __u16 reserve_nat4(
    __u32 backend, __u32 reply_addr, __u16 backend_port, __u8 protocol,
    __u32 client, __u16 client_port, __u32 vip, __u16 vip_port,
    __u32 sid, __u32 bid, __u32 hash)
{
#pragma unroll
    for (int i = 0; i < FLUXVM_NAT_PORT_PROBES; i++) {
        __u16 port = i == 0 ? client_port :
            (__u16)(FLUXVM_NAT_PORT_MIN +
                    ((hash + (__u32)i * 7919u) % FLUXVM_NAT_PORT_SPAN));
        if (port == 0)
            continue;
        struct nat4_key key = {
            .backend_address = backend,
            .reply_address = reply_addr,
            .backend_port = backend_port,
            .reply_port = port,
            .protocol = protocol,
            .pad = {0, 0, 0},
        };
        struct nat4_value *hit = bpf_map_lookup_elem(&fluxvm_nat4, &key);
        if (hit) {
            if (nat4_same(hit, client, client_port, vip, vip_port, sid, bid)) {
                hit->last_seen_ns = bpf_ktime_get_ns();
                return port;
            }
            continue;
        }
        struct nat4_value value = {
            .service_id = sid,
            .backend_id = bid,
            .client_address = client,
            .vip_address = vip,
            .last_seen_ns = bpf_ktime_get_ns(),
            .vip_port = vip_port,
            .client_port = client_port,
            .pad = 0,
        };
        if (bpf_map_update_elem(&fluxvm_nat4, &key, &value, BPF_NOEXIST) == 0) {
            fluxvm_ha_nat4(sid, bid, FLUXVM_HA_OP_UPSERT, protocol, &key, &value);
            return port;
        }
        hit = bpf_map_lookup_elem(&fluxvm_nat4, &key);
        if (hit && nat4_same(hit, client, client_port, vip, vip_port, sid, bid))
            return port;
    }
    return 0;
}

static __always_inline __u16 reserve_nat6(
    const __u8 *backend, const __u8 *reply_addr, __u16 backend_port, __u8 protocol,
    const __u8 *client, __u16 client_port, const __u8 *vip, __u16 vip_port,
    __u32 sid, __u32 bid, __u32 hash)
{
    struct nat6_key *key = nat6_key_scratch();
    struct nat6_value *value = nat6_val_scratch();
    if (!key || !value)
        return 0;
#pragma unroll
    for (int i = 0; i < FLUXVM_NAT_PORT_PROBES; i++) {
        __u16 port = i == 0 ? client_port :
            (__u16)(FLUXVM_NAT_PORT_MIN +
                    ((hash + (__u32)i * 7919u) % FLUXVM_NAT_PORT_SPAN));
        if (port == 0)
            continue;
        __builtin_memset(key, 0, sizeof(*key));
        key->backend_port = backend_port;
        key->reply_port = port;
        key->protocol = protocol;
        __builtin_memcpy(key->backend_address, backend, 16);
        __builtin_memcpy(key->reply_address, reply_addr, 16);
        struct nat6_value *hit = bpf_map_lookup_elem(&fluxvm_nat6, key);
        if (hit) {
            if (nat6_same(hit, client, client_port, vip, vip_port, sid, bid)) {
                hit->last_seen_ns = bpf_ktime_get_ns();
                return port;
            }
            continue;
        }
        __builtin_memset(value, 0, sizeof(*value));
        value->service_id = sid;
        value->backend_id = bid;
        value->last_seen_ns = bpf_ktime_get_ns();
        value->vip_port = vip_port;
        value->client_port = client_port;
        __builtin_memcpy(value->client_address, client, 16);
        __builtin_memcpy(value->vip_address, vip, 16);
        if (bpf_map_update_elem(&fluxvm_nat6, key, value, BPF_NOEXIST) == 0) {
            fluxvm_ha_nat6(sid, bid, FLUXVM_HA_OP_UPSERT, protocol, key, value);
            return port;
        }
        hit = bpf_map_lookup_elem(&fluxvm_nat6, key);
        if (hit && nat6_same(hit, client, client_port, vip, vip_port, sid, bid))
            return port;
    }
    return 0;
}

static __always_inline int parse_ports4(
    struct iphdr *iph, void *data_end, __u16 *sport, __u16 *dport,
    __u32 *l4_off, int *udp_csum)
{
    void *l4 = (void *)iph + iph->ihl * 4;
    *l4_off = ETH_HLEN + iph->ihl * 4;
    *udp_csum = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(tcp->source);
        *dport = bpf_ntohs(tcp->dest);
        return 1;
    }
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(udp->source);
        *dport = bpf_ntohs(udp->dest);
        *udp_csum = udp->check != 0;
        return 1;
    }
    return 0;
}

static __always_inline int parse_ports6(
    struct ipv6hdr *ip6, void *data_end, __u16 *sport, __u16 *dport,
    __u32 *l4_off, int *udp_csum)
{
    void *l4 = (void *)(ip6 + 1);
    *l4_off = ETH_HLEN + sizeof(*ip6);
    *udp_csum = 0;
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(tcp->source);
        *dport = bpf_ntohs(tcp->dest);
        return 1;
    }
    if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(udp->source);
        *dport = bpf_ntohs(udp->dest);
        *udp_csum = 1; /* IPv6 UDP checksum is mandatory. */
        return 1;
    }
    return 0;
}

static __always_inline int rewrite4(
    struct __sk_buff *skb, __u32 l4_off, __u8 protocol, int udp_csum,
    __u32 old_src, __u32 new_src, __u32 old_dst, __u32 new_dst,
    __u16 old_sport, __u16 new_sport, __u16 old_dport, __u16 new_dport)
{
    __u32 check_off = l4_off +
        (protocol == IPPROTO_TCP ? offsetof(struct tcphdr, check)
                                 : offsetof(struct udphdr, check));
    __u64 mark = protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0;
    if (protocol == IPPROTO_TCP || udp_csum) {
        if (old_src != new_src && bpf_l4_csum_replace(
                skb, check_off, old_src, new_src,
                BPF_F_PSEUDO_HDR | mark | sizeof(__u32)) < 0)
            return -1;
        if (old_dst != new_dst && bpf_l4_csum_replace(
                skb, check_off, old_dst, new_dst,
                BPF_F_PSEUDO_HDR | mark | sizeof(__u32)) < 0)
            return -1;
        __u16 os = bpf_htons(old_sport), ns = bpf_htons(new_sport);
        __u16 od = bpf_htons(old_dport), nd = bpf_htons(new_dport);
        if (os != ns && bpf_l4_csum_replace(skb, check_off, os, ns, mark | sizeof(__u16)) < 0)
            return -1;
        if (od != nd && bpf_l4_csum_replace(skb, check_off, od, nd, mark | sizeof(__u16)) < 0)
            return -1;
    }
    if (old_src != new_src && bpf_l3_csum_replace(
            skb, ETH_HLEN + offsetof(struct iphdr, check), old_src, new_src,
            sizeof(__u32)) < 0)
        return -1;
    if (old_dst != new_dst && bpf_l3_csum_replace(
            skb, ETH_HLEN + offsetof(struct iphdr, check), old_dst, new_dst,
            sizeof(__u32)) < 0)
        return -1;

    if (old_src != new_src && bpf_skb_store_bytes(
            skb, ETH_HLEN + offsetof(struct iphdr, saddr), &new_src, sizeof(new_src), 0) < 0)
        return -1;
    if (old_dst != new_dst && bpf_skb_store_bytes(
            skb, ETH_HLEN + offsetof(struct iphdr, daddr), &new_dst, sizeof(new_dst), 0) < 0)
        return -1;
    __u16 ns = bpf_htons(new_sport), nd = bpf_htons(new_dport);
    if (old_sport != new_sport && bpf_skb_store_bytes(skb, l4_off, &ns, sizeof(ns), 0) < 0)
        return -1;
    if (old_dport != new_dport && bpf_skb_store_bytes(
            skb, l4_off + sizeof(__u16), &nd, sizeof(nd), 0) < 0)
        return -1;
    return 0;
}

static __always_inline int checksum_addr6(
    struct __sk_buff *skb, __u32 check_off, const __u8 *old, const __u8 *new,
    __u64 flags)
{
#pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 a = 0, b = 0;
        __builtin_memcpy(&a, old + i * 4, 4);
        __builtin_memcpy(&b, new + i * 4, 4);
        if (a != b && bpf_l4_csum_replace(
                skb, check_off, a, b, BPF_F_PSEUDO_HDR | flags | sizeof(__u32)) < 0)
            return -1;
    }
    return 0;
}

static __always_inline int rewrite6(
    struct __sk_buff *skb, __u32 l4_off, __u8 protocol,
    const __u8 *old_src, const __u8 *new_src,
    const __u8 *old_dst, const __u8 *new_dst,
    __u16 old_sport, __u16 new_sport, __u16 old_dport, __u16 new_dport)
{
    __u32 check_off = l4_off +
        (protocol == IPPROTO_TCP ? offsetof(struct tcphdr, check)
                                 : offsetof(struct udphdr, check));
    __u64 mark = protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0;
    if (checksum_addr6(skb, check_off, old_src, new_src, mark) < 0 ||
        checksum_addr6(skb, check_off, old_dst, new_dst, mark) < 0)
        return -1;
    __u16 os = bpf_htons(old_sport), ns = bpf_htons(new_sport);
    __u16 od = bpf_htons(old_dport), nd = bpf_htons(new_dport);
    if (os != ns && bpf_l4_csum_replace(skb, check_off, os, ns, mark | sizeof(__u16)) < 0)
        return -1;
    if (od != nd && bpf_l4_csum_replace(skb, check_off, od, nd, mark | sizeof(__u16)) < 0)
        return -1;

    if (bpf_skb_store_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), new_src, 16, 0) < 0)
        return -1;
    if (bpf_skb_store_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr), new_dst, 16, 0) < 0)
        return -1;
    if (old_sport != new_sport && bpf_skb_store_bytes(skb, l4_off, &ns, sizeof(ns), 0) < 0)
        return -1;
    if (old_dport != new_dport && bpf_skb_store_bytes(
            skb, l4_off + sizeof(__u16), &nd, sizeof(nd), 0) < 0)
        return -1;
    return 0;
}

static __always_inline int fib_redirect4(
    struct __sk_buff *skb, __u32 route_dst, __u32 src,
    __u8 protocol, __u16 sport, __u16 dport)
{
    struct bpf_fib_lookup *fib = fib_scratch();
    if (!fib)
        return TC_ACT_SHOT;
    __builtin_memset(fib, 0, sizeof(*fib));
    fib->family = FLUXVM_AF_INET;
    fib->ifindex = skb->ifindex;
    fib->ipv4_src = src;
    fib->ipv4_dst = route_dst;
    fib->l4_protocol = protocol;
    fib->sport = bpf_htons(sport);
    fib->dport = bpf_htons(dport);
    int rc = bpf_fib_lookup(skb, fib, sizeof(*fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return TC_ACT_SHOT;
    if (bpf_skb_store_bytes(skb, 0, fib->dmac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(skb, ETH_ALEN, fib->smac, ETH_ALEN, 0) < 0)
        return TC_ACT_SHOT;
    return bpf_redirect(fib->ifindex, 0);
}

static __always_inline int fib_redirect6(
    struct __sk_buff *skb, const __u8 *route_dst, const __u8 *src,
    __u8 protocol, __u16 sport, __u16 dport)
{
    struct bpf_fib_lookup *fib = fib_scratch();
    if (!fib)
        return TC_ACT_SHOT;
    __builtin_memset(fib, 0, sizeof(*fib));
    fib->family = FLUXVM_AF_INET6;
    fib->ifindex = skb->ifindex;
    __builtin_memcpy(fib->ipv6_src, src, 16);
    __builtin_memcpy(fib->ipv6_dst, route_dst, 16);
    fib->l4_protocol = protocol;
    fib->sport = bpf_htons(sport);
    fib->dport = bpf_htons(dport);
    int rc = bpf_fib_lookup(skb, fib, sizeof(*fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return TC_ACT_SHOT;
    if (bpf_skb_store_bytes(skb, 0, fib->dmac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(skb, ETH_ALEN, fib->smac, ETH_ALEN, 0) < 0)
        return TC_ACT_SHOT;
    return bpf_redirect(fib->ifindex, 0);
}

static __always_inline int fib_redirect4_soft(
    struct __sk_buff *skb, __u32 route_dst, __u32 src,
    __u8 protocol, __u16 sport, __u16 dport)
{
    struct bpf_fib_lookup *fib = fib_scratch();
    if (!fib)
        return TC_ACT_UNSPEC;
    __builtin_memset(fib, 0, sizeof(*fib));
    fib->family = FLUXVM_AF_INET;
    fib->ifindex = skb->ifindex;
    fib->ipv4_src = src;
    fib->ipv4_dst = route_dst;
    fib->l4_protocol = protocol;
    fib->sport = bpf_htons(sport);
    fib->dport = bpf_htons(dport);
    int rc = bpf_fib_lookup(skb, fib, sizeof(*fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) return TC_ACT_UNSPEC;
    if (bpf_skb_store_bytes(skb, 0, fib->dmac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(skb, ETH_ALEN, fib->smac, ETH_ALEN, 0) < 0)
        return TC_ACT_SHOT;
    return bpf_redirect(fib->ifindex, 0);
}

static __always_inline int fib_redirect6_soft(
    struct __sk_buff *skb, const __u8 *route_dst, const __u8 *src,
    __u8 protocol, __u16 sport, __u16 dport)
{
    struct bpf_fib_lookup *fib = fib_scratch();
    if (!fib)
        return TC_ACT_UNSPEC;
    __builtin_memset(fib, 0, sizeof(*fib));
    fib->family = FLUXVM_AF_INET6;
    fib->ifindex = skb->ifindex;
    __builtin_memcpy(fib->ipv6_src, src, 16);
    __builtin_memcpy(fib->ipv6_dst, route_dst, 16);
    fib->l4_protocol = protocol;
    fib->sport = bpf_htons(sport);
    fib->dport = bpf_htons(dport);
    int rc = bpf_fib_lookup(skb, fib, sizeof(*fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) return TC_ACT_UNSPEC;
    if (bpf_skb_store_bytes(skb, 0, fib->dmac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(skb, ETH_ALEN, fib->smac, ETH_ALEN, 0) < 0)
        return TC_ACT_SHOT;
    return bpf_redirect(fib->ifindex, 0);
}

static __always_inline int reverse4(
    struct __sk_buff *skb, struct iphdr *iph, void *data_end)
{
    __u16 sport = 0, dport = 0;
    __u32 l4_off = 0;
    int udp_csum = 0;
    int parsed = parse_ports4(iph, data_end, &sport, &dport, &l4_off, &udp_csum);
    if (parsed <= 0)
        return 0;
    struct nat4_key key = {
        .backend_address = iph->saddr,
        .reply_address = iph->daddr,
        .backend_port = sport,
        .reply_port = dport,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };
    struct nat4_value *nat = bpf_map_lookup_elem(&fluxvm_nat4, &key);
    if (!nat)
        return 0;

    __u32 sid = nat->service_id;
    __u32 bid = nat->backend_id;
    __u64 now = bpf_ktime_get_ns();
    nat->last_seen_ns = now;
    struct fct4_key fkey = {
        .client_address = nat->client_address,
        .vip_address = nat->vip_address,
        .client_port = nat->client_port,
        .vip_port = nat->vip_port,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };
    struct fct_value fvalue = {
        .service_id = sid,
        .backend_id = bid,
        .last_seen_ns = now,
        .expires_at_ns = now + timeout4(iph, data_end),
    };
    bpf_map_update_elem(&fluxvm_fct4, &fkey, &fvalue, BPF_ANY);

    __u32 old_src = iph->saddr, old_dst = iph->daddr;
    __u32 new_src = nat->vip_address, new_dst = nat->client_address;
    __u16 new_sport = nat->vip_port, new_dport = nat->client_port;
    if (rewrite4(
            skb, l4_off, iph->protocol, udp_csum,
            old_src, new_src, old_dst, new_dst,
            sport, new_sport, dport, new_dport) < 0)
        return -1;
    count_reverse(sid);
    return 1;
}

static __always_inline int reverse6(
    struct __sk_buff *skb, struct ipv6hdr *ip6, void *data_end)
{
    __u16 sport = 0, dport = 0;
    __u32 l4_off = 0;
    int udp_csum = 0;
    int parsed = parse_ports6(ip6, data_end, &sport, &dport, &l4_off, &udp_csum);
    if (parsed <= 0)
        return 0;
    struct nat6_key *key = nat6_key_scratch();
    if (!key)
        return 0;
    __builtin_memset(key, 0, sizeof(*key));
    key->backend_port = sport;
    key->reply_port = dport;
    key->protocol = ip6->nexthdr;
    __builtin_memcpy(key->backend_address, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(key->reply_address, ip6->daddr.in6_u.u6_addr8, 16);
    struct nat6_value *nat = bpf_map_lookup_elem(&fluxvm_nat6, key);
    if (!nat)
        return 0;

    __u32 sid = nat->service_id;
    __u32 bid = nat->backend_id;
    __u64 now = bpf_ktime_get_ns();
    nat->last_seen_ns = now;
    struct fct6_key *fkey = fct6_key_scratch();
    if (!fkey)
        return -1;
    __builtin_memset(fkey, 0, sizeof(*fkey));
    fkey->client_port = nat->client_port;
    fkey->vip_port = nat->vip_port;
    fkey->protocol = ip6->nexthdr;
    __builtin_memcpy(fkey->client_address, nat->client_address, 16);
    __builtin_memcpy(fkey->vip_address, nat->vip_address, 16);
    struct fct_value fvalue = {
        .service_id = sid,
        .backend_id = bid,
        .last_seen_ns = now,
        .expires_at_ns = now + timeout6(ip6, data_end),
    };
    bpf_map_update_elem(&fluxvm_fct6, fkey, &fvalue, BPF_ANY);

    __u8 old_src[16], old_dst[16], new_dst[16];
    __builtin_memcpy(old_src, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(old_dst, ip6->daddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(new_dst, nat->client_address, 16);
    __u16 new_sport = nat->vip_port;
    __u16 new_dport = nat->client_port;
    if (rewrite6(
            skb, l4_off, ip6->nexthdr,
            old_src, nat->vip_address, old_dst, new_dst,
            sport, new_sport, dport, new_dport) < 0)
        return -1;
    count_reverse(sid);
    return 1;
}

static __always_inline int forward4(
    struct __sk_buff *skb, struct iphdr *iph, void *data_end)
{
    if ((bpf_ntohs(iph->frag_off) & 0x3fff) != 0)
        return TC_ACT_UNSPEC;
    __u16 sport = 0, dport = 0;
    __u32 l4_off = 0;
    int udp_csum = 0;
    int parsed = parse_ports4(iph, data_end, &sport, &dport, &l4_off, &udp_csum);
    if (parsed <= 0)
        return TC_ACT_UNSPEC;

    struct svc4_key skey = {
        .address = iph->daddr,
        .port = dport,
        .protocol = iph->protocol,
        .pad = 0,
    };
    struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc4, &skey);
    if (!svc)
        return TC_ACT_UNSPEC;
    __u32 sid = svc->service_id;
    int policy_action = fluxvm_policy4_tc(skb, sid, iph->saddr, iph->protocol);
    if (policy_action != TC_ACT_UNSPEC)
        return policy_action;
    __u32 original_src = iph->saddr, original_dst = iph->daddr;
    __u8 original_protocol = iph->protocol;
    __u32 bid = 0;
    int pinned = affinity4(sid, iph, data_end, sport, dport, &bid);
    __u32 h = flow_hash4(iph->saddr, iph->daddr, sport, dport, iph->protocol);
    if (!pinned) {
        if (svc->table_size == 0) {
            count_miss(sid); record_flow4(skb, svc, 0xffffffffu, iph, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_NO_MAGLEV);
            return TC_ACT_SHOT;
        }
        struct maglev_key mkey = {.service_id = sid, .slot = h % svc->table_size};
        __u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
        if (!backend_id) {
            count_miss(sid); record_flow4(skb, svc, 0xffffffffu, iph, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_NO_MAGLEV);
            return TC_ACT_SHOT;
        }
        bid = *backend_id;
    }
    struct backend_key bkey = {.service_id = sid, .backend_id = bid};
    struct backend4_value *backend = bpf_map_lookup_elem(&fluxvm_backend4, &bkey);
    if (!backend || (backend->flags & FLUXVM_SVC_BACKEND_UNHEALTHY) ||
        (pinned && !(backend->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING))) ||
        (!pinned && !(backend->flags & FLUXVM_SVC_BACKEND_READY))) {
        count_miss(sid);
        backend_failure(sid, bid);
        record_flow4(skb, svc, bid, iph, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_BACKEND_UNHEALTHY);
        return TC_ACT_SHOT;
    }

    if (svc->mode == FLUXVM_SVC_MODE_DSR) {
        __u32 src4 = iph->saddr;
        __u8 proto4 = iph->protocol;
        /* Learn before fib_redirect: skb helpers invalidate packet pointers. */
        if (!pinned)
            learn_affinity4(sid, bid, iph, data_end, sport, dport);
        int action = fib_redirect4(
            skb, backend->address, src4, proto4, sport, dport);
        if (action == TC_ACT_SHOT) {
            count_miss(sid); backend_failure(sid, bid);
            record_flow4_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_DROP, FLUXVM_REASON_NO_BACKEND);
        } else {
            backend_success(sid, bid);
            apply_edt(skb, sid, svc);
            record_flow4_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_ALLOW, FLUXVM_REASON_NONE);
            count_forward(sid, skb->len, 1, 0);
        }
        return action;
    }
    if (svc->mode != FLUXVM_SVC_MODE_NAT) {
        count_miss(sid); record_flow4(skb, svc, bid, iph, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_BAD_MODE);
        return TC_ACT_SHOT;
    }

    __u32 old_src = iph->saddr, old_dst = iph->daddr;
    __u8 proto4 = iph->protocol;
    __u32 new_src = old_src;
    __u16 flags = 0;
    struct snat4_value *snat = bpf_map_lookup_elem(&fluxvm_snat4, &sid);
    if (snat && snat->enabled) {
        new_src = snat->address;
        flags |= FLUXVM_NAT_F_SNAT;
    }
    __u16 reply_port = reserve_nat4(
        backend->address, new_src, backend->port, proto4,
        old_src, sport, old_dst, dport, sid, bid, h);
    if (!reply_port) {
        count_miss(sid); record_flow4(skb, svc, bid, iph, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_NAT_EXHAUSTED);
        return TC_ACT_SHOT;
    }
    if (!pinned)
        learn_affinity4(sid, bid, iph, data_end, sport, dport);
    if (rewrite4(
            skb, l4_off, proto4, udp_csum,
            old_src, new_src, old_dst, backend->address,
            sport, reply_port, dport, backend->port) < 0) {
        if (!pinned)
            delete_affinity4(old_src, old_dst, sport, dport, proto4);
        count_miss(sid); record_flow4_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_DROP, FLUXVM_REASON_REWRITE_FAILED);
        return TC_ACT_SHOT;
    }
    backend_success(sid, bid);
    apply_edt(skb, sid, svc);
    record_flow4_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_ALLOW, FLUXVM_REASON_NONE);
    count_forward(sid, skb->len, 0, flags != 0);
    if (svc->flags & FLUXVM_SVC_F_HOST_ROUTING) {
        int action = fib_redirect4_soft(skb, backend->address, new_src, original_protocol, reply_port, backend->port);
        /* After DNAT, stop the clsact chain so sandbox policy does not
         * re-filter the rewritten backend port/address. */
        if (action == TC_ACT_UNSPEC) { count_host_route(sid, 0); return TC_ACT_OK; }
        if (action == TC_ACT_SHOT) { count_miss(sid); return TC_ACT_SHOT; }
        count_host_route(sid, 1); return action;
    }
    return TC_ACT_OK;
}

static __always_inline int forward6(
    struct __sk_buff *skb, struct ipv6hdr *ip6, void *data_end)
{
    __u16 sport = 0, dport = 0;
    __u32 l4_off = 0;
    int udp_csum = 0;
    int parsed = parse_ports6(ip6, data_end, &sport, &dport, &l4_off, &udp_csum);
    if (parsed <= 0)
        return TC_ACT_UNSPEC;

    struct svc6_key skey = {.port = dport, .protocol = ip6->nexthdr, .pad = 0};
    __builtin_memcpy(skey.address, ip6->daddr.in6_u.u6_addr8, 16);
    struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc6, &skey);
    if (!svc)
        return TC_ACT_UNSPEC;
    __u32 sid = svc->service_id;
    int policy_action = fluxvm_policy6_tc(skb, sid, ip6->saddr.in6_u.u6_addr8, ip6->nexthdr);
    if (policy_action != TC_ACT_UNSPEC)
        return policy_action;
    __u8 original_src[16], original_dst[16];
    __builtin_memcpy(original_src, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(original_dst, ip6->daddr.in6_u.u6_addr8, 16);
    __u8 original_protocol = ip6->nexthdr;
    __u32 bid = 0;
    int pinned = affinity6(sid, ip6, data_end, sport, dport, &bid);
    __u32 h = hash_words6(
        ip6->saddr.in6_u.u6_addr8, ip6->daddr.in6_u.u6_addr8,
        sport, dport, ip6->nexthdr);
    if (!pinned) {
        if (svc->table_size == 0) {
            count_miss(sid); record_flow6(skb, svc, 0xffffffffu, ip6, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_NO_MAGLEV);
            return TC_ACT_SHOT;
        }
        struct maglev_key mkey = {.service_id = sid, .slot = h % svc->table_size};
        __u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
        if (!backend_id) {
            count_miss(sid); record_flow6(skb, svc, 0xffffffffu, ip6, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_NO_MAGLEV);
            return TC_ACT_SHOT;
        }
        bid = *backend_id;
    }
    struct backend_key bkey = {.service_id = sid, .backend_id = bid};
    struct backend6_value *backend = bpf_map_lookup_elem(&fluxvm_backend6, &bkey);
    if (!backend || (backend->flags & FLUXVM_SVC_BACKEND_UNHEALTHY) ||
        (pinned && !(backend->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING))) ||
        (!pinned && !(backend->flags & FLUXVM_SVC_BACKEND_READY))) {
        count_miss(sid);
        backend_failure(sid, bid);
        record_flow6(skb, svc, bid, ip6, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_BACKEND_UNHEALTHY);
        return TC_ACT_SHOT;
    }

    if (svc->mode == FLUXVM_SVC_MODE_DSR) {
        __u8 proto6 = ip6->nexthdr;
        /* Learn before fib_redirect: skb helpers invalidate packet pointers. */
        if (!pinned)
            learn_affinity6(sid, bid, ip6, data_end, sport, dport);
        int action = fib_redirect6(
            skb, backend->address, original_src, proto6, sport, dport);
        if (action == TC_ACT_SHOT) {
            count_miss(sid); backend_failure(sid, bid);
            record_flow6_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_DROP, FLUXVM_REASON_NO_BACKEND);
        } else {
            backend_success(sid, bid);
            apply_edt(skb, sid, svc);
            record_flow6_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_ALLOW, FLUXVM_REASON_NONE);
            count_forward(sid, skb->len, 1, 0);
        }
        return action;
    }
    if (svc->mode != FLUXVM_SVC_MODE_NAT) {
        count_miss(sid); record_flow6(skb, svc, bid, ip6, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_BAD_MODE);
        return TC_ACT_SHOT;
    }

    __u8 new_src[16];
    __u8 proto6 = ip6->nexthdr;
    __builtin_memcpy(new_src, original_src, 16);
    __u16 flags = 0;
    struct snat6_value *snat = bpf_map_lookup_elem(&fluxvm_snat6, &sid);
    if (snat && snat->enabled) {
        __builtin_memcpy(new_src, snat->address, 16);
        flags |= FLUXVM_NAT_F_SNAT;
    }
    __u16 reply_port = reserve_nat6(
        backend->address, new_src, backend->port, proto6,
        original_src, sport, original_dst, dport, sid, bid, h);
    if (!reply_port) {
        count_miss(sid); record_flow6(skb, svc, bid, ip6, sport, dport, FLUXVM_FLOW_DROP, FLUXVM_REASON_NAT_EXHAUSTED);
        return TC_ACT_SHOT;
    }
    if (!pinned)
        learn_affinity6(sid, bid, ip6, data_end, sport, dport);
    if (rewrite6(
            skb, l4_off, proto6,
            original_src, new_src, original_dst, backend->address,
            sport, reply_port, dport, backend->port) < 0) {
        if (!pinned)
            delete_affinity6(original_src, original_dst, sport, dport, proto6);
        count_miss(sid); record_flow6_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_DROP, FLUXVM_REASON_REWRITE_FAILED);
        return TC_ACT_SHOT;
    }
    backend_success(sid, bid);
    apply_edt(skb, sid, svc);
    record_flow6_raw(skb, svc, bid, original_src, original_dst, sport, dport, original_protocol, FLUXVM_FLOW_ALLOW, FLUXVM_REASON_NONE);
    count_forward(sid, skb->len, 0, flags != 0);
    if (svc->flags & FLUXVM_SVC_F_HOST_ROUTING) {
        int action = fib_redirect6_soft(skb, backend->address, new_src, original_protocol, reply_port, backend->port);
        /* After DNAT, stop the clsact chain so sandbox policy does not
         * re-filter the rewritten backend port/address. */
        if (action == TC_ACT_UNSPEC) { count_host_route(sid, 0); return TC_ACT_OK; }
        if (action == TC_ACT_SHOT) { count_miss(sid); return TC_ACT_SHOT; }
        count_host_route(sid, 1); return action;
    }
    return TC_ACT_OK;
}

static __always_inline int service_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    __u16 proto = bpf_ntohs(eth->h_proto);

    if (update_guard_enabled() && (proto == ETH_P_IP || proto == ETH_P_IPV6))
        return TC_ACT_SHOT;

    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end || iph->ihl < 5 ||
            (void *)iph + iph->ihl * 4 > data_end)
            return TC_ACT_UNSPEC;
        if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
            return TC_ACT_UNSPEC;
        int rev = reverse4(skb, iph, data_end);
        if (rev < 0)
            return TC_ACT_SHOT;
        if (rev > 0)
            return TC_ACT_OK;
        return forward4(skb, iph, data_end);
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_UNSPEC;
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return TC_ACT_UNSPEC;
        int rev = reverse6(skb, ip6, data_end);
        if (rev < 0)
            return TC_ACT_SHOT;
        if (rev > 0)
            return TC_ACT_OK;
        return forward6(skb, ip6, data_end);
    }
    return TC_ACT_UNSPEC;
}

static __always_inline int service_reverse_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;
    __u16 proto = bpf_ntohs(eth->h_proto);

    if (update_guard_enabled() && (proto == ETH_P_IP || proto == ETH_P_IPV6))
        return TC_ACT_SHOT;

    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end || iph->ihl < 5 ||
            (void *)iph + iph->ihl * 4 > data_end)
            return TC_ACT_UNSPEC;
        if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
            return TC_ACT_UNSPEC;
        int rev = reverse4(skb, iph, data_end);
        if (rev < 0)
            return TC_ACT_SHOT;
        if (rev > 0)
            return TC_ACT_OK;
        return TC_ACT_UNSPEC;
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_UNSPEC;
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return TC_ACT_UNSPEC;
        int rev = reverse6(skb, ip6, data_end);
        if (rev < 0)
            return TC_ACT_SHOT;
        if (rev > 0)
            return TC_ACT_OK;
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}

SEC("tc")
int fvm_svc_vm(struct __sk_buff *skb)
{
    return service_tc(skb);
}

SEC("tc")
int fvm_svc_host(struct __sk_buff *skb)
{
    return service_tc(skb);
}

/* Same map instance, egress hook: return traffic sees the NAT entry created
 * on ingress before it leaves the client/uplink interface. */
SEC("tc")
int fvm_svc_rev(struct __sk_buff *skb)
{
    return service_reverse_tc(skb);
}

char LICENSE[] SEC("license") = "GPL";
