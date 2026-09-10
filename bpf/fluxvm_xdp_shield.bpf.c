// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM XDP Shield v1.
//
// This program is intentionally not auto-attached to a shared node uplink.
// It is for a dedicated/explicit ingress interface whose protected VM IPs are
// supplied by userspace.  The loader refuses to replace an existing XDP
// owner, including Cilium.  Policy maps are generation keyed and the config
// generation is published last, so policy replacement is atomic.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_SHIELD_MODE_OFF      0u
#define FLUXVM_SHIELD_MODE_AUDIT    1u
#define FLUXVM_SHIELD_MODE_ENFORCE  2u

#define FLUXVM_SHIELD_ACTION_PASS   0u
#define FLUXVM_SHIELD_ACTION_DROP   1u
#define FLUXVM_SHIELD_ACTION_AUDIT  2u

#define FLUXVM_SHIELD_REASON_PASS             0u
#define FLUXVM_SHIELD_REASON_EXPLICIT_DENY    1u
#define FLUXVM_SHIELD_REASON_SYN_RATE         2u
#define FLUXVM_SHIELD_REASON_UDP_RATE         3u
#define FLUXVM_SHIELD_REASON_ICMP_RATE        4u
#define FLUXVM_SHIELD_REASON_OTHER_RATE       5u
#define FLUXVM_SHIELD_REASON_BUCKET_EXHAUSTED 6u
#define FLUXVM_SHIELD_REASON_MALFORMED        7u

#define FLUXVM_SHIELD_CLASS_SYN    1u
#define FLUXVM_SHIELD_CLASS_UDP    2u
#define FLUXVM_SHIELD_CLASS_ICMP   3u
#define FLUXVM_SHIELD_CLASS_OTHER  4u

#define FLUXVM_AF_INET   4u
#define FLUXVM_AF_INET6  6u
#define FLUXVM_NS_PER_SEC 1000000000ULL

struct shield_config {
    __u32 generation;
    __u32 mode;
    __u32 protect_all;
    __u32 syn_pps;
    __u32 udp_pps;
    __u32 icmp_pps;
    __u32 other_pps;
    __u32 burst_seconds;
    __u32 sample_rate;
    __u32 reserved0;
};
_Static_assert(sizeof(struct shield_config) == 40, "shield config ABI");

struct protected4_key {
    __u32 generation;
    __u32 addr;
};

struct protected6_key {
    __u32 generation;
    __u8 addr[16];
};

struct cidr4_key {
    __u32 prefixlen;
    __u32 generation;
    __u32 addr;
};

struct cidr6_key {
    __u32 prefixlen;
    __u32 generation;
    __u8 addr[16];
};

struct source_key {
    __u8 family;
    __u8 class_id;
    __u16 reserved0;
    __u8 addr[16];
};
_Static_assert(sizeof(struct source_key) == 20, "shield source key ABI");

struct source_state {
    struct bpf_spin_lock lock;
    __u32 reserved0;
    __u64 last_refill_ns;
    __u64 tokens;
    __u64 last_seen_ns;
};
_Static_assert(sizeof(struct source_state) == 32, "shield source state ABI");

struct shield_stat_key {
    __u32 generation;
    __u32 reason;
    __u32 action;
};

struct shield_stat_value {
    __u64 packets;
    __u64 bytes;
};

struct shield_event {
    __u64 timestamp_ns;
    __u32 generation;
    __u32 ifindex;
    __u32 reason;
    __u32 action;
    __u8 family;
    __u8 class_id;
    __u8 protocol;
    __u8 reserved0;
    __u8 source[16];
    __u8 destination[16];
    __u16 source_port;
    __u16 destination_port;
    __u32 bytes;
};
_Static_assert(sizeof(struct shield_event) == 72, "shield event ABI");

struct fluxvm_vlan_hdr {
    __be16 tci;
    __be16 encap_proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_config);
} fluxvm_shield_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct protected4_key);
    __type(value, __u32);
} fluxvm_shield_protected4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct protected6_key);
    __type(value, __u32);
} fluxvm_shield_protected6 SEC(".maps");

#define DEFINE_CIDR4_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
    __uint(max_entries, 8192); \
    __type(key, struct cidr4_key); \
    __type(value, __u32); \
} name SEC(".maps")

#define DEFINE_CIDR6_MAP(name) \
struct { \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
    __uint(max_entries, 8192); \
    __type(key, struct cidr6_key); \
    __type(value, __u32); \
} name SEC(".maps")

DEFINE_CIDR4_MAP(fluxvm_shield_allow4);
DEFINE_CIDR4_MAP(fluxvm_shield_deny4);
DEFINE_CIDR6_MAP(fluxvm_shield_allow6);
DEFINE_CIDR6_MAP(fluxvm_shield_deny6);

// Regular HASH is deliberate: bpf_spin_lock is supported for HASH/ARRAY map
// values, not LRU_HASH.  On source-map exhaustion, enforce mode fails closed
// for the protected packet instead of silently disabling flood protection.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65536);
    __type(key, struct source_key);
    __type(value, struct source_state);
} fluxvm_shield_sources SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct shield_stat_key);
    __type(value, struct shield_stat_value);
} fluxvm_shield_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fluxvm_shield_events SEC(".maps");

static __always_inline void stat_add(__u32 generation, __u32 reason, __u32 action, __u32 bytes)
{
    struct shield_stat_key key = {
        .generation = generation,
        .reason = reason,
        .action = action,
    };
    struct shield_stat_value *value = bpf_map_lookup_elem(&fluxvm_shield_stats, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, bytes);
        return;
    }
    struct shield_stat_value initial = {.packets = 1, .bytes = bytes};
    bpf_map_update_elem(&fluxvm_shield_stats, &key, &initial, BPF_NOEXIST);
}

static __always_inline __u32 class_rate(const struct shield_config *cfg, __u8 class_id)
{
    if (class_id == FLUXVM_SHIELD_CLASS_SYN)
        return cfg->syn_pps;
    if (class_id == FLUXVM_SHIELD_CLASS_UDP)
        return cfg->udp_pps;
    if (class_id == FLUXVM_SHIELD_CLASS_ICMP)
        return cfg->icmp_pps;
    return cfg->other_pps;
}

// 1 = token granted, 0 = rate limited, -1 = source-map insertion exhausted.
static __always_inline int source_token(const struct source_key *key, __u32 rate, __u32 burst_seconds)
{
    if (rate == 0)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    __u64 burst = (__u64)rate * (__u64)(burst_seconds ? burst_seconds : 1);
    if (burst == 0)
        burst = 1;

    struct source_state *state = bpf_map_lookup_elem(&fluxvm_shield_sources, key);
    if (!state) {
        struct source_state initial = {
            .last_refill_ns = now,
            .tokens = burst > 0 ? burst - 1 : 0,
            .last_seen_ns = now,
        };
        if (bpf_map_update_elem(&fluxvm_shield_sources, key, &initial, BPF_NOEXIST) == 0)
            return 1;
        state = bpf_map_lookup_elem(&fluxvm_shield_sources, key);
        if (!state)
            return -1;
    }

    int allowed = 0;
    bpf_spin_lock(&state->lock);
    __u64 elapsed = now - state->last_refill_ns;
    if (elapsed >= 60 * FLUXVM_NS_PER_SEC) {
        state->tokens = burst;
        state->last_refill_ns = now;
    } else if (elapsed > 0) {
        __u64 refill = (elapsed * (__u64)rate) / FLUXVM_NS_PER_SEC;
        if (refill > 0) {
            __u64 next = state->tokens + refill;
            state->tokens = next > burst ? burst : next;
            state->last_refill_ns = now;
        }
    }
    if (state->tokens > 0) {
        state->tokens--;
        allowed = 1;
    }
    state->last_seen_ns = now;
    bpf_spin_unlock(&state->lock);
    return allowed;
}

static __always_inline int protected4(const struct shield_config *cfg, __u32 addr)
{
    if (cfg->protect_all)
        return 1;
    struct protected4_key key = {.generation = cfg->generation, .addr = addr};
    __u32 *hit = bpf_map_lookup_elem(&fluxvm_shield_protected4, &key);
    return hit && *hit;
}

static __always_inline int protected6(const struct shield_config *cfg, const __u8 *addr)
{
    if (cfg->protect_all)
        return 1;
    struct protected6_key key = {.generation = cfg->generation};
    __builtin_memcpy(key.addr, addr, 16);
    __u32 *hit = bpf_map_lookup_elem(&fluxvm_shield_protected6, &key);
    return hit && *hit;
}

static __always_inline int cidr4_match(void *map, __u32 generation, __u32 addr)
{
    struct cidr4_key key = {.prefixlen = 64, .generation = generation, .addr = addr};
    __u32 *hit = bpf_map_lookup_elem(map, &key);
    return hit && *hit;
}

static __always_inline int cidr6_match(void *map, __u32 generation, const __u8 *addr)
{
    struct cidr6_key key = {.prefixlen = 160, .generation = generation};
    __builtin_memcpy(key.addr, addr, 16);
    __u32 *hit = bpf_map_lookup_elem(map, &key);
    return hit && *hit;
}

static __always_inline void emit_event(
    struct xdp_md *ctx,
    const struct shield_config *cfg,
    __u32 reason,
    __u32 action,
    __u8 family,
    __u8 class_id,
    __u8 protocol,
    const __u8 *source,
    const __u8 *destination,
    __u16 sport,
    __u16 dport,
    __u32 bytes)
{
    int emit = reason != FLUXVM_SHIELD_REASON_PASS;
    if (!emit && cfg->sample_rate > 0)
        emit = (bpf_get_prandom_u32() % cfg->sample_rate) == 0;
    if (!emit)
        return;
    struct shield_event *event = bpf_ringbuf_reserve(&fluxvm_shield_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->generation = cfg->generation;
    event->ifindex = ctx->ingress_ifindex;
    event->reason = reason;
    event->action = action;
    event->family = family;
    event->class_id = class_id;
    event->protocol = protocol;
    event->reserved0 = 0;
    __builtin_memcpy(event->source, source, 16);
    __builtin_memcpy(event->destination, destination, 16);
    event->source_port = sport;
    event->destination_port = dport;
    event->bytes = bytes;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int verdict(
    struct xdp_md *ctx,
    const struct shield_config *cfg,
    __u32 reason,
    __u8 family,
    __u8 class_id,
    __u8 protocol,
    const __u8 *source,
    const __u8 *destination,
    __u16 sport,
    __u16 dport,
    __u32 bytes)
{
    __u32 action = FLUXVM_SHIELD_ACTION_PASS;
    int result = XDP_PASS;
    if (reason != FLUXVM_SHIELD_REASON_PASS) {
        if (cfg->mode == FLUXVM_SHIELD_MODE_ENFORCE) {
            action = FLUXVM_SHIELD_ACTION_DROP;
            result = XDP_DROP;
        } else if (cfg->mode == FLUXVM_SHIELD_MODE_AUDIT) {
            action = FLUXVM_SHIELD_ACTION_AUDIT;
        }
    }
    stat_add(cfg->generation, reason, action, bytes);
    emit_event(ctx, cfg, reason, action, family, class_id, protocol,
               source, destination, sport, dport, bytes);
    return result;
}

static __always_inline int handle4(struct xdp_md *ctx, const struct shield_config *cfg,
                                   void *cursor, void *data_end, __u32 bytes)
{
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (!protected4(cfg, ip->daddr))
        return XDP_PASS;

    __u8 src[16] = {};
    __u8 dst[16] = {};
    __builtin_memcpy(src, &ip->saddr, 4);
    __builtin_memcpy(dst, &ip->daddr, 4);
    if (ip->ihl < 5)
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_MALFORMED,
                       FLUXVM_AF_INET, FLUXVM_SHIELD_CLASS_OTHER, ip->protocol,
                       src, dst, 0, 0, bytes);
    __u32 ihl = (__u32)ip->ihl * 4;
    if ((void *)ip + ihl > data_end)
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_MALFORMED,
                       FLUXVM_AF_INET, FLUXVM_SHIELD_CLASS_OTHER, ip->protocol,
                       src, dst, 0, 0, bytes);

    if (cidr4_match(&fluxvm_shield_deny4, cfg->generation, ip->saddr))
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_EXPLICIT_DENY,
                       FLUXVM_AF_INET, FLUXVM_SHIELD_CLASS_OTHER, ip->protocol,
                       src, dst, 0, 0, bytes);
    if (cidr4_match(&fluxvm_shield_allow4, cfg->generation, ip->saddr))
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_PASS,
                       FLUXVM_AF_INET, FLUXVM_SHIELD_CLASS_OTHER, ip->protocol,
                       src, dst, 0, 0, bytes);

    __u16 sport = 0, dport = 0;
    __u8 class_id = FLUXVM_SHIELD_CLASS_OTHER;
    __u16 frag = bpf_ntohs(ip->frag_off);
    int nonfirst_fragment = (frag & 0x1fff) != 0;
    void *l4 = (void *)ip + ihl;
    if (!nonfirst_fragment && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_MALFORMED,
                           FLUXVM_AF_INET, class_id, ip->protocol,
                           src, dst, 0, 0, bytes);
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        class_id = (tcp->syn && !tcp->ack) ? FLUXVM_SHIELD_CLASS_SYN : FLUXVM_SHIELD_CLASS_OTHER;
    } else if (!nonfirst_fragment && ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_MALFORMED,
                           FLUXVM_AF_INET, class_id, ip->protocol,
                           src, dst, 0, 0, bytes);
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        class_id = FLUXVM_SHIELD_CLASS_UDP;
    } else if (!nonfirst_fragment && ip->protocol == IPPROTO_ICMP) {
        class_id = FLUXVM_SHIELD_CLASS_ICMP;
    }

    struct source_key key = {.family = FLUXVM_AF_INET, .class_id = class_id};
    __builtin_memcpy(key.addr, src, 16);
    __u32 rate = class_rate(cfg, class_id);
    int token = source_token(&key, rate, cfg->burst_seconds);
    if (token > 0)
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_PASS,
                       FLUXVM_AF_INET, class_id, ip->protocol, src, dst, sport, dport, bytes);
    __u32 reason = token < 0 ? FLUXVM_SHIELD_REASON_BUCKET_EXHAUSTED :
                   class_id == FLUXVM_SHIELD_CLASS_SYN ? FLUXVM_SHIELD_REASON_SYN_RATE :
                   class_id == FLUXVM_SHIELD_CLASS_UDP ? FLUXVM_SHIELD_REASON_UDP_RATE :
                   class_id == FLUXVM_SHIELD_CLASS_ICMP ? FLUXVM_SHIELD_REASON_ICMP_RATE :
                   FLUXVM_SHIELD_REASON_OTHER_RATE;
    return verdict(ctx, cfg, reason, FLUXVM_AF_INET, class_id, ip->protocol,
                   src, dst, sport, dport, bytes);
}

static __always_inline int handle6(struct xdp_md *ctx, const struct shield_config *cfg,
                                   void *cursor, void *data_end, __u32 bytes)
{
    struct ipv6hdr *ip6 = cursor;
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;
    if (!protected6(cfg, ip6->daddr.in6_u.u6_addr8))
        return XDP_PASS;

    __u8 src[16] = {};
    __u8 dst[16] = {};
    __builtin_memcpy(src, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(dst, ip6->daddr.in6_u.u6_addr8, 16);

    if (cidr6_match(&fluxvm_shield_deny6, cfg->generation, src))
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_EXPLICIT_DENY,
                       FLUXVM_AF_INET6, FLUXVM_SHIELD_CLASS_OTHER, ip6->nexthdr,
                       src, dst, 0, 0, bytes);
    if (cidr6_match(&fluxvm_shield_allow6, cfg->generation, src))
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_PASS,
                       FLUXVM_AF_INET6, FLUXVM_SHIELD_CLASS_OTHER, ip6->nexthdr,
                       src, dst, 0, 0, bytes);

    __u16 sport = 0, dport = 0;
    __u8 class_id = FLUXVM_SHIELD_CLASS_OTHER;
    void *l4 = (void *)(ip6 + 1);
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_MALFORMED,
                           FLUXVM_AF_INET6, class_id, ip6->nexthdr,
                           src, dst, 0, 0, bytes);
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        class_id = (tcp->syn && !tcp->ack) ? FLUXVM_SHIELD_CLASS_SYN : FLUXVM_SHIELD_CLASS_OTHER;
    } else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_MALFORMED,
                           FLUXVM_AF_INET6, class_id, ip6->nexthdr,
                           src, dst, 0, 0, bytes);
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        class_id = FLUXVM_SHIELD_CLASS_UDP;
    } else if (ip6->nexthdr == IPPROTO_ICMPV6) {
        class_id = FLUXVM_SHIELD_CLASS_ICMP;
    }

    struct source_key key = {.family = FLUXVM_AF_INET6, .class_id = class_id};
    __builtin_memcpy(key.addr, src, 16);
    __u32 rate = class_rate(cfg, class_id);
    int token = source_token(&key, rate, cfg->burst_seconds);
    if (token > 0)
        return verdict(ctx, cfg, FLUXVM_SHIELD_REASON_PASS,
                       FLUXVM_AF_INET6, class_id, ip6->nexthdr, src, dst, sport, dport, bytes);
    __u32 reason = token < 0 ? FLUXVM_SHIELD_REASON_BUCKET_EXHAUSTED :
                   class_id == FLUXVM_SHIELD_CLASS_SYN ? FLUXVM_SHIELD_REASON_SYN_RATE :
                   class_id == FLUXVM_SHIELD_CLASS_UDP ? FLUXVM_SHIELD_REASON_UDP_RATE :
                   class_id == FLUXVM_SHIELD_CLASS_ICMP ? FLUXVM_SHIELD_REASON_ICMP_RATE :
                   FLUXVM_SHIELD_REASON_OTHER_RATE;
    return verdict(ctx, cfg, reason, FLUXVM_AF_INET6, class_id, ip6->nexthdr,
                   src, dst, sport, dport, bytes);
}

SEC("xdp")
int fluxvm_shield(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct shield_config *cfg = bpf_map_lookup_elem(&fluxvm_shield_cfg, &zero);
    if (!cfg || cfg->mode == FLUXVM_SHIELD_MODE_OFF || cfg->generation == 0)
        return XDP_PASS;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    void *cursor = eth + 1;
    __u16 proto = bpf_ntohs(eth->h_proto);

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != 0x8100 && proto != 0x88a8)
            break;
        struct fluxvm_vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        proto = bpf_ntohs(vlan->encap_proto);
        cursor = vlan + 1;
    }

    __u32 bytes = (__u32)((long)data_end - (long)data);
    if (proto == ETH_P_IP)
        return handle4(ctx, cfg, cursor, data_end, bytes);
    if (proto == ETH_P_IPV6)
        return handle6(ctx, cfg, cursor, data_end, bytes);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
