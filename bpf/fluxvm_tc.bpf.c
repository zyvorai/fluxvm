// Copyright 2026 Zyvor
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM VM-edge TC dataplane v3.
//
// Attach on TC ingress of the host-visible VM edge. For a namespaced VM
// this is the host-side veth, so ingress here is egress from the guest.
// FluxVM owns only the maps/programs below its own bpffs pin root and never
// mutates Cilium-owned maps.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "fluxvm_pod_policy.bpf.h"

#define FLUXVM_VERDICT_DROP  0
#define FLUXVM_VERDICT_ALLOW 1
#define FLUXVM_AF_INET       4
#define FLUXVM_AF_INET6      6
#define FLUXVM_RATE_WINDOW_NS 1000000000ULL

struct iface_config {
    __u32 identity;
    __u32 default_allow;
    // One global CIDR-enforcement bit. If the operator supplies only IPv6
    // CIDRs, IPv4 has no matching entries and therefore fails closed too.
    __u32 enforce_cidr;
    __u32 enforce_l4;
    __u32 sample_rate;
    __u32 allow_icmp;
    __u64 rate_bytes_per_sec;
    __u64 rate_packets_per_sec;
    // Set 6S: Kubernetes Pod identity for fluxvm_pspol/fluxvm_pid4/6 lookups.
    // 0 means "no Pod-scoped policy" (Secure Containers not in use for this
    // VM, or Set 6S not configured) -- handle_ipv4/6 skip the pod-policy
    // check entirely in that case, so every non-Secure-Containers sandbox
    // keeps today's behavior unchanged. `reserved0` is explicit trailing
    // padding so the struct's size (48 bytes) has no implicit compiler-
    // inserted padding for the userspace loader to get wrong.
    __u32 pod_id;
    __u32 reserved0;
};
_Static_assert(sizeof(struct iface_config) == 48, "iface config ABI");

// Prefix length covers exact 32-bit FluxVM identity + destination prefix.
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 identity;
    __u32 addr;
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u32 identity;
    __u8 addr[16];
};

struct l4_key {
    __u32 identity;
    __u16 port;
    __u8 protocol;
    __u8 pad;
};

struct stat_key {
    __u32 identity;
    __u32 verdict;
};

struct stat_value {
    __u64 packets;
    __u64 bytes;
};

// Family-neutral flow key. IPv4 occupies the first four bytes of src/dst
// and the remaining twelve bytes stay zero. Ports are host byte order.
struct flow_key {
    __u32 identity;
    __u8 src[16];
    __u8 dst[16];
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 verdict;
    __u8 family;
    __u8 pad;
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

struct rate_state {
    struct bpf_spin_lock lock;
    __u32 pad;
    __u64 window_start_ns;
    __u64 bytes;
    __u64 packets;
};

struct flow_event {
    __u64 timestamp_ns;
    __u32 identity;
    __u32 ifindex;
    __u8 src[16];
    __u8 dst[16];
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 verdict;
    __u8 family;
    __u8 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct iface_config);
} fluxvm_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
} fluxvm_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);
} fluxvm_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct l4_key);
    __type(value, __u32);
} fluxvm_l4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct rate_state);
} fluxvm_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 32);
    __type(key, struct stat_key);
    __type(value, struct stat_value);
} fluxvm_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} fluxvm_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fluxvm_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
} fluxvm_deny4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);
} fluxvm_deny6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_key);
    __type(value, __u8);
} fluxvm_ct SEC(".maps");

struct group_ids {
    __u32 n;
    __u32 ids[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct group_ids);
} fluxvm_gid SEC(".maps");

static __always_inline void count(__u32 identity, __u32 verdict, __u32 bytes)
{
    struct stat_key key = {
        .identity = identity,
        .verdict = verdict,
    };
    struct stat_value *value = bpf_map_lookup_elem(&fluxvm_stats, &key);
    if (value) {
        value->packets += 1;
        value->bytes += bytes;
        return;
    }
    struct stat_value initial = {
        .packets = 1,
        .bytes = bytes,
    };
    bpf_map_update_elem(&fluxvm_stats, &key, &initial, BPF_NOEXIST);
}

static __always_inline int parse_ports4(
    struct iphdr *iph,
    void *data_end,
    __u16 *sport,
    __u16 *dport)
{
    void *l4 = (void *)iph + (iph->ihl * 4);
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
        return 1;
    }
    *sport = 0;
    *dport = 0;
    return 0;
}

// v3 intentionally supports direct TCP/UDP after the IPv6 base header.
// Extension-header walking is not verifier-portable across the minimum
// kernel set we target. With an L4 allowlist enabled, such packets fail
// closed; L3-only IPv6 CIDR policy still works normally.
static __always_inline int parse_ports6(
    struct ipv6hdr *ip6,
    void *data_end,
    __u16 *sport,
    __u16 *dport)
{
    void *l4 = (void *)(ip6 + 1);
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
        return 1;
    }
    *sport = 0;
    *dport = 0;
    return 0;
}

static __always_inline int is_dhcp4(__u8 protocol, __u16 sport, __u16 dport)
{
    if (protocol != IPPROTO_UDP)
        return 0;
    return (sport == 67 && dport == 68) || (sport == 68 && dport == 67);
}

static __always_inline int is_dhcp6(__u8 protocol, __u16 sport, __u16 dport)
{
    if (protocol != IPPROTO_UDP)
        return 0;
    return (sport == 546 && dport == 547) || (sport == 547 && dport == 546);
}

static __always_inline int is_ipv6_ndp(struct ipv6hdr *ip6, void *data_end)
{
    if (ip6->nexthdr != IPPROTO_ICMPV6)
        return 0;
    struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
    if ((void *)(icmp6 + 1) > data_end)
        return 0;
    return icmp6->icmp6_type == 133 || // Router Solicitation
           icmp6->icmp6_type == 134 || // Router Advertisement
           icmp6->icmp6_type == 135 || // Neighbor Solicitation
           icmp6->icmp6_type == 136;   // Neighbor Advertisement
}

static __always_inline int rate_allowed(
    const struct iface_config *cfg,
    __u32 bytes)
{
    __u64 byte_limit = cfg->rate_bytes_per_sec;
    __u64 packet_limit = cfg->rate_packets_per_sec;
    if (byte_limit == 0 && packet_limit == 0)
        return 1;

    __u32 identity = cfg->identity;
    struct rate_state *state = bpf_map_lookup_elem(&fluxvm_rate, &identity);
    if (!state) {
        // Initialize inside BPF rather than from userspace. Map values that
        // contain bpf_spin_lock require special BPF_F_LOCK syscall handling;
        // lazy initialization avoids making bpftool responsible for that ABI.
        struct rate_state initial = {};
        bpf_map_update_elem(&fluxvm_rate, &identity, &initial, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&fluxvm_rate, &identity);
        if (!state)
            return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    int allowed = 1;
    bpf_spin_lock(&state->lock);
    if (state->window_start_ns == 0 ||
        now - state->window_start_ns >= FLUXVM_RATE_WINDOW_NS) {
        state->window_start_ns = now;
        state->bytes = 0;
        state->packets = 0;
    }
    if (byte_limit > 0 &&
        (state->bytes >= byte_limit || (__u64)bytes > byte_limit - state->bytes))
        allowed = 0;
    if (packet_limit > 0 && state->packets >= packet_limit)
        allowed = 0;
    if (allowed) {
        state->bytes += bytes;
        state->packets += 1;
    }
    bpf_spin_unlock(&state->lock);
    return allowed;
}

static __always_inline int cidr_lookup4(void *map, __u32 identity, __u32 daddr)
{
    struct ipv4_lpm_key key = {
        .prefixlen = 64,
        .identity = identity,
        .addr = daddr,
    };
    __u32 *hit = bpf_map_lookup_elem(map, &key);
    return hit && *hit;
}

static __always_inline int cidr_allowed4(__u32 identity, __u32 daddr)
{
    return cidr_lookup4(&fluxvm_v4, identity, daddr);
}

static __always_inline int cidr_denied4(__u32 identity, __u32 daddr)
{
    return cidr_lookup4(&fluxvm_deny4, identity, daddr);
}

static __always_inline int cidr_lookup6(void *map, __u32 identity, const struct in6_addr *daddr)
{
    struct ipv6_lpm_key key = {
        .prefixlen = 160,
        .identity = identity,
    };
    __builtin_memcpy(key.addr, daddr->in6_u.u6_addr8, 16);
    __u32 *hit = bpf_map_lookup_elem(map, &key);
    return hit && *hit;
}

static __always_inline int cidr_allowed6(__u32 identity, const struct in6_addr *daddr)
{
    return cidr_lookup6(&fluxvm_v6, identity, daddr);
}

static __always_inline int cidr_denied6(__u32 identity, const struct in6_addr *daddr)
{
    return cidr_lookup6(&fluxvm_deny6, identity, daddr);
}

static __always_inline int ct_hit(const struct flow_key *probe)
{
    struct flow_key key = *probe;
    key.verdict = 0;
    key.pad = 0;
    __u8 *hit = bpf_map_lookup_elem(&fluxvm_ct, &key);
    return hit != 0;
}

static __always_inline void ct_learn(const struct flow_key *probe)
{
    struct flow_key key = *probe;
    key.verdict = 0;
    key.pad = 0;
    __u8 one = 1;
    bpf_map_update_elem(&fluxvm_ct, &key, &one, BPF_ANY);
}

static __always_inline int l4_allowed(__u32 identity, __u8 protocol, __u16 port)
{
    struct l4_key key = {
        .identity = identity,
        .port = port,
        .protocol = protocol,
        .pad = 0,
    };
    __u32 *allow = bpf_map_lookup_elem(&fluxvm_l4, &key);
    if (allow && *allow)
        return 1;
    key.port = 0;
    allow = bpf_map_lookup_elem(&fluxvm_l4, &key);
    return allow && *allow;
}

static __always_inline int any_cidr4(__u32 ifindex, __u32 identity, __u32 daddr)
{
    if (cidr_allowed4(identity, daddr))
        return 1;
    struct group_ids *g = bpf_map_lookup_elem(&fluxvm_gid, &ifindex);
    if (!g)
        return 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= g->n)
            break;
        if (cidr_allowed4(g->ids[i], daddr))
            return 1;
    }
    return 0;
}

static __always_inline int any_deny4(__u32 ifindex, __u32 identity, __u32 daddr)
{
    if (cidr_denied4(identity, daddr))
        return 1;
    struct group_ids *g = bpf_map_lookup_elem(&fluxvm_gid, &ifindex);
    if (!g)
        return 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= g->n)
            break;
        if (cidr_denied4(g->ids[i], daddr))
            return 1;
    }
    return 0;
}

static __always_inline int any_cidr6(__u32 ifindex, __u32 identity, const struct in6_addr *daddr)
{
    if (cidr_allowed6(identity, daddr))
        return 1;
    struct group_ids *g = bpf_map_lookup_elem(&fluxvm_gid, &ifindex);
    if (!g)
        return 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= g->n)
            break;
        if (cidr_allowed6(g->ids[i], daddr))
            return 1;
    }
    return 0;
}

static __always_inline int any_deny6(__u32 ifindex, __u32 identity, const struct in6_addr *daddr)
{
    if (cidr_denied6(identity, daddr))
        return 1;
    struct group_ids *g = bpf_map_lookup_elem(&fluxvm_gid, &ifindex);
    if (!g)
        return 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= g->n)
            break;
        if (cidr_denied6(g->ids[i], daddr))
            return 1;
    }
    return 0;
}

static __always_inline int any_l4(__u32 ifindex, __u32 identity, __u8 protocol, __u16 port)
{
    if (l4_allowed(identity, protocol, port))
        return 1;
    struct group_ids *g = bpf_map_lookup_elem(&fluxvm_gid, &ifindex);
    if (!g)
        return 0;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= g->n)
            break;
        if (l4_allowed(g->ids[i], protocol, port))
            return 1;
    }
    return 0;
}

static __always_inline void record_flow_raw(
    struct __sk_buff *skb,
    __u32 identity,
    __u8 family,
    const __u8 *src,
    const __u8 *dst,
    __u16 sport,
    __u16 dport,
    __u8 protocol,
    __u8 verdict,
    __u32 sample_rate)
{
    struct flow_key key = {
        .identity = identity,
        .sport = sport,
        .dport = dport,
        .protocol = protocol,
        .verdict = verdict,
        .family = family,
        .pad = 0,
    };
    __builtin_memcpy(key.src, src, 16);
    __builtin_memcpy(key.dst, dst, 16);

    struct flow_value *value = bpf_map_lookup_elem(&fluxvm_flows, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        value->last_seen_ns = bpf_ktime_get_ns();
    } else {
        struct flow_value initial = {
            .packets = 1,
            .bytes = skb->len,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&fluxvm_flows, &key, &initial, BPF_NOEXIST);
    }

    int emit = verdict == FLUXVM_VERDICT_DROP;
    if (!emit && sample_rate > 0)
        emit = (bpf_get_prandom_u32() % sample_rate) == 0;
    if (!emit)
        return;

    struct flow_event *event = bpf_ringbuf_reserve(&fluxvm_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->identity = identity;
    event->ifindex = skb->ifindex;
    __builtin_memcpy(event->src, src, 16);
    __builtin_memcpy(event->dst, dst, 16);
    event->bytes = skb->len;
    event->sport = sport;
    event->dport = dport;
    event->protocol = protocol;
    event->verdict = verdict;
    event->family = family;
    event->pad = 0;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void record_flow4(
    struct __sk_buff *skb,
    __u32 identity,
    struct iphdr *iph,
    __u16 sport,
    __u16 dport,
    __u8 verdict,
    __u32 sample_rate)
{
    __u8 src[16] = {};
    __u8 dst[16] = {};
    __builtin_memcpy(src, &iph->saddr, 4);
    __builtin_memcpy(dst, &iph->daddr, 4);
    record_flow_raw(skb, identity, FLUXVM_AF_INET, src, dst, sport, dport,
                    iph->protocol, verdict, sample_rate);
}

static __always_inline void record_flow6(
    struct __sk_buff *skb,
    __u32 identity,
    struct ipv6hdr *ip6,
    __u16 sport,
    __u16 dport,
    __u8 verdict,
    __u32 sample_rate)
{
    record_flow_raw(skb, identity, FLUXVM_AF_INET6,
                    ip6->saddr.in6_u.u6_addr8,
                    ip6->daddr.in6_u.u6_addr8,
                    sport, dport, ip6->nexthdr, verdict, sample_rate);
}

static __always_inline int handle_ipv4(
    struct __sk_buff *skb,
    struct iface_config *cfg,
    void *data,
    void *data_end)
{
    struct ethhdr *eth = data;
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl < 5)
        return TC_ACT_SHOT;
    if ((void *)iph + (iph->ihl * 4) > data_end)
        return TC_ACT_SHOT;

    __u16 sport = 0;
    __u16 dport = 0;
    __u16 frag = bpf_ntohs(iph->frag_off);
    int fragmented = (frag & 0x3fff) != 0;
    int parsed_l4 = 0;
    if (!fragmented) {
        parsed_l4 = parse_ports4(iph, data_end, &sport, &dport);
        if (parsed_l4 < 0)
            return TC_ACT_SHOT;
    }

    if (fragmented && cfg->enforce_l4) {
        count(cfg->identity, FLUXVM_VERDICT_DROP, skb->len);
        record_flow4(skb, cfg->identity, iph, 0, 0,
                     FLUXVM_VERDICT_DROP, cfg->sample_rate);
        return TC_ACT_SHOT;
    }

    if (is_dhcp4(iph->protocol, sport, dport)) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        record_flow4(skb, cfg->identity, iph, sport, dport,
                     FLUXVM_VERDICT_ALLOW, cfg->sample_rate);
        return TC_ACT_OK;
    }

    __u32 sample = cfg->sample_rate & 0x7fffffffu;
    __u32 audit = cfg->sample_rate >> 31;
    __u8 src[16] = {};
    __u8 dst[16] = {};
    __builtin_memcpy(src, &iph->saddr, 4);
    __builtin_memcpy(dst, &iph->daddr, 4);
    struct flow_key ctkey = {
        .identity = cfg->identity,
        .sport = sport,
        .dport = dport,
        .protocol = iph->protocol,
        .verdict = 0,
        .family = FLUXVM_AF_INET,
        .pad = 0,
    };
    __builtin_memcpy(ctkey.src, src, 16);
    __builtin_memcpy(ctkey.dst, dst, 16);
    if (ct_hit(&ctkey)) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        record_flow4(skb, cfg->identity, iph, sport, dport,
                     FLUXVM_VERDICT_ALLOW, sample);
        return TC_ACT_OK;
    }
    if (any_deny4(skb->ifindex, cfg->identity, iph->daddr)) {
        if (audit) {
            count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
            record_flow4(skb, cfg->identity, iph, sport, dport,
                         FLUXVM_VERDICT_DROP, sample);
            return TC_ACT_OK;
        }
        count(cfg->identity, FLUXVM_VERDICT_DROP, skb->len);
        record_flow4(skb, cfg->identity, iph, sport, dport,
                     FLUXVM_VERDICT_DROP, sample);
        return TC_ACT_SHOT;
    }
    if (cfg->allow_icmp && iph->protocol == IPPROTO_ICMP) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        record_flow4(skb, cfg->identity, iph, sport, dport,
                     FLUXVM_VERDICT_ALLOW, sample);
        ct_learn(&ctkey);
        return TC_ACT_OK;
    }
    int has_policy = cfg->enforce_cidr || cfg->enforce_l4;
    int allowed = has_policy ? 1 : (cfg->default_allow != 0);
    if (cfg->enforce_cidr)
        allowed = allowed && any_cidr4(skb->ifindex, cfg->identity, iph->daddr);
    if (cfg->enforce_l4)
        allowed = allowed && parsed_l4 > 0 &&
                  any_l4(skb->ifindex, cfg->identity, iph->protocol, dport);
    // Set 6S: Kubernetes-Pod-identity-scoped policy, additive on top of the
    // VM-level CIDR/L4 verdict above -- can only narrow an allow, never
    // widen a deny into an allow (mirrors any_deny4's precedence).
    if (cfg->pod_id && allowed)
        allowed = fluxvm_pod_policy_allowed4(cfg->pod_id, iph->daddr);
    if (allowed && !rate_allowed(cfg, skb->len))
        allowed = 0;
    if (!allowed && audit)
        allowed = 1;
    if (allowed)
        ct_learn(&ctkey);

    __u8 verdict = allowed ? FLUXVM_VERDICT_ALLOW : FLUXVM_VERDICT_DROP;
    count(cfg->identity, verdict, skb->len);
    record_flow4(skb, cfg->identity, iph, sport, dport, verdict, sample);
    return allowed ? TC_ACT_OK : TC_ACT_SHOT;
}

static __always_inline int handle_ipv6(
    struct __sk_buff *skb,
    struct iface_config *cfg,
    void *data,
    void *data_end)
{
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return TC_ACT_SHOT;

    __u16 sport = 0;
    __u16 dport = 0;
    int parsed_l4 = parse_ports6(ip6, data_end, &sport, &dport);
    if (parsed_l4 < 0)
        return TC_ACT_SHOT;

    // Neighbor discovery/router discovery and DHCPv6 are infrastructure
    // bootstrap. Denying these makes an IPv6 guest unable to establish the
    // addressing information policy itself depends on.
    if (is_ipv6_ndp(ip6, data_end) || is_dhcp6(ip6->nexthdr, sport, dport)) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        record_flow6(skb, cfg->identity, ip6, sport, dport,
                     FLUXVM_VERDICT_ALLOW, cfg->sample_rate);
        return TC_ACT_OK;
    }

    if (any_deny6(skb->ifindex, cfg->identity, &ip6->daddr)) {
        count(cfg->identity, FLUXVM_VERDICT_DROP, skb->len);
        record_flow6(skb, cfg->identity, ip6, sport, dport,
                     FLUXVM_VERDICT_DROP, cfg->sample_rate);
        return TC_ACT_SHOT;
    }
    if (cfg->allow_icmp && ip6->nexthdr == IPPROTO_ICMPV6) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        record_flow6(skb, cfg->identity, ip6, sport, dport,
                     FLUXVM_VERDICT_ALLOW, cfg->sample_rate);
        return TC_ACT_OK;
    }
    int has_policy = cfg->enforce_cidr || cfg->enforce_l4;
    int allowed = has_policy ? 1 : (cfg->default_allow != 0);
    if (cfg->enforce_cidr)
        allowed = allowed && any_cidr6(skb->ifindex, cfg->identity, &ip6->daddr);
    if (cfg->enforce_l4)
        allowed = allowed && parsed_l4 > 0 &&
                  any_l4(skb->ifindex, cfg->identity, ip6->nexthdr, dport);
    // Set 6S: see the IPv4 path above for the additive-only precedence.
    if (cfg->pod_id && allowed)
        allowed = fluxvm_pod_policy_allowed6(cfg->pod_id, ip6->daddr.in6_u.u6_addr8);
    if (allowed && !rate_allowed(cfg, skb->len))
        allowed = 0;

    __u8 verdict = allowed ? FLUXVM_VERDICT_ALLOW : FLUXVM_VERDICT_DROP;
    count(cfg->identity, verdict, skb->len);
    record_flow6(skb, cfg->identity, ip6, sport, dport, verdict, cfg->sample_rate);
    return allowed ? TC_ACT_OK : TC_ACT_SHOT;
}

SEC("tc")
int fluxvm_egress(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct iface_config *cfg = bpf_map_lookup_elem(&fluxvm_id, &ifindex);
    // Loader v3 writes config before attaching, so a missing entry should
    // only occur after external map tampering. Fail closed rather than
    // silently turning an enforced interface into allow-all.
    if (!cfg)
        return TC_ACT_SHOT;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_ARP) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        return TC_ACT_OK;
    }
    if (eth_proto == ETH_P_IP)
        return handle_ipv4(skb, cfg, data, data_end);
    if (eth_proto == ETH_P_IPV6)
        return handle_ipv6(skb, cfg, data, data_end);

    __u8 verdict = cfg->default_allow ? FLUXVM_VERDICT_ALLOW : FLUXVM_VERDICT_DROP;
    count(cfg->identity, verdict, skb->len);
    return verdict == FLUXVM_VERDICT_ALLOW ? TC_ACT_OK : TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
