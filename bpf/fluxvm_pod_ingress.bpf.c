// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Secure Containers Set 14: Kubernetes NetworkPolicy ingress hook.
//
// Attach to TC egress of the host-visible VM edge. For FluxVM's VM-edge
// topology that is host -> guest traffic. The program reuses the maps pinned
// by fluxvm_tc.bpf.o, including fluxvm_ct, so NetworkPolicy remains stateful:
// replies to an allowed guest-initiated flow bypass a restrictive ingress
// policy, and replies to an allowed ingress-initiated flow bypass a restrictive
// egress policy in the main FluxVM TC program.

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

#define FLUXVM_AF_INET  4
#define FLUXVM_AF_INET6 6

struct iface_config {
    __u32 identity;
    __u32 default_allow;
    __u32 enforce_cidr;
    __u32 enforce_l4;
    __u32 sample_rate;
    __u32 allow_icmp;
    __u64 rate_bytes_per_sec;
    __u64 rate_packets_per_sec;
    __u32 pod_id;
    __u32 reserved0;
};
_Static_assert(sizeof(struct iface_config) == 48, "iface config ABI");

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
_Static_assert(sizeof(struct flow_key) == 44, "flow key ABI");

struct fluxvm_sctphdr_min {
    __be16 source;
    __be16 dest;
    __be32 vtag;
    __be32 checksum;
};

/* Set 16: state stored in fluxvm_ct. Must stay byte-for-byte identical to
 * fluxvm_tc.bpf.c's own struct ct_state -- both objects bind the same
 * pinned map instance (see sync_pod_ingress_attachment in ebpf.rs), so a
 * mismatched value size/layout here would fail at load time. */
struct ct_state {
    __u64 last_seen_ns;
};
_Static_assert(sizeof(struct ct_state) == 8, "conntrack state ABI");

/* Set 16: TCP/SCTP timeouts mirror fluxvm_tc.bpf.c's own; a UDP/"other"
 * timeout isn't needed here since this program only ever calls ct_hit on
 * entries the main egress program itself learned for TCP/SCTP flows it
 * chose to fast-path, but keeping all four keeps ct_timeout_ns identical
 * between the two objects rather than a narrower, easy-to-drift copy. */
#define FLUXVM_CT_TCP_TIMEOUT_NS  (2ULL * 60ULL * 60ULL * 1000000000ULL)
#define FLUXVM_CT_SCTP_TIMEOUT_NS (2ULL * 60ULL * 60ULL * 1000000000ULL)
#define FLUXVM_CT_UDP_TIMEOUT_NS  (120ULL * 1000000000ULL)
#define FLUXVM_CT_OTHER_TIMEOUT_NS (30ULL * 1000000000ULL)

static __always_inline __u64 ct_timeout_ns(__u8 protocol)
{
    if (protocol == IPPROTO_TCP)
        return FLUXVM_CT_TCP_TIMEOUT_NS;
    if (protocol == IPPROTO_SCTP)
        return FLUXVM_CT_SCTP_TIMEOUT_NS;
    if (protocol == IPPROTO_UDP)
        return FLUXVM_CT_UDP_TIMEOUT_NS;
    return FLUXVM_CT_OTHER_TIMEOUT_NS;
}

/* Do not let an old established-flow entry authorize a brand-new TCP/SCTP
 * connection that happens to reuse the same 5-tuple. Mirrors
 * fluxvm_tc.bpf.c's transport_opens_new_flow4/6. */
static __always_inline int transport_opens_new_flow4(struct iphdr *ip, void *data_end)
{
    void *l4 = (void *)ip + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return 1;
        return tcp->syn && !tcp->ack;
    }
    if (ip->protocol == IPPROTO_SCTP) {
        struct fluxvm_sctphdr_min *sctp = l4;
        if ((void *)(sctp + 1) > data_end)
            return 1;
        return sctp->vtag == 0;
    }
    return 0;
}

static __always_inline int transport_opens_new_flow6(struct ipv6hdr *ip, void *data_end)
{
    void *l4 = (void *)(ip + 1);
    if (ip->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return 1;
        return tcp->syn && !tcp->ack;
    }
    if (ip->nexthdr == IPPROTO_SCTP) {
        struct fluxvm_sctphdr_min *sctp = l4;
        if ((void *)(sctp + 1) > data_end)
            return 1;
        return sctp->vtag == 0;
    }
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct iface_config);
} fluxvm_id SEC(".maps");

/* Must be map-compatible with fluxvm_tc.bpf.c. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct flow_key);
    __type(value, struct ct_state);
} fluxvm_ct SEC(".maps");

static __always_inline int parse_ports4(
    struct iphdr *ip,
    void *data_end,
    __u16 *sport,
    __u16 *dport)
{
    void *l4 = (void *)ip + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(tcp->source);
        *dport = bpf_ntohs(tcp->dest);
        return 1;
    }
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(udp->source);
        *dport = bpf_ntohs(udp->dest);
        return 1;
    }
    if (ip->protocol == IPPROTO_SCTP) {
        struct fluxvm_sctphdr_min *sctp = l4;
        if ((void *)(sctp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(sctp->source);
        *dport = bpf_ntohs(sctp->dest);
        return 1;
    }
    *sport = 0;
    *dport = 0;
    return 0;
}

/* FLUXVM_SECURE_CONTAINERS_SET19: verifier-bounded IPv6 extension walk. */
#define FLUXVM_IPV6_MAX_EXT 6
struct fluxvm_ipv6_opt_min { __u8 nexthdr; __u8 hdrlen; };
struct fluxvm_ipv6_frag_min { __u8 nexthdr; __u8 reserved; __be16 frag_off; __be32 identification; };
struct fluxvm_ipv6_l4_info {
    __u8 protocol;
    __u8 fragmented;
    __u8 non_first_fragment;
    __u8 parsed_ports;
    __u16 offset;
    __u16 sport;
    __u16 dport;
};

static __always_inline int fluxvm_parse_ipv6_l4(struct ipv6hdr *ip6, void *data_end,
                                                struct fluxvm_ipv6_l4_info *info)
{
    __u32 off = sizeof(*ip6);
    __u8 next = ip6->nexthdr;
    __builtin_memset(info, 0, sizeof(*info));
#pragma unroll
    for (int i = 0; i < FLUXVM_IPV6_MAX_EXT; i++) {
        if (next == 0 || next == 43 || next == 60) {
            struct fluxvm_ipv6_opt_min *h = (void *)ip6 + off;
            if ((void *)(h + 1) > data_end) return -1;
            __u32 len = ((__u32)h->hdrlen + 1u) * 8u;
            if (len < 8 || off + len > 512 || (void *)ip6 + off + len > data_end) return -1;
            next = h->nexthdr; off += len; continue;
        }
        if (next == 44) {
            struct fluxvm_ipv6_frag_min *h = (void *)ip6 + off;
            if ((void *)(h + 1) > data_end) return -1;
            __u16 frag = bpf_ntohs(h->frag_off);
            info->fragmented = 1;
            next = h->nexthdr; off += 8;
            if (frag & 0xfff8) { info->non_first_fragment = 1; break; }
            continue;
        }
        if (next == 51) {
            struct fluxvm_ipv6_opt_min *h = (void *)ip6 + off;
            if ((void *)(h + 1) > data_end) return -1;
            __u32 len = ((__u32)h->hdrlen + 2u) * 4u;
            if (len < 8 || off + len > 512 || (void *)ip6 + off + len > data_end) return -1;
            next = h->nexthdr; off += len; continue;
        }
        break;
    }
    info->protocol = next;
    info->offset = (__u16)off;
    if (info->non_first_fragment || next == 50 || next == 59) return 0;
    void *l4 = (void *)ip6 + off;
    if (next == IPPROTO_TCP) {
        struct tcphdr *tcp = l4; if ((void *)(tcp + 1) > data_end) return -1;
        info->sport=bpf_ntohs(tcp->source); info->dport=bpf_ntohs(tcp->dest); info->parsed_ports=1;
    } else if (next == IPPROTO_UDP) {
        struct udphdr *udp = l4; if ((void *)(udp + 1) > data_end) return -1;
        info->sport=bpf_ntohs(udp->source); info->dport=bpf_ntohs(udp->dest); info->parsed_ports=1;
    } else if (next == IPPROTO_SCTP) {
        struct fluxvm_sctphdr_min *sctp=l4; if ((void *)(sctp + 1) > data_end) return -1;
        info->sport=bpf_ntohs(sctp->source); info->dport=bpf_ntohs(sctp->dest); info->parsed_ports=1;
    }
    return 0;
}

static __always_inline int fluxvm_ipv6_new_flow(struct ipv6hdr *ip6, void *data_end,
                                                 const struct fluxvm_ipv6_l4_info *info)
{
    if (info->fragmented) return 1;
    void *l4 = (void *)ip6 + info->offset;
    if (info->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp=l4; if ((void *)(tcp+1)>data_end) return 1; return tcp->syn && !tcp->ack;
    }
    if (info->protocol == IPPROTO_SCTP) {
        struct fluxvm_sctphdr_min *sctp=l4; if ((void *)(sctp+1)>data_end) return 1; return sctp->vtag == 0;
    }
    return 0;
}

static __always_inline int fluxvm_ipv6_ndp(struct ipv6hdr *ip6, void *data_end,
                                            const struct fluxvm_ipv6_l4_info *info)
{
    if (info->protocol != IPPROTO_ICMPV6 || info->non_first_fragment) return 0;
    struct icmp6hdr *icmp6=(void *)ip6 + info->offset;
    if ((void *)(icmp6+1)>data_end) return 0;
    return icmp6->icmp6_type==133 || icmp6->icmp6_type==134 || icmp6->icmp6_type==135 || icmp6->icmp6_type==136;
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

static __always_inline int is_ipv6_ndp(struct ipv6hdr *ip, void *data_end)
{
    if (ip->nexthdr != IPPROTO_ICMPV6)
        return 0;
    struct icmp6hdr *icmp6 = (void *)(ip + 1);
    if ((void *)(icmp6 + 1) > data_end)
        return 0;
    return icmp6->icmp6_type == 133 ||
           icmp6->icmp6_type == 134 ||
           icmp6->icmp6_type == 135 ||
           icmp6->icmp6_type == 136;
}

/*
 * Build the guest -> remote tuple corresponding to an ingress packet.
 * That is exactly the tuple the main egress program stores in fluxvm_ct.
 */
static __always_inline void reverse_key4(
    struct flow_key *key,
    __u32 identity,
    struct iphdr *ip,
    __u16 sport,
    __u16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->identity = identity;
    __builtin_memcpy(key->src, &ip->daddr, 4);
    __builtin_memcpy(key->dst, &ip->saddr, 4);
    key->sport = dport;
    key->dport = sport;
    key->protocol = ip->protocol;
    key->family = FLUXVM_AF_INET;
}

static __always_inline void reverse_key6(
    struct flow_key *key,
    __u32 identity,
    struct ipv6hdr *ip,
    __u16 sport,
    __u16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->identity = identity;
    __builtin_memcpy(key->src, ip->daddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(key->dst, ip->saddr.in6_u.u6_addr8, 16);
    key->sport = dport;
    key->dport = sport;
    key->protocol = ip->nexthdr;
    key->family = FLUXVM_AF_INET6;
}

static __always_inline int reverse_ct_hit(struct flow_key *key)
{
    struct ct_state *state = bpf_map_lookup_elem(&fluxvm_ct, key);
    if (!state)
        return 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 timeout = ct_timeout_ns(key->protocol);
    if (state->last_seen_ns == 0 || now - state->last_seen_ns > timeout) {
        bpf_map_delete_elem(&fluxvm_ct, key);
        return 0;
    }
    state->last_seen_ns = now;
    return 1;
}

static __always_inline void reverse_ct_learn(struct flow_key *key)
{
    struct ct_state state = {.last_seen_ns = bpf_ktime_get_ns()};
    bpf_map_update_elem(&fluxvm_ct, key, &state, BPF_ANY);
}

SEC("tc")
int fluxvm_pod_ingress(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct iface_config *cfg = bpf_map_lookup_elem(&fluxvm_id, &ifindex);
    if (!cfg || !cfg->pod_id)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_ARP)
        return TC_ACT_OK;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end || ip->ihl < 5 ||
            (void *)ip + ip->ihl * 4 > data_end)
            return TC_ACT_SHOT;

        /* Non-initial/fragmented IPv4 cannot safely supply L4 ports. Keep
         * L3/protocol-only rich rules usable, but a port-specific rule will
         * fail closed because dport remains zero. */
        __u16 frag = bpf_ntohs(ip->frag_off);
        int fragmented = (frag & 0x3fff) != 0;
        __u16 sport = 0, dport = 0;
        if (!fragmented && parse_ports4(ip, data_end, &sport, &dport) < 0)
            return TC_ACT_SHOT;
        if (!fragmented && is_dhcp4(ip->protocol, sport, dport))
            return TC_ACT_OK;

        struct flow_key reverse = {};
        reverse_key4(&reverse, cfg->identity, ip, sport, dport);
        if (!fragmented && !transport_opens_new_flow4(ip, data_end) && reverse_ct_hit(&reverse))
            return TC_ACT_OK;

        int verdict = fluxvm_pod_policy_verdict4_tuple(
            cfg->pod_id, FLUXVM_POD_DIR_INGRESS,
            ip->saddr, ip->protocol, dport);
        if (verdict == FLUXVM_POD_VERDICT_DENY)
            return TC_ACT_SHOT;
        if (!fragmented)
            reverse_ct_learn(&reverse);
        return TC_ACT_OK;
    }

    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip=(void *)(eth+1); if ((void *)(ip+1)>data_end) return TC_ACT_SHOT;
        struct fluxvm_ipv6_l4_info li={}; if (fluxvm_parse_ipv6_l4(ip,data_end,&li)<0) return TC_ACT_SHOT;
        if (fluxvm_ipv6_ndp(ip,data_end,&li) || is_dhcp6(li.protocol,li.sport,li.dport)) return TC_ACT_OK;
        struct flow_key reverse={}; __builtin_memset(&reverse,0,sizeof(reverse));
        reverse.identity=cfg->identity; __builtin_memcpy(reverse.src,ip->daddr.in6_u.u6_addr8,16); __builtin_memcpy(reverse.dst,ip->saddr.in6_u.u6_addr8,16);
        reverse.sport=li.dport; reverse.dport=li.sport; reverse.protocol=li.protocol; reverse.family=FLUXVM_AF_INET6;
        if (!li.fragmented && !fluxvm_ipv6_new_flow(ip,data_end,&li) && reverse_ct_hit(&reverse)) return TC_ACT_OK;
        int verdict=fluxvm_pod_policy_verdict6_tuple(cfg->pod_id,FLUXVM_POD_DIR_INGRESS,ip->saddr.in6_u.u6_addr8,li.protocol,li.dport);
        if (verdict==FLUXVM_POD_VERDICT_DENY) return TC_ACT_SHOT;
        if (!li.fragmented) reverse_ct_learn(&reverse);
        return TC_ACT_OK;
    }

    /* NetworkPolicy is IP-layer policy. Keep non-IP bootstrap L2 unchanged. */
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
