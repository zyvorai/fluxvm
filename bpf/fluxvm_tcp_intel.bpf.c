// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM TCP Intelligence v1.
// Passive, fail-open TC observer.  It never changes packet verdicts.
// Attach guest->host at ingress and host->guest at egress on the VM edge.
// Handshake latency is exact for observed SYN/SYN-ACK pairs. Data RTT and
// retransmission signals are packet-level estimates, intentionally labeled as
// such by userspace rather than pretending to be the guest TCP stack's srtt.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_AF_INET  4u
#define FLUXVM_AF_INET6 6u
#define TCP_KIND_HANDSHAKE 1u
#define TCP_KIND_RTT       2u
#define TCP_COUNT_SYN          1u
#define TCP_COUNT_ESTABLISHED  2u
#define TCP_COUNT_RETRANSMIT   3u
#define TCP_COUNT_RST          4u
#define TCP_COUNT_FIN          5u
#define TCP_COUNT_FLOW_MISS    6u
#define TCP_EVENT_SYN          1u
#define TCP_EVENT_ESTABLISHED  2u
#define TCP_EVENT_RETRANSMIT   3u
#define TCP_EVENT_RTT          4u
#define TCP_EVENT_RST          5u
#define TCP_EVENT_FIN          6u

struct tcp_config {
    __u64 vm_key;
    __u32 ifindex;
    __u32 sample_rate;
};

struct tcp_flow_key {
    __u8 family;
    __u8 reserved0[3];
    __u8 guest[16];
    __u8 remote[16];
    __u16 guest_port;
    __u16 remote_port;
};
_Static_assert(sizeof(struct tcp_flow_key) == 40, "tcp flow key ABI");

struct tcp_flow_value {
    __u64 syn_ns;
    __u64 handshake_ns;
    __u64 last_out_ns;
    __u64 last_in_ns;
    __u64 rtt_total_ns;
    __u64 rtt_max_ns;
    __u64 rtt_min_ns;
    __u64 last_seen_ns;
    __u32 last_out_seq;
    __u32 last_out_end;
    __u32 last_in_seq;
    __u32 last_in_end;
    __u32 last_ack_from_remote;
    __u32 last_ack_from_guest;
    __u32 retransmits;
    __u32 syn_retransmits;
    __u32 rtt_samples;
    __u32 rst_count;
    __u32 fin_count;
    __u32 established;
    __u32 syn_origin; // 1 = guest, 2 = remote
    __u32 reserved0;
};
_Static_assert(sizeof(struct tcp_flow_value) == 120, "tcp flow value ABI");

struct tcp_hist_key {
    __u32 kind;
    __u32 bucket;
};

struct tcp_hist_value {
    __u64 count;
    __u64 total_ns;
    __u64 max_ns;
};

struct tcp_count_key {
    __u32 kind;
};

struct fluxvm_vlan_hdr {
    __be16 tci;
    __be16 encap_proto;
};

struct tcp_event {
    __u64 timestamp_ns;
    __u64 vm_key;
    __u32 ifindex;
    __u32 event_type;
    __u8 family;
    __u8 direction; // 1 = guest->remote, 2 = remote->guest
    __u8 reserved0[2];
    __u8 guest[16];
    __u8 remote[16];
    __u16 guest_port;
    __u16 remote_port;
    __u32 sequence;
    __u32 acknowledgement;
    __u64 duration_ns;
};
_Static_assert(sizeof(struct tcp_event) == 80, "tcp event ABI");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tcp_config);
} fluxvm_tcp_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct tcp_flow_key);
    __type(value, struct tcp_flow_value);
} fluxvm_tcp_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct tcp_hist_key);
    __type(value, struct tcp_hist_value);
} fluxvm_tcp_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, struct tcp_count_key);
    __type(value, __u64);
} fluxvm_tcp_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fluxvm_tcp_events SEC(".maps");

static __always_inline void count(__u32 kind)
{
    struct tcp_count_key key = {.kind = kind};
    __u64 *value = bpf_map_lookup_elem(&fluxvm_tcp_counts, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(&fluxvm_tcp_counts, &key, &one, BPF_NOEXIST);
}

static __always_inline __u32 bucket_for(__u64 ns)
{
    __u64 us = (ns + 999) / 1000;
    __u32 bucket = 0;
    #pragma unroll
    for (int i = 0; i < 24; i++) {
        if (us > 1) {
            us >>= 1;
            bucket++;
        }
    }
    return bucket > 24 ? 24 : bucket;
}

static __always_inline void histogram(__u32 kind, __u64 ns)
{
    struct tcp_hist_key key = {.kind = kind, .bucket = bucket_for(ns)};
    struct tcp_hist_value *value = bpf_map_lookup_elem(&fluxvm_tcp_hist, &key);
    if (value) {
        __sync_fetch_and_add(&value->count, 1);
        __sync_fetch_and_add(&value->total_ns, ns);
        if (ns > value->max_ns)
            value->max_ns = ns;
        return;
    }
    struct tcp_hist_value initial = {.count = 1, .total_ns = ns, .max_ns = ns};
    bpf_map_update_elem(&fluxvm_tcp_hist, &key, &initial, BPF_NOEXIST);
}

static __always_inline void event_emit(const struct tcp_config *cfg, __u32 type,
                                       const struct tcp_flow_key *key, __u8 direction,
                                       __u32 seq, __u32 ack, __u64 duration)
{
    int emit = type != TCP_EVENT_RTT;
    if (!emit && cfg->sample_rate > 0)
        emit = (bpf_get_prandom_u32() % cfg->sample_rate) == 0;
    if (!emit)
        return;
    struct tcp_event *event = bpf_ringbuf_reserve(&fluxvm_tcp_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->vm_key = cfg->vm_key;
    event->ifindex = cfg->ifindex;
    event->event_type = type;
    event->family = key->family;
    event->direction = direction;
    event->reserved0[0] = 0;
    event->reserved0[1] = 0;
    __builtin_memcpy(event->guest, key->guest, 16);
    __builtin_memcpy(event->remote, key->remote, 16);
    event->guest_port = key->guest_port;
    event->remote_port = key->remote_port;
    event->sequence = seq;
    event->acknowledgement = ack;
    event->duration_ns = duration;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int parse_l2(struct __sk_buff *skb, void **cursor_out, void **end_out, __u16 *proto_out)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    void *cursor = eth + 1;
    __u16 proto = bpf_ntohs(eth->h_proto);
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != 0x8100 && proto != 0x88a8)
            break;
        struct fluxvm_vlan_hdr *vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return 0;
        proto = bpf_ntohs(vlan->encap_proto);
        cursor = vlan + 1;
    }
    *cursor_out = cursor;
    *end_out = data_end;
    *proto_out = proto;
    return 1;
}

static __always_inline int parse4(struct __sk_buff *skb, int inbound,
                                  struct tcp_flow_key *key,
                                  struct tcphdr **tcp_out,
                                  __u32 *payload_len)
{
    void *cursor = 0, *data_end = 0;
    __u16 proto = 0;
    if (!parse_l2(skb, &cursor, &data_end, &proto) || proto != ETH_P_IP)
        return 0;
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > data_end || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
        return 0;
    __u32 ihl = (__u32)ip->ihl * 4;
    if ((void *)ip + ihl > data_end)
        return 0;
    __u16 frag = bpf_ntohs(ip->frag_off);
    if ((frag & 0x1fff) != 0)
        return 0;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return 0;
    __u32 thl = (__u32)tcp->doff * 4;
    if ((void *)tcp + thl > data_end)
        return 0;
    __u32 total = bpf_ntohs(ip->tot_len);
    *payload_len = total > ihl + thl ? total - ihl - thl : 0;
    key->family = FLUXVM_AF_INET;
    if (!inbound) {
        __builtin_memcpy(key->guest, &ip->saddr, 4);
        __builtin_memcpy(key->remote, &ip->daddr, 4);
        key->guest_port = bpf_ntohs(tcp->source);
        key->remote_port = bpf_ntohs(tcp->dest);
    } else {
        __builtin_memcpy(key->guest, &ip->daddr, 4);
        __builtin_memcpy(key->remote, &ip->saddr, 4);
        key->guest_port = bpf_ntohs(tcp->dest);
        key->remote_port = bpf_ntohs(tcp->source);
    }
    *tcp_out = tcp;
    return 1;
}

static __always_inline int parse6(struct __sk_buff *skb, int inbound,
                                  struct tcp_flow_key *key,
                                  struct tcphdr **tcp_out,
                                  __u32 *payload_len)
{
    void *cursor = 0, *data_end = 0;
    __u16 proto = 0;
    if (!parse_l2(skb, &cursor, &data_end, &proto) || proto != ETH_P_IPV6)
        return 0;
    struct ipv6hdr *ip6 = cursor;
    if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
        return 0;
    struct tcphdr *tcp = (void *)(ip6 + 1);
    if ((void *)(tcp + 1) > data_end || tcp->doff < 5)
        return 0;
    __u32 thl = (__u32)tcp->doff * 4;
    if ((void *)tcp + thl > data_end)
        return 0;
    __u32 plen = bpf_ntohs(ip6->payload_len);
    *payload_len = plen > thl ? plen - thl : 0;
    key->family = FLUXVM_AF_INET6;
    if (!inbound) {
        __builtin_memcpy(key->guest, ip6->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key->remote, ip6->daddr.in6_u.u6_addr8, 16);
        key->guest_port = bpf_ntohs(tcp->source);
        key->remote_port = bpf_ntohs(tcp->dest);
    } else {
        __builtin_memcpy(key->guest, ip6->daddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(key->remote, ip6->saddr.in6_u.u6_addr8, 16);
        key->guest_port = bpf_ntohs(tcp->dest);
        key->remote_port = bpf_ntohs(tcp->source);
    }
    *tcp_out = tcp;
    return 1;
}

static __always_inline int parse_tcp(struct __sk_buff *skb, int inbound,
                                     struct tcp_flow_key *key,
                                     struct tcphdr **tcp_out,
                                     __u32 *payload_len)
{
    __builtin_memset(key, 0, sizeof(*key));
    if (parse4(skb, inbound, key, tcp_out, payload_len))
        return 1;
    __builtin_memset(key, 0, sizeof(*key));
    return parse6(skb, inbound, key, tcp_out, payload_len);
}

static __always_inline struct tcp_flow_value *flow_get_or_create(const struct tcp_flow_key *key, __u64 now)
{
    struct tcp_flow_value *value = bpf_map_lookup_elem(&fluxvm_tcp_flows, key);
    if (value)
        return value;
    struct tcp_flow_value initial = {.rtt_min_ns = ~0ULL, .last_seen_ns = now};
    bpf_map_update_elem(&fluxvm_tcp_flows, key, &initial, BPF_NOEXIST);
    value = bpf_map_lookup_elem(&fluxvm_tcp_flows, key);
    if (!value)
        count(TCP_COUNT_FLOW_MISS);
    return value;
}

static __always_inline void rtt_sample(const struct tcp_config *cfg,
                                       const struct tcp_flow_key *key,
                                       struct tcp_flow_value *value,
                                       __u8 direction, __u32 seq, __u32 ack,
                                       __u64 sent_ns, __u32 *last_ack)
{
    if (!sent_ns || ack == *last_ack)
        return;
    __u64 now = bpf_ktime_get_ns();
    __u64 rtt = now - sent_ns;
    *last_ack = ack;
    value->rtt_samples++;
    value->rtt_total_ns += rtt;
    if (rtt > value->rtt_max_ns)
        value->rtt_max_ns = rtt;
    if (rtt < value->rtt_min_ns)
        value->rtt_min_ns = rtt;
    histogram(TCP_KIND_RTT, rtt);
    event_emit(cfg, TCP_EVENT_RTT, key, direction, seq, ack, rtt);
}

static __always_inline void handshake_sample(const struct tcp_config *cfg,
                                             const struct tcp_flow_key *key,
                                             struct tcp_flow_value *value,
                                             __u8 direction, __u32 seq, __u32 ack)
{
    if (!value->syn_ns || value->established)
        return;
    __u64 hs = bpf_ktime_get_ns() - value->syn_ns;
    value->handshake_ns = hs;
    value->established = 1;
    count(TCP_COUNT_ESTABLISHED);
    histogram(TCP_KIND_HANDSHAKE, hs);
    event_emit(cfg, TCP_EVENT_ESTABLISHED, key, direction, seq, ack, hs);
}

static __always_inline void observe_out(struct __sk_buff *skb, const struct tcp_config *cfg)
{
    struct tcp_flow_key key;
    struct tcphdr *tcp = 0;
    __u32 payload_len = 0;
    if (!parse_tcp(skb, 0, &key, &tcp, &payload_len))
        return;
    __u64 now = bpf_ktime_get_ns();
    __u32 seq = bpf_ntohl(tcp->seq);
    __u32 ack = bpf_ntohl(tcp->ack_seq);
    struct tcp_flow_value *value = flow_get_or_create(&key, now);
    if (!value)
        return;
    value->last_seen_ns = now;

    if (tcp->syn && !tcp->ack) {
        count(TCP_COUNT_SYN);
        if (value->syn_ns && !value->established && value->syn_origin == 1) {
            value->syn_retransmits++;
            value->retransmits++;
            count(TCP_COUNT_RETRANSMIT);
            event_emit(cfg, TCP_EVENT_RETRANSMIT, &key, 1, seq, ack, 0);
        } else if (!value->syn_ns || value->established) {
            value->syn_ns = now;
            value->syn_origin = 1;
            value->established = 0;
            event_emit(cfg, TCP_EVENT_SYN, &key, 1, seq, ack, 0);
        }
    } else if (tcp->syn && tcp->ack && value->syn_origin == 2) {
        handshake_sample(cfg, &key, value, 1, seq, ack);
    }

    if (payload_len > 0) {
        __u32 end = seq + payload_len;
        if (value->last_out_seq == seq && value->last_out_end == end) {
            value->retransmits++;
            count(TCP_COUNT_RETRANSMIT);
            event_emit(cfg, TCP_EVENT_RETRANSMIT, &key, 1, seq, ack, 0);
        }
        value->last_out_seq = seq;
        value->last_out_end = end;
        value->last_out_ns = now;
    }
    if (tcp->ack && value->last_in_ns && value->last_in_end && ack >= value->last_in_end)
        rtt_sample(cfg, &key, value, 1, seq, ack, value->last_in_ns, &value->last_ack_from_guest);
    if (tcp->rst) {
        value->rst_count++;
        count(TCP_COUNT_RST);
        event_emit(cfg, TCP_EVENT_RST, &key, 1, seq, ack, 0);
    }
    if (tcp->fin) {
        value->fin_count++;
        count(TCP_COUNT_FIN);
        event_emit(cfg, TCP_EVENT_FIN, &key, 1, seq, ack, 0);
    }
}

static __always_inline void observe_in(struct __sk_buff *skb, const struct tcp_config *cfg)
{
    struct tcp_flow_key key;
    struct tcphdr *tcp = 0;
    __u32 payload_len = 0;
    if (!parse_tcp(skb, 1, &key, &tcp, &payload_len))
        return;
    __u64 now = bpf_ktime_get_ns();
    __u32 seq = bpf_ntohl(tcp->seq);
    __u32 ack = bpf_ntohl(tcp->ack_seq);
    struct tcp_flow_value *value = flow_get_or_create(&key, now);
    if (!value)
        return;
    value->last_seen_ns = now;

    if (tcp->syn && !tcp->ack) {
        count(TCP_COUNT_SYN);
        if (value->syn_ns && !value->established && value->syn_origin == 2) {
            value->syn_retransmits++;
            value->retransmits++;
            count(TCP_COUNT_RETRANSMIT);
            event_emit(cfg, TCP_EVENT_RETRANSMIT, &key, 2, seq, ack, 0);
        } else if (!value->syn_ns || value->established) {
            value->syn_ns = now;
            value->syn_origin = 2;
            value->established = 0;
            event_emit(cfg, TCP_EVENT_SYN, &key, 2, seq, ack, 0);
        }
    } else if (tcp->syn && tcp->ack && value->syn_origin == 1) {
        handshake_sample(cfg, &key, value, 2, seq, ack);
    }

    if (payload_len > 0) {
        __u32 end = seq + payload_len;
        if (value->last_in_seq == seq && value->last_in_end == end) {
            value->retransmits++;
            count(TCP_COUNT_RETRANSMIT);
            event_emit(cfg, TCP_EVENT_RETRANSMIT, &key, 2, seq, ack, 0);
        }
        value->last_in_seq = seq;
        value->last_in_end = end;
        value->last_in_ns = now;
    }
    if (tcp->ack && value->last_out_ns && value->last_out_end && ack >= value->last_out_end)
        rtt_sample(cfg, &key, value, 2, seq, ack, value->last_out_ns, &value->last_ack_from_remote);
    if (tcp->rst) {
        value->rst_count++;
        count(TCP_COUNT_RST);
        event_emit(cfg, TCP_EVENT_RST, &key, 2, seq, ack, 0);
    }
    if (tcp->fin) {
        value->fin_count++;
        count(TCP_COUNT_FIN);
        event_emit(cfg, TCP_EVENT_FIN, &key, 2, seq, ack, 0);
    }
}

SEC("tc")
int fluxvm_tcp_out(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct tcp_config *cfg = bpf_map_lookup_elem(&fluxvm_tcp_cfg, &zero);
    if (cfg && cfg->vm_key)
        observe_out(skb, cfg);
    return TC_ACT_OK;
}

SEC("tc")
int fluxvm_tcp_in(struct __sk_buff *skb)
{
    __u32 zero = 0;
    struct tcp_config *cfg = bpf_map_lookup_elem(&fluxvm_tcp_cfg, &zero);
    if (cfg && cfg->vm_key)
        observe_in(skb, cfg);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
