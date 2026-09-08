// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM Service Fabric v1: VM-edge IPv4 L4 service load balancing.
//
// Ingress program (traffic leaving a VM): VIP -> backend DNAT selected from a
// userspace-precomputed Maglev table. Egress program (traffic returning to a
// VM): reverse-NAT backend -> VIP. The program is deliberately separate from
// fluxvm_tc.bpf.c so service rollout does not disturb the security-policy ABI.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_SVC_BACKEND_ENABLED 1u

struct svc4_key {
    __u32 address;      // network byte order, same representation as iphdr::daddr
    __u16 port;         // host byte order
    __u8 protocol;
    __u8 pad;
};

struct svc4_value {
    __u32 service_id;
    __u32 table_size;
};

struct backend_key {
    __u32 service_id;
    __u32 backend_id;
};

struct backend4_value {
    __u32 address;      // network byte order
    __u16 port;         // host byte order
    __u16 flags;
};

struct maglev_key {
    __u32 service_id;
    __u32 slot;
};

struct revnat4_key {
    __u32 backend_address;
    __u32 client_address;
    __u16 backend_port;
    __u16 client_port;
    __u8 protocol;
    __u8 pad[3];
};

struct revnat4_value {
    __u32 vip_address;
    __u16 vip_port;
    __u16 pad;
    __u32 service_id;
    __u32 pad2;
    __u64 last_seen_ns;
};

struct service_stat {
    __u64 forward_packets;
    __u64 forward_bytes;
    __u64 reverse_packets;
    __u64 backend_misses;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct svc4_key);
    __type(value, struct svc4_value);
} fluxvm_svc4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} fluxvm_sguard SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct backend_key);
    __type(value, struct backend4_value);
} fluxvm_backend4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct maglev_key);
    __type(value, __u32);
} fluxvm_maglev4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct revnat4_key);
    __type(value, struct revnat4_value);
} fluxvm_revnat4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct service_stat);
} fluxvm_sstats SEC(".maps");

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

static __always_inline struct service_stat *stat_for(__u32 service_id)
{
    struct service_stat *s = bpf_map_lookup_elem(&fluxvm_sstats, &service_id);
    if (s)
        return s;
    struct service_stat zero = {};
    bpf_map_update_elem(&fluxvm_sstats, &service_id, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_sstats, &service_id);
}

static __always_inline void count_forward(__u32 service_id, __u32 bytes)
{
    struct service_stat *s = stat_for(service_id);
    if (!s)
        return;
    s->forward_packets += 1;
    s->forward_bytes += bytes;
}

static __always_inline void count_reverse(__u32 service_id)
{
    struct service_stat *s = stat_for(service_id);
    if (s)
        s->reverse_packets += 1;
}

static __always_inline void count_miss(__u32 service_id)
{
    struct service_stat *s = stat_for(service_id);
    if (s)
        s->backend_misses += 1;
}

static __always_inline int parse_ports4(
    struct iphdr *iph, void *data_end, __u16 *sport, __u16 *dport,
    struct tcphdr **tcp_out, struct udphdr **udp_out)
{
    void *l4 = (void *)iph + (iph->ihl * 4);
    *tcp_out = 0;
    *udp_out = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(tcp->source);
        *dport = bpf_ntohs(tcp->dest);
        *tcp_out = tcp;
        return 1;
    }
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(udp->source);
        *dport = bpf_ntohs(udp->dest);
        *udp_out = udp;
        return 1;
    }
    return 0;
}

static __always_inline int replace_l4_addr_port(
    struct __sk_buff *skb, struct iphdr *iph, struct tcphdr *tcp,
    struct udphdr *udp, int source, __u32 new_addr, __u16 new_port)
{
    __u32 old_addr = source ? iph->saddr : iph->daddr;
    __u16 old_port_net;
    __u16 new_port_net = bpf_htons(new_port);
    __u32 l4_off = ETH_HLEN + (iph->ihl * 4);

    if (tcp) {
        old_port_net = source ? tcp->source : tcp->dest;
        if (bpf_l4_csum_replace(
                skb, l4_off + offsetof(struct tcphdr, check), old_addr, new_addr,
                BPF_F_PSEUDO_HDR | sizeof(__u32)) < 0)
            return -1;
        if (bpf_l4_csum_replace(
                skb, l4_off + offsetof(struct tcphdr, check), old_port_net,
                new_port_net, sizeof(__u16)) < 0)
            return -1;
    } else if (udp) {
        old_port_net = source ? udp->source : udp->dest;
        if (udp->check != 0) {
            if (bpf_l4_csum_replace(
                    skb, l4_off + offsetof(struct udphdr, check), old_addr, new_addr,
                    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(__u32)) < 0)
                return -1;
            if (bpf_l4_csum_replace(
                    skb, l4_off + offsetof(struct udphdr, check), old_port_net,
                    new_port_net, BPF_F_MARK_MANGLED_0 | sizeof(__u16)) < 0)
                return -1;
        }
    } else {
        return -1;
    }

    if (bpf_l3_csum_replace(
            skb, ETH_HLEN + offsetof(struct iphdr, check), old_addr, new_addr,
            sizeof(__u32)) < 0)
        return -1;

    // Store only after checksum helpers. This avoids carrying packet pointers
    // across skb-writing helpers, which keeps verifier behavior portable.
    __u32 addr_off = ETH_HLEN + (source ? offsetof(struct iphdr, saddr)
                                           : offsetof(struct iphdr, daddr));
    __u32 port_off = l4_off + (source ? 0u : sizeof(__u16));
    if (bpf_skb_store_bytes(skb, addr_off, &new_addr, sizeof(new_addr), 0) < 0)
        return -1;
    if (bpf_skb_store_bytes(skb, port_off, &new_port_net, sizeof(new_port_net), 0) < 0)
        return -1;
    return 0;
}

static __always_inline int update_guard_enabled(void)
{
    __u32 key = 0;
    __u32 *value = bpf_map_lookup_elem(&fluxvm_sguard, &key);
    return value && *value;
}

SEC("tc")
int fvm_svc_out(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_UNSPEC;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl < 5 ||
        (void *)iph + (iph->ihl * 4) > data_end)
        return TC_ACT_UNSPEC;

    // Do not NAT non-first fragments. A service hit must have an L4 tuple.
    if ((bpf_ntohs(iph->frag_off) & 0x3fff) != 0)
        return TC_ACT_UNSPEC;

    // Userspace flips this while replacing service/backend/Maglev maps.
    // Over-deny TCP/UDP during an interrupted update instead of letting a
    // temporarily missing VIP entry bypass the service layer.
    if ((iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) &&
        update_guard_enabled())
        return TC_ACT_SHOT;

    __u16 sport = 0, dport = 0;
    struct tcphdr *tcp = 0;
    struct udphdr *udp = 0;
    int parsed = parse_ports4(iph, data_end, &sport, &dport, &tcp, &udp);
    if (parsed <= 0)
        return TC_ACT_UNSPEC;

    struct svc4_key skey = {
        .address = iph->daddr,
        .port = dport,
        .protocol = iph->protocol,
        .pad = 0,
    };
    struct svc4_value *svc = bpf_map_lookup_elem(&fluxvm_svc4, &skey);
    if (!svc)
        return TC_ACT_UNSPEC;
    __u32 service_id = svc->service_id;
    __u32 table_size = svc->table_size;
    if (table_size == 0) {
        count_miss(service_id);
        return TC_ACT_SHOT;
    }

    __u32 h = flow_hash4(iph->saddr, iph->daddr, sport, dport, iph->protocol);
    struct maglev_key mkey = {
        .service_id = service_id,
        .slot = h % table_size,
    };
    __u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev4, &mkey);
    if (!backend_id) {
        count_miss(service_id);
        return TC_ACT_SHOT;
    }
    struct backend_key bkey = {
        .service_id = service_id,
        .backend_id = *backend_id,
    };
    struct backend4_value *backend = bpf_map_lookup_elem(&fluxvm_backend4, &bkey);
    if (!backend || !(backend->flags & FLUXVM_SVC_BACKEND_ENABLED)) {
        count_miss(service_id);
        return TC_ACT_SHOT;
    }

    __u32 backend_addr = backend->address;
    __u16 backend_port = backend->port;
    struct revnat4_key rkey = {
        .backend_address = backend_addr,
        .client_address = iph->saddr,
        .backend_port = backend_port,
        .client_port = sport,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };
    struct revnat4_value rval = {
        .vip_address = iph->daddr,
        .vip_port = dport,
        .pad = 0,
        .service_id = service_id,
        .pad2 = 0,
        .last_seen_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&fluxvm_revnat4, &rkey, &rval, BPF_ANY);

    if (replace_l4_addr_port(skb, iph, tcp, udp, 0, backend_addr, backend_port) < 0) {
        count_miss(service_id);
        return TC_ACT_SHOT;
    }
    count_forward(service_id, skb->len);

    // Continue to the existing FluxVM policy program at its later priority.
    return TC_ACT_UNSPEC;
}

SEC("tc")
int fvm_svc_in(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_UNSPEC;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl < 5 ||
        (void *)iph + (iph->ihl * 4) > data_end)
        return TC_ACT_UNSPEC;
    if ((bpf_ntohs(iph->frag_off) & 0x3fff) != 0)
        return TC_ACT_UNSPEC;

    __u16 sport = 0, dport = 0;
    struct tcphdr *tcp = 0;
    struct udphdr *udp = 0;
    int parsed = parse_ports4(iph, data_end, &sport, &dport, &tcp, &udp);
    if (parsed <= 0)
        return TC_ACT_UNSPEC;

    struct revnat4_key rkey = {
        .backend_address = iph->saddr,
        .client_address = iph->daddr,
        .backend_port = sport,
        .client_port = dport,
        .protocol = iph->protocol,
        .pad = {0, 0, 0},
    };
    struct revnat4_value *rev = bpf_map_lookup_elem(&fluxvm_revnat4, &rkey);
    if (!rev)
        return TC_ACT_UNSPEC;

    __u32 vip_addr = rev->vip_address;
    __u16 vip_port = rev->vip_port;
    __u32 service_id = rev->service_id;
    if (replace_l4_addr_port(skb, iph, tcp, udp, 1, vip_addr, vip_port) < 0)
        return TC_ACT_SHOT;
    rev->last_seen_ns = bpf_ktime_get_ns();
    count_reverse(service_id);
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
