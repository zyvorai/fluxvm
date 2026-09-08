// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM Service Fabric v2: dual-stack VM-edge + host-uplink TC dataplane.
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

#define FLUXVM_SVC_BACKEND_ENABLED 1u
#define FLUXVM_SVC_MODE_NAT 1u
#define FLUXVM_SVC_MODE_DSR 2u
#define FLUXVM_NAT_F_SNAT 1u
#define FLUXVM_NAT_PORT_MIN 32768u
#define FLUXVM_NAT_PORT_SPAN 28232u
#define FLUXVM_NAT_PORT_PROBES 16
#define FLUXVM_AF_INET 2
#define FLUXVM_AF_INET6 10

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
    __u32 client_address;
    __u32 vip_address;
    __u32 service_id;
    __u16 vip_port;
    __u16 client_port;
    __u64 last_seen_ns;
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
    __u8 client_address[16];
    __u8 vip_address[16];
    __u64 last_seen_ns;
    __u32 service_id;
    __u16 vip_port;
    __u16 client_port;
};

struct service_stat {
    __u64 forward_packets;
    __u64 forward_bytes;
    __u64 reverse_packets;
    __u64 backend_misses;
    __u64 dsr_packets;
    __u64 snat_packets;
    __u64 xdp_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct svc4_key);
    __type(value, struct svc_value);
} fluxvm_svc4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
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
    __uint(max_entries, 16384);
    __type(key, struct backend_key);
    __type(value, struct backend4_value);
} fluxvm_backend4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct backend_key);
    __type(value, struct backend6_value);
} fluxvm_backend6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct maglev_key);
    __type(value, __u32);
} fluxvm_maglev SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct nat4_key);
    __type(value, struct nat4_value);
} fluxvm_nat4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct nat6_key);
    __type(value, struct nat6_value);
} fluxvm_nat6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct snat4_value);
} fluxvm_snat4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct snat6_value);
} fluxvm_snat6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct service_stat);
} fluxvm_sstats SEC(".maps");

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
    __u32 vip, __u16 vip_port, __u32 sid)
{
    return v->client_address == client && v->client_port == client_port &&
           v->vip_address == vip && v->vip_port == vip_port &&
           v->service_id == sid;
}

static __always_inline int nat6_same(
    const struct nat6_value *v, const __u8 *client, __u16 client_port,
    const __u8 *vip, __u16 vip_port, __u32 sid)
{
    return v->client_port == client_port && v->vip_port == vip_port &&
           v->service_id == sid && addr6_equal(v->client_address, client) &&
           addr6_equal(v->vip_address, vip);
}

/* Reserve a reply tuple. Preserve the original source port when possible;
 * on collision use a bounded deterministic high-port probe. This prevents
 * SNAT collisions and also handles two VIPs converging on the same backend. */
static __always_inline __u16 reserve_nat4(
    __u32 backend, __u32 reply_addr, __u16 backend_port, __u8 protocol,
    __u32 client, __u16 client_port, __u32 vip, __u16 vip_port,
    __u32 sid, __u32 hash)
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
            if (nat4_same(hit, client, client_port, vip, vip_port, sid)) {
                hit->last_seen_ns = bpf_ktime_get_ns();
                return port;
            }
            continue;
        }
        struct nat4_value value = {
            .client_address = client,
            .vip_address = vip,
            .service_id = sid,
            .vip_port = vip_port,
            .client_port = client_port,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        if (bpf_map_update_elem(&fluxvm_nat4, &key, &value, BPF_NOEXIST) == 0)
            return port;
        hit = bpf_map_lookup_elem(&fluxvm_nat4, &key);
        if (hit && nat4_same(hit, client, client_port, vip, vip_port, sid))
            return port;
    }
    return 0;
}

static __always_inline __u16 reserve_nat6(
    const __u8 *backend, const __u8 *reply_addr, __u16 backend_port, __u8 protocol,
    const __u8 *client, __u16 client_port, const __u8 *vip, __u16 vip_port,
    __u32 sid, __u32 hash)
{
#pragma unroll
    for (int i = 0; i < FLUXVM_NAT_PORT_PROBES; i++) {
        __u16 port = i == 0 ? client_port :
            (__u16)(FLUXVM_NAT_PORT_MIN +
                    ((hash + (__u32)i * 7919u) % FLUXVM_NAT_PORT_SPAN));
        if (port == 0)
            continue;
        struct nat6_key key = {
            .backend_port = backend_port,
            .reply_port = port,
            .protocol = protocol,
            .pad = {0, 0, 0},
        };
        __builtin_memcpy(key.backend_address, backend, 16);
        __builtin_memcpy(key.reply_address, reply_addr, 16);
        struct nat6_value *hit = bpf_map_lookup_elem(&fluxvm_nat6, &key);
        if (hit) {
            if (nat6_same(hit, client, client_port, vip, vip_port, sid)) {
                hit->last_seen_ns = bpf_ktime_get_ns();
                return port;
            }
            continue;
        }
        struct nat6_value value = {
            .last_seen_ns = bpf_ktime_get_ns(),
            .service_id = sid,
            .vip_port = vip_port,
            .client_port = client_port,
        };
        __builtin_memcpy(value.client_address, client, 16);
        __builtin_memcpy(value.vip_address, vip, 16);
        if (bpf_map_update_elem(&fluxvm_nat6, &key, &value, BPF_NOEXIST) == 0)
            return port;
        hit = bpf_map_lookup_elem(&fluxvm_nat6, &key);
        if (hit && nat6_same(hit, client, client_port, vip, vip_port, sid))
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
    struct bpf_fib_lookup fib = {};
    fib.family = FLUXVM_AF_INET;
    fib.ifindex = skb->ifindex;
    fib.ipv4_src = src;
    fib.ipv4_dst = route_dst;
    fib.l4_protocol = protocol;
    fib.sport = bpf_htons(sport);
    fib.dport = bpf_htons(dport);
    int rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return TC_ACT_SHOT;
    if (bpf_skb_store_bytes(skb, 0, fib.dmac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(skb, ETH_ALEN, fib.smac, ETH_ALEN, 0) < 0)
        return TC_ACT_SHOT;
    return bpf_redirect(fib.ifindex, 0);
}

static __always_inline int fib_redirect6(
    struct __sk_buff *skb, const __u8 *route_dst, const __u8 *src,
    __u8 protocol, __u16 sport, __u16 dport)
{
    struct bpf_fib_lookup fib = {};
    fib.family = FLUXVM_AF_INET6;
    fib.ifindex = skb->ifindex;
    __builtin_memcpy(fib.ipv6_src, src, 16);
    __builtin_memcpy(fib.ipv6_dst, route_dst, 16);
    fib.l4_protocol = protocol;
    fib.sport = bpf_htons(sport);
    fib.dport = bpf_htons(dport);
    int rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS)
        return TC_ACT_SHOT;
    if (bpf_skb_store_bytes(skb, 0, fib.dmac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(skb, ETH_ALEN, fib.smac, ETH_ALEN, 0) < 0)
        return TC_ACT_SHOT;
    return bpf_redirect(fib.ifindex, 0);
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

    __u32 old_src = iph->saddr, old_dst = iph->daddr;
    __u32 new_src = nat->vip_address;
    __u32 new_dst = nat->client_address;
    __u16 new_sport = nat->vip_port;
    __u16 new_dport = nat->client_port;
    __u32 sid = nat->service_id;
    nat->last_seen_ns = bpf_ktime_get_ns();
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
    struct nat6_key key = {
        .backend_port = sport,
        .reply_port = dport,
        .protocol = ip6->nexthdr,
        .pad = {0, 0, 0},
    };
    __builtin_memcpy(key.backend_address, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(key.reply_address, ip6->daddr.in6_u.u6_addr8, 16);
    struct nat6_value *nat = bpf_map_lookup_elem(&fluxvm_nat6, &key);
    if (!nat)
        return 0;

    __u8 old_src[16], old_dst[16], new_dst[16];
    __builtin_memcpy(old_src, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(old_dst, ip6->daddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(new_dst, nat->client_address, 16);
    __u16 new_sport = nat->vip_port;
    __u16 new_dport = nat->client_port;
    __u32 sid = nat->service_id;
    nat->last_seen_ns = bpf_ktime_get_ns();
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
    if (svc->table_size == 0) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }

    __u32 h = flow_hash4(iph->saddr, iph->daddr, sport, dport, iph->protocol);
    struct maglev_key mkey = {.service_id = sid, .slot = h % svc->table_size};
    __u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
    if (!backend_id) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }
    struct backend_key bkey = {.service_id = sid, .backend_id = *backend_id};
    struct backend4_value *backend = bpf_map_lookup_elem(&fluxvm_backend4, &bkey);
    if (!backend || !(backend->flags & FLUXVM_SVC_BACKEND_ENABLED)) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }

    if (svc->mode == FLUXVM_SVC_MODE_DSR) {
        int action = fib_redirect4(
            skb, backend->address, iph->saddr, iph->protocol, sport, dport);
        if (action == TC_ACT_SHOT)
            count_miss(sid);
        else
            count_forward(sid, skb->len, 1, 0);
        return action;
    }
    if (svc->mode != FLUXVM_SVC_MODE_NAT) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }

    __u32 old_src = iph->saddr, old_dst = iph->daddr;
    __u32 new_src = old_src;
    __u16 flags = 0;
    struct snat4_value *snat = bpf_map_lookup_elem(&fluxvm_snat4, &sid);
    if (snat && snat->enabled) {
        new_src = snat->address;
        flags |= FLUXVM_NAT_F_SNAT;
    }
    __u16 reply_port = reserve_nat4(
        backend->address, new_src, backend->port, iph->protocol,
        old_src, sport, old_dst, dport, sid, h);
    if (!reply_port) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }
    if (rewrite4(
            skb, l4_off, iph->protocol, udp_csum,
            old_src, new_src, old_dst, backend->address,
            sport, reply_port, dport, backend->port) < 0) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }
    count_forward(sid, skb->len, 0, flags != 0);
    return TC_ACT_UNSPEC;
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
    if (svc->table_size == 0) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }

    __u32 h = hash_words6(
        ip6->saddr.in6_u.u6_addr8, ip6->daddr.in6_u.u6_addr8,
        sport, dport, ip6->nexthdr);
    struct maglev_key mkey = {.service_id = sid, .slot = h % svc->table_size};
    __u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
    if (!backend_id) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }
    struct backend_key bkey = {.service_id = sid, .backend_id = *backend_id};
    struct backend6_value *backend = bpf_map_lookup_elem(&fluxvm_backend6, &bkey);
    if (!backend || !(backend->flags & FLUXVM_SVC_BACKEND_ENABLED)) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }

    if (svc->mode == FLUXVM_SVC_MODE_DSR) {
        int action = fib_redirect6(
            skb, backend->address, ip6->saddr.in6_u.u6_addr8,
            ip6->nexthdr, sport, dport);
        if (action == TC_ACT_SHOT)
            count_miss(sid);
        else
            count_forward(sid, skb->len, 1, 0);
        return action;
    }
    if (svc->mode != FLUXVM_SVC_MODE_NAT) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }

    __u8 old_src[16], old_dst[16], new_src[16];
    __builtin_memcpy(old_src, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(old_dst, ip6->daddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(new_src, old_src, 16);
    __u16 flags = 0;
    struct snat6_value *snat = bpf_map_lookup_elem(&fluxvm_snat6, &sid);
    if (snat && snat->enabled) {
        __builtin_memcpy(new_src, snat->address, 16);
        flags |= FLUXVM_NAT_F_SNAT;
    }
    __u16 reply_port = reserve_nat6(
        backend->address, new_src, backend->port, ip6->nexthdr,
        old_src, sport, old_dst, dport, sid, h);
    if (!reply_port) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }
    if (rewrite6(
            skb, l4_off, ip6->nexthdr,
            old_src, new_src, old_dst, backend->address,
            sport, reply_port, dport, backend->port) < 0) {
        count_miss(sid);
        return TC_ACT_SHOT;
    }
    count_forward(sid, skb->len, 0, flags != 0);
    return TC_ACT_UNSPEC;
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
            return TC_ACT_UNSPEC;
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
            return TC_ACT_UNSPEC;
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
        return rev < 0 ? TC_ACT_SHOT : TC_ACT_UNSPEC;
    }

    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_UNSPEC;
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return TC_ACT_UNSPEC;
        int rev = reverse6(skb, ip6, data_end);
        return rev < 0 ? TC_ACT_SHOT : TC_ACT_UNSPEC;
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
