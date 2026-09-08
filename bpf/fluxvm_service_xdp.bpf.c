// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Optional north-south XDP accelerator for FluxVM Service Fabric v2.
// Maps are reused from the host TC service instance so reverse NAT state
// written here is consumed by the host TC ingress/egress reverse-NAT path.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

struct svc4_key { __u32 address; __u16 port; __u8 protocol; __u8 pad; };
struct svc6_key { __u8 address[16]; __u16 port; __u8 protocol; __u8 pad; };
struct svc_value { __u32 service_id; __u32 table_size; __u8 mode; __u8 flags; __u16 pad; };
struct backend_key { __u32 service_id; __u32 backend_id; };
struct backend4_value { __u32 address; __u16 port; __u16 flags; };
struct backend6_value { __u8 address[16]; __u16 port; __u16 flags; };
struct maglev_key { __u32 service_id; __u32 slot; };
struct snat4_value { __u32 address; __u32 enabled; };
struct snat6_value { __u8 address[16]; __u32 enabled; };
struct nat4_key {
    __u32 backend_address; __u32 reply_address;
    __u16 backend_port; __u16 reply_port; __u8 protocol; __u8 pad[3];
};
struct nat4_value {
    __u32 client_address; __u32 vip_address; __u32 service_id;
    __u16 vip_port; __u16 client_port; __u64 last_seen_ns;
};
struct nat6_key {
    __u8 backend_address[16]; __u8 reply_address[16];
    __u16 backend_port; __u16 reply_port; __u8 protocol; __u8 pad[3];
};
struct nat6_value {
    __u8 client_address[16]; __u8 vip_address[16]; __u64 last_seen_ns;
    __u32 service_id; __u16 vip_port; __u16 client_port;
};
struct service_stat {
    __u64 forward_packets; __u64 forward_bytes; __u64 reverse_packets;
    __u64 backend_misses; __u64 dsr_packets; __u64 snat_packets; __u64 xdp_packets;
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, struct svc4_key); __type(value, struct svc_value); } fluxvm_svc4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, struct svc6_key); __type(value, struct svc_value); } fluxvm_svc6 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u32); } fluxvm_sguard SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, struct backend_key); __type(value, struct backend4_value); } fluxvm_backend4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, struct backend_key); __type(value, struct backend6_value); } fluxvm_backend6 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 262144); __type(key, struct maglev_key); __type(value, __u32); } fluxvm_maglev SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 131072); __type(key, struct nat4_key); __type(value, struct nat4_value); } fluxvm_nat4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 131072); __type(key, struct nat6_key); __type(value, struct nat6_value); } fluxvm_nat6 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, struct snat4_value); } fluxvm_snat4 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, struct snat6_value); } fluxvm_snat6 SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, struct service_stat); } fluxvm_sstats SEC(".maps");
/* XDP-private scratch so fib_lookup does not blow the 512B BPF stack when
 * NAT/DSR frames are live. Not shared with the TC object. */
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

static __always_inline int guard(void)
{
    __u32 key = 0;
    __u32 *v = bpf_map_lookup_elem(&fluxvm_sguard, &key);
    return v && *v;
}

static __always_inline struct service_stat *stat_for(__u32 sid)
{
    struct service_stat *s = bpf_map_lookup_elem(&fluxvm_sstats, &sid);
    if (s)
        return s;
    struct service_stat z = {};
    bpf_map_update_elem(&fluxvm_sstats, &sid, &z, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_sstats, &sid);
}

static __always_inline void count_xdp(__u32 sid, __u32 bytes, int dsr, int snat)
{
    struct service_stat *s = stat_for(sid);
    if (!s)
        return;
    s->forward_packets += 1;
    s->forward_bytes += bytes;
    s->xdp_packets += 1;
    if (dsr)
        s->dsr_packets += 1;
    if (snat)
        s->snat_packets += 1;
}

static __always_inline void count_miss(__u32 sid)
{
    struct service_stat *s = stat_for(sid);
    if (s)
        s->backend_misses += 1;
}

static __always_inline __u32 mix32(__u32 x)
{
    x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15; x *= 0x846ca68bU; x ^= x >> 16;
    return x;
}

static __always_inline __u32 hash4(__u32 s, __u32 d, __u16 sp, __u16 dp, __u8 p)
{
    return mix32(s ^ mix32(d) ^ mix32(((__u32)sp << 16) | dp) ^ ((__u32)p << 24));
}

static __always_inline __u32 hash6(const __u8 *s, const __u8 *d, __u16 sp, __u16 dp, __u8 p)
{
    __u32 h = ((__u32)sp << 16) | dp;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 a = 0, b = 0;
        __builtin_memcpy(&a, s + i * 4, 4);
        __builtin_memcpy(&b, d + i * 4, 4);
        h = mix32(h ^ a ^ mix32(b));
    }
    return mix32(h ^ ((__u32)p << 24));
}


static __always_inline int addr6_equal(const __u8 *a, const __u8 *b)
{
#pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 x = 0, y = 0;
        __builtin_memcpy(&x, a + i * 4, 4);
        __builtin_memcpy(&y, b + i * 4, 4);
        if (x != y) return 0;
    }
    return 1;
}

static __always_inline int nat4_same(
    const struct nat4_value *v, __u32 client, __u16 client_port,
    __u32 vip, __u16 vip_port, __u32 sid)
{
    return v->client_address == client && v->client_port == client_port &&
           v->vip_address == vip && v->vip_port == vip_port && v->service_id == sid;
}

static __always_inline int nat6_same(
    const struct nat6_value *v, const __u8 *client, __u16 client_port,
    const __u8 *vip, __u16 vip_port, __u32 sid)
{
    return v->client_port == client_port && v->vip_port == vip_port &&
           v->service_id == sid && addr6_equal(v->client_address, client) &&
           addr6_equal(v->vip_address, vip);
}

static __always_inline __u16 reserve_nat4(
    __u32 backend, __u32 reply_addr, __u16 backend_port, __u8 protocol,
    __u32 client, __u16 client_port, __u32 vip, __u16 vip_port,
    __u32 sid, __u32 hash)
{
#pragma unroll
    for (int i = 0; i < FLUXVM_NAT_PORT_PROBES; i++) {
        __u16 port = i == 0 ? client_port :
            (__u16)(FLUXVM_NAT_PORT_MIN + ((hash + (__u32)i * 7919u) % FLUXVM_NAT_PORT_SPAN));
        struct nat4_key key = {
            .backend_address = backend, .reply_address = reply_addr,
            .backend_port = backend_port, .reply_port = port,
            .protocol = protocol, .pad = {0,0,0},
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
            .client_address = client, .vip_address = vip, .service_id = sid,
            .vip_port = vip_port, .client_port = client_port,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        if (bpf_map_update_elem(&fluxvm_nat4, &key, &value, BPF_NOEXIST) == 0) return port;
        hit = bpf_map_lookup_elem(&fluxvm_nat4, &key);
        if (hit && nat4_same(hit, client, client_port, vip, vip_port, sid)) return port;
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
            (__u16)(FLUXVM_NAT_PORT_MIN + ((hash + (__u32)i * 7919u) % FLUXVM_NAT_PORT_SPAN));
        struct nat6_key key = {
            .backend_port = backend_port, .reply_port = port,
            .protocol = protocol, .pad = {0,0,0},
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
            .last_seen_ns = bpf_ktime_get_ns(), .service_id = sid,
            .vip_port = vip_port, .client_port = client_port,
        };
        __builtin_memcpy(value.client_address, client, 16);
        __builtin_memcpy(value.vip_address, vip, 16);
        if (bpf_map_update_elem(&fluxvm_nat6, &key, &value, BPF_NOEXIST) == 0) return port;
        hit = bpf_map_lookup_elem(&fluxvm_nat6, &key);
        if (hit && nat6_same(hit, client, client_port, vip, vip_port, sid)) return port;
    }
    return 0;
}

static __always_inline __u16 fold_replace(__u16 check_be, __u16 old_host, __u16 new_host)
{
    __u32 sum = (~bpf_ntohs(check_be) & 0xffffu) +
                (~old_host & 0xffffu) + new_host;
    sum = (sum & 0xffffu) + (sum >> 16);
    sum = (sum & 0xffffu) + (sum >> 16);
    return bpf_htons((__u16)~sum);
}

static __always_inline __u16 csum_addr4(__u16 check, __u32 old_be, __u32 new_be)
{
    __u32 old = bpf_ntohl(old_be), newv = bpf_ntohl(new_be);
    check = fold_replace(check, (__u16)(old >> 16), (__u16)(newv >> 16));
    check = fold_replace(check, (__u16)old, (__u16)newv);
    return check;
}

static __always_inline __u16 csum_addr6(__u16 check, const __u8 *old, const __u8 *newv)
{
#pragma unroll
    for (int i = 0; i < 8; i++) {
        __u16 a = ((__u16)old[i * 2] << 8) | old[i * 2 + 1];
        __u16 b = ((__u16)newv[i * 2] << 8) | newv[i * 2 + 1];
        check = fold_replace(check, a, b);
    }
    return check;
}

static __always_inline void fix_udp_zero(__u8 proto, __u16 *check)
{
    if (proto == IPPROTO_UDP && *check == 0)
        *check = bpf_htons(0xffff);
}

static __always_inline int fib4(
    struct xdp_md *ctx, __u32 src, __u32 route_dst, __u8 proto,
    __u16 sport, __u16 dport, __u16 tot_len, struct bpf_fib_lookup *fib)
{
    __builtin_memset(fib, 0, sizeof(*fib));
    fib->family = FLUXVM_AF_INET;
    fib->ifindex = ctx->ingress_ifindex;
    fib->ipv4_src = src;
    fib->ipv4_dst = route_dst;
    fib->l4_protocol = proto;
    fib->sport = bpf_htons(sport);
    fib->dport = bpf_htons(dport);
    fib->tot_len = tot_len;
    return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

static __always_inline int fib6(
    struct xdp_md *ctx, const __u8 *src, const __u8 *route_dst, __u8 proto,
    __u16 sport, __u16 dport, __u16 tot_len, struct bpf_fib_lookup *fib)
{
    __builtin_memset(fib, 0, sizeof(*fib));
    fib->family = FLUXVM_AF_INET6;
    fib->ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(fib->ipv6_src, src, 16);
    __builtin_memcpy(fib->ipv6_dst, route_dst, 16);
    fib->l4_protocol = proto;
    fib->sport = bpf_htons(sport);
    fib->dport = bpf_htons(dport);
    fib->tot_len = tot_len;
    return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

static __noinline int xdp4(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph, void *end)
{
    if (iph->ihl < 5 || (void *)iph + iph->ihl * 4 > end ||
        (bpf_ntohs(iph->frag_off) & 0x3fff) != 0)
        return XDP_PASS;
    void *l4 = (void *)iph + iph->ihl * 4;
    __u16 sport = 0, dport = 0, *l4_check = 0;
    __u16 old_sport_be = 0, old_dport_be = 0;
    int udp_zero = 0;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > end) return XDP_PASS;
        sport = bpf_ntohs(tcp->source); dport = bpf_ntohs(tcp->dest);
        old_sport_be = tcp->source; old_dport_be = tcp->dest; l4_check = &tcp->check;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > end) return XDP_PASS;
        sport = bpf_ntohs(udp->source); dport = bpf_ntohs(udp->dest);
        old_sport_be = udp->source; old_dport_be = udp->dest; l4_check = &udp->check;
        udp_zero = udp->check == 0;
    } else return XDP_PASS;

    struct svc4_key key = {.address = iph->daddr, .port = dport, .protocol = iph->protocol, .pad = 0};
    struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc4, &key);
    if (!svc) return XDP_PASS;
    __u32 sid = svc->service_id;
    if (!svc->table_size) { count_miss(sid); return XDP_DROP; }
    struct maglev_key mk = {.service_id = sid, .slot = hash4(iph->saddr, iph->daddr, sport, dport, iph->protocol) % svc->table_size};
    __u32 *bid = bpf_map_lookup_elem(&fluxvm_maglev, &mk);
    if (!bid) { count_miss(sid); return XDP_DROP; }
    struct backend_key bk = {.service_id = sid, .backend_id = *bid};
    struct backend4_value *be = bpf_map_lookup_elem(&fluxvm_backend4, &bk);
    if (!be || !(be->flags & FLUXVM_SVC_BACKEND_ENABLED)) { count_miss(sid); return XDP_DROP; }

    if (svc->mode == FLUXVM_SVC_MODE_DSR) {
        struct bpf_fib_lookup *fib = fib_scratch();
        if (!fib) return XDP_PASS;
        int rc = fib4(ctx, iph->saddr, be->address, iph->protocol, sport, dport,
                      bpf_ntohs(iph->tot_len), fib);
        if (rc != BPF_FIB_LKUP_RET_SUCCESS) return XDP_PASS;
        __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
        count_xdp(sid, (__u32)((long)end - (long)eth), 1, 0);
        return bpf_redirect(fib->ifindex, 0);
    }
    if (svc->mode != FLUXVM_SVC_MODE_NAT) { count_miss(sid); return XDP_DROP; }

    struct snat4_value *snat = bpf_map_lookup_elem(&fluxvm_snat4, &sid);
    if (!snat || !snat->enabled) { count_miss(sid); return XDP_DROP; }
    struct bpf_fib_lookup *fib = fib_scratch();
    if (!fib) return XDP_PASS;
    int rc = fib4(ctx, snat->address, be->address, iph->protocol, sport, be->port,
                  bpf_ntohs(iph->tot_len), fib);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) return XDP_PASS;

    __u32 old_src = iph->saddr, old_dst = iph->daddr;
    __u32 h = hash4(old_src, old_dst, sport, dport, iph->protocol);
    __u16 reply_port = reserve_nat4(
        be->address, snat->address, be->port, iph->protocol,
        old_src, sport, old_dst, dport, sid, h);
    if (!reply_port) { count_miss(sid); return XDP_DROP; }

    iph->check = csum_addr4(iph->check, old_src, snat->address);
    iph->check = csum_addr4(iph->check, old_dst, be->address);
    if (!udp_zero) {
        *l4_check = csum_addr4(*l4_check, old_src, snat->address);
        *l4_check = csum_addr4(*l4_check, old_dst, be->address);
        *l4_check = fold_replace(*l4_check, bpf_ntohs(old_sport_be), reply_port);
        *l4_check = fold_replace(*l4_check, bpf_ntohs(old_dport_be), be->port);
        fix_udp_zero(iph->protocol, l4_check);
    }
    iph->saddr = snat->address;
    iph->daddr = be->address;
    __u16 new_sport = bpf_htons(reply_port), new_dport = bpf_htons(be->port);
    if (iph->protocol == IPPROTO_TCP) {
        ((struct tcphdr *)l4)->source = new_sport;
        ((struct tcphdr *)l4)->dest = new_dport;
    } else {
        ((struct udphdr *)l4)->source = new_sport;
        ((struct udphdr *)l4)->dest = new_dport;
    }
    __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
    count_xdp(sid, (__u32)((long)end - (long)eth), 0, 1);
    return bpf_redirect(fib->ifindex, 0);
}

static __noinline int xdp6(struct xdp_md *ctx, struct ethhdr *eth, struct ipv6hdr *ip6, void *end)
{
    void *l4 = (void *)(ip6 + 1);
    __u16 sport = 0, dport = 0, *l4_check = 0, old_sport_be = 0, old_dport_be = 0;
    if (ip6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > end) return XDP_PASS;
        sport = bpf_ntohs(tcp->source); dport = bpf_ntohs(tcp->dest);
        old_sport_be = tcp->source; old_dport_be = tcp->dest; l4_check = &tcp->check;
    } else if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > end) return XDP_PASS;
        sport = bpf_ntohs(udp->source); dport = bpf_ntohs(udp->dest);
        old_sport_be = udp->source; old_dport_be = udp->dest; l4_check = &udp->check;
    } else return XDP_PASS;

    struct svc6_key key = {.port = dport, .protocol = ip6->nexthdr, .pad = 0};
    __builtin_memcpy(key.address, ip6->daddr.in6_u.u6_addr8, 16);
    struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc6, &key);
    if (!svc) return XDP_PASS;
    __u32 sid = svc->service_id;
    if (!svc->table_size) { count_miss(sid); return XDP_DROP; }
    struct maglev_key mk = {.service_id = sid, .slot = hash6(ip6->saddr.in6_u.u6_addr8, ip6->daddr.in6_u.u6_addr8, sport, dport, ip6->nexthdr) % svc->table_size};
    __u32 *bid = bpf_map_lookup_elem(&fluxvm_maglev, &mk);
    if (!bid) { count_miss(sid); return XDP_DROP; }
    struct backend_key bk = {.service_id = sid, .backend_id = *bid};
    struct backend6_value *be = bpf_map_lookup_elem(&fluxvm_backend6, &bk);
    if (!be || !(be->flags & FLUXVM_SVC_BACKEND_ENABLED)) { count_miss(sid); return XDP_DROP; }

    __u16 tot_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
    if (svc->mode == FLUXVM_SVC_MODE_DSR) {
        struct bpf_fib_lookup *fib = fib_scratch();
        if (!fib) return XDP_PASS;
        int rc = fib6(ctx, ip6->saddr.in6_u.u6_addr8, be->address, ip6->nexthdr,
                      sport, dport, tot_len, fib);
        if (rc != BPF_FIB_LKUP_RET_SUCCESS) return XDP_PASS;
        __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
        count_xdp(sid, (__u32)((long)end - (long)eth), 1, 0);
        return bpf_redirect(fib->ifindex, 0);
    }
    if (svc->mode != FLUXVM_SVC_MODE_NAT) { count_miss(sid); return XDP_DROP; }

    struct snat6_value *snat = bpf_map_lookup_elem(&fluxvm_snat6, &sid);
    if (!snat || !snat->enabled) { count_miss(sid); return XDP_DROP; }
    struct bpf_fib_lookup *fib = fib_scratch();
    if (!fib) return XDP_PASS;
    int rc = fib6(ctx, snat->address, be->address, ip6->nexthdr,
                  sport, be->port, tot_len, fib);
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) return XDP_PASS;

    __u8 old_src[16], old_dst[16];
    __builtin_memcpy(old_src, ip6->saddr.in6_u.u6_addr8, 16);
    __builtin_memcpy(old_dst, ip6->daddr.in6_u.u6_addr8, 16);
    __u32 h = hash6(old_src, old_dst, sport, dport, ip6->nexthdr);
    __u16 reply_port = reserve_nat6(
        be->address, snat->address, be->port, ip6->nexthdr,
        old_src, sport, old_dst, dport, sid, h);
    if (!reply_port) { count_miss(sid); return XDP_DROP; }

    *l4_check = csum_addr6(*l4_check, old_src, snat->address);
    *l4_check = csum_addr6(*l4_check, old_dst, be->address);
    *l4_check = fold_replace(*l4_check, bpf_ntohs(old_sport_be), reply_port);
    *l4_check = fold_replace(*l4_check, bpf_ntohs(old_dport_be), be->port);
    fix_udp_zero(ip6->nexthdr, l4_check);
    __builtin_memcpy(ip6->saddr.in6_u.u6_addr8, snat->address, 16);
    __builtin_memcpy(ip6->daddr.in6_u.u6_addr8, be->address, 16);
    __u16 new_sport = bpf_htons(reply_port), new_dport = bpf_htons(be->port);
    if (ip6->nexthdr == IPPROTO_TCP) {
        ((struct tcphdr *)l4)->source = new_sport;
        ((struct tcphdr *)l4)->dest = new_dport;
    } else {
        ((struct udphdr *)l4)->source = new_sport;
        ((struct udphdr *)l4)->dest = new_dport;
    }
    __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
    count_xdp(sid, (__u32)((long)end - (long)eth), 0, 1);
    return bpf_redirect(fib->ifindex, 0);
}

SEC("xdp")
int fvm_svc_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    __u16 proto = bpf_ntohs(eth->h_proto);
    if (guard() && (proto == ETH_P_IP || proto == ETH_P_IPV6)) return XDP_DROP;
    if (proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > end) return XDP_PASS;
        return xdp4(ctx, eth, iph, end);
    }
    if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > end) return XDP_PASS;
        return xdp6(ctx, eth, ip6, end);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
