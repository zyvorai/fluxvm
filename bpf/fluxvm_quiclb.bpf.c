// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Set 10: QUIC-aware XDP DSR load balancer.
// The program is node-local. It never mutates Cilium/Fabric maps and only
// attaches when the userspace loader has exclusive ownership of the XDP hook.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct fluxvm_vlan_hdr { __be16 tci; __be16 encapsulated_proto; };

#define FLUXVM_AF_INET 4
#define FLUXVM_AF_INET6 6
#define FLUXVM_QUIC_MAX_CID 20
#define FLUXVM_SERVICE_F_QUIC_ONLY (1u << 0)
#define FLUXVM_BACKEND_READY       (1u << 0)
#define FLUXVM_BACKEND_DRAINING    (1u << 1)
#define FLUXVM_BACKEND_UNHEALTHY   (1u << 2)
#define FLUXVM_EVENT_SELECT        1u
#define FLUXVM_EVENT_AFFINITY_HIT  2u
#define FLUXVM_EVENT_RESELECT      3u
#define FLUXVM_EVENT_PARSE_ERROR   4u
#define FLUXVM_EVENT_BACKEND_MISS  5u
#define FLUXVM_EVENT_NON_QUIC      6u

struct generation_value { __u32 generation; };

struct service_key {
    __u32 generation;
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 vip[16];
};
_Static_assert(sizeof(struct service_key) == 24, "service key ABI");

struct service_value {
    __u32 service_id;
    __u32 maglev_size;
    __u32 flags;
    __u32 short_dcid_len;
    __u32 sample_rate;
};
_Static_assert(sizeof(struct service_value) == 20, "service value ABI");

struct backend_key { __u32 generation; __u32 service_id; __u32 backend_id; };
struct backend_value {
    __u32 ifindex;
    __u32 flags;
    __u8 dmac[6];
    __u8 pad[2];
};
_Static_assert(sizeof(struct backend_value) == 16, "backend value ABI");

struct maglev_key { __u32 generation; __u32 service_id; __u32 slot; };

struct affinity_key {
    __u32 service_id;
    __u8 cid_len;
    __u8 cid[FLUXVM_QUIC_MAX_CID];
    __u8 pad[3];
};
_Static_assert(sizeof(struct affinity_key) == 28, "affinity key ABI");

struct affinity_value { __u32 backend_id; __u32 reserved; __u64 last_seen_ns; };

struct service_stats {
    __u64 packets;
    __u64 bytes;
    __u64 quic_long;
    __u64 quic_short;
    __u64 affinity_hits;
    __u64 affinity_misses;
    __u64 tuple_fallbacks;
    __u64 backend_misses;
    __u64 redirects;
    __u64 non_quic_pass;
    __u64 parse_errors;
    __u64 reselections;
    __u64 affinity_store_failures;
};

struct quic_event {
    __u64 timestamp_ns;
    __u32 service_id;
    __u32 backend_id;
    __u32 ifindex;
    __u32 event_type;
    __u32 cid_hash;
    __u16 sport;
    __u16 dport;
    __u8 family;
    __u8 cid_len;
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct generation_value);
} fluxvm_quic_gen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct service_key);
    __type(value, struct service_value);
} fluxvm_quic_services SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct backend_key);
    __type(value, struct backend_value);
} fluxvm_quic_backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 524288);
    __type(key, struct maglev_key);
    __type(value, __u32);
} fluxvm_quic_maglev SEC(".maps");

#ifdef FLUXVM_QUICLB_OFFLOAD_PROFILE
#define FLUXVM_AFFINITY_MAP_TYPE BPF_MAP_TYPE_HASH
#else
#define FLUXVM_AFFINITY_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#endif
struct {
    __uint(type, FLUXVM_AFFINITY_MAP_TYPE);
    __uint(max_entries, 131072);
    __type(key, struct affinity_key);
    __type(value, struct affinity_value);
} fluxvm_quic_affinity SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct service_stats);
} fluxvm_quic_stats SEC(".maps");

#ifndef FLUXVM_QUICLB_OFFLOAD_PROFILE
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fluxvm_quic_events SEC(".maps");
#endif

static __always_inline void stat_add(__u32 sid, __u32 which, __u64 n)
{
    struct service_stats *s = bpf_map_lookup_elem(&fluxvm_quic_stats, &sid);
    if (!s) {
        struct service_stats z = {};
        bpf_map_update_elem(&fluxvm_quic_stats, &sid, &z, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&fluxvm_quic_stats, &sid);
        if (!s) return;
    }
    switch (which) {
    case 0: __sync_fetch_and_add(&s->packets, n); break;
    case 1: __sync_fetch_and_add(&s->bytes, n); break;
    case 2: __sync_fetch_and_add(&s->quic_long, n); break;
    case 3: __sync_fetch_and_add(&s->quic_short, n); break;
    case 4: __sync_fetch_and_add(&s->affinity_hits, n); break;
    case 5: __sync_fetch_and_add(&s->affinity_misses, n); break;
    case 6: __sync_fetch_and_add(&s->tuple_fallbacks, n); break;
    case 7: __sync_fetch_and_add(&s->backend_misses, n); break;
    case 8: __sync_fetch_and_add(&s->redirects, n); break;
    case 9: __sync_fetch_and_add(&s->non_quic_pass, n); break;
    case 10: __sync_fetch_and_add(&s->parse_errors, n); break;
    case 11: __sync_fetch_and_add(&s->reselections, n); break;
    case 12: __sync_fetch_and_add(&s->affinity_store_failures, n); break;
    default: break;
    }
}

static __always_inline __u32 affinity_hash(const struct affinity_key *k)
{
    __u32 h = 2166136261u ^ k->service_id;
    h = (h ^ k->cid_len) * 16777619u;
#pragma unroll
    for (int i = 0; i < FLUXVM_QUIC_MAX_CID; i++)
        h = (h ^ k->cid[i]) * 16777619u;
    return h ? h : 1;
}

static __always_inline void tuple_fallback4(struct affinity_key *a, struct iphdr *iph,
                                             __u16 sport, __u16 dport)
{
    __u32 h1 = 2166136261u;
    const __u8 *s = (const __u8 *)&iph->saddr;
    const __u8 *d = (const __u8 *)&iph->daddr;
#pragma unroll
    for (int i = 0; i < 4; i++) h1 = (h1 ^ s[i]) * 16777619u;
#pragma unroll
    for (int i = 0; i < 4; i++) h1 = (h1 ^ d[i]) * 16777619u;
    h1 = (h1 ^ sport) * 16777619u;
    h1 = (h1 ^ dport) * 16777619u;
    a->cid_len = 0;
    __builtin_memcpy(a->cid, &h1, sizeof(h1));
}

static __always_inline void tuple_fallback6(struct affinity_key *a, struct ipv6hdr *ip6,
                                             __u16 sport, __u16 dport)
{
    __u32 h1 = 2166136261u;
#pragma unroll
    for (int i = 0; i < 16; i++) h1 = (h1 ^ ip6->saddr.s6_addr[i]) * 16777619u;
#pragma unroll
    for (int i = 0; i < 16; i++) h1 = (h1 ^ ip6->daddr.s6_addr[i]) * 16777619u;
    h1 = (h1 ^ sport) * 16777619u;
    h1 = (h1 ^ dport) * 16777619u;
    a->cid_len = 0;
    __builtin_memcpy(a->cid, &h1, sizeof(h1));
}

static __always_inline int parse_quic(void *payload, void *data_end, __u32 short_len,
                                      struct affinity_key *a, int *kind)
{
    __u8 *p = payload;
    if ((void *)(p + 1) > data_end) return -1;
    __u8 first = p[0];
    if (!(first & 0x40)) return 0;
    if (first & 0x80) {
        if ((void *)(p + 6) > data_end) return -1;
        __u8 len = p[5];
        if (len == 0 || len > FLUXVM_QUIC_MAX_CID) return 0;
        // Runtime check for the real, possibly-short packet: does NOT by
        // itself make the unrolled loop below verifier-safe (see the
        // per-iteration check inside it), but it does keep short, valid
        // packets (short CID, no MAX_CID padding) from being rejected here
        // -- a stricter compile-time-constant-only bound was tried first
        // and reproduced a real functional regression: it rejected every
        // packet whose actual length was less than 6+FLUXVM_QUIC_MAX_CID,
        // even ones whose declared CID fully fit.
        if ((void *)(p + 6 + len) > data_end) return -1;
        a->cid_len = len;
#pragma unroll
        for (int i = 0; i < FLUXVM_QUIC_MAX_CID; i++) {
            // Both conditions are needed: `i < len` is the logical/protocol
            // bound; the explicit fixed-offset comparison against data_end
            // (not a variable-computed pointer) is what the verifier can
            // actually prove safe for this specific unrolled access. The
            // first is implied by the len check above for real packets,
            // but the verifier can't derive that on its own.
            if (i < len && (void *)(p + 6 + i + 1) <= data_end) {
                a->cid[i] = p[6 + i];
            }
        }
        *kind = 1;
        return 1;
    }
    if (short_len == 0 || short_len > FLUXVM_QUIC_MAX_CID) return 0;
    if ((void *)(p + 1 + short_len) > data_end) return -1;
    a->cid_len = (__u8)short_len;
#pragma unroll
    for (int i = 0; i < FLUXVM_QUIC_MAX_CID; i++) {
        if ((__u32)i < short_len && (void *)(p + 1 + i + 1) <= data_end) {
            a->cid[i] = p[1 + i];
        }
    }
    *kind = 2;
    return 1;
}

#ifndef FLUXVM_QUICLB_OFFLOAD_PROFILE
static __always_inline void emit_event(struct xdp_md *ctx, const struct service_value *svc,
                                       __u32 backend, __u32 type, __u32 cid_hash,
                                       __u16 sport, __u16 dport, __u8 family,
                                       __u8 cid_len)
{
    if (type == FLUXVM_EVENT_SELECT && svc->sample_rate > 1 &&
        (bpf_get_prandom_u32() % svc->sample_rate) != 0) return;
    struct quic_event *e = bpf_ringbuf_reserve(&fluxvm_quic_events, sizeof(*e), 0);
    if (!e) return;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->service_id = svc->service_id;
    e->backend_id = backend;
    e->ifindex = ctx->ingress_ifindex;
    e->event_type = type;
    e->cid_hash = cid_hash;
    e->sport = sport;
    e->dport = dport;
    e->family = family;
    e->cid_len = cid_len;
    e->pad[0] = e->pad[1] = 0;
    bpf_ringbuf_submit(e, 0);
}
#else
static __always_inline void emit_event(struct xdp_md *ctx, const struct service_value *svc,
                                       __u32 backend, __u32 type, __u32 cid_hash,
                                       __u16 sport, __u16 dport, __u8 family,
                                       __u8 cid_len)
{
    (void)ctx; (void)svc; (void)backend; (void)type; (void)cid_hash;
    (void)sport; (void)dport; (void)family; (void)cid_len;
}
#endif

static __always_inline int backend_usable(__u32 gen, __u32 service_id, __u32 backend_id,
                                          int existing, struct backend_value **out)
{
    struct backend_key k = {.generation = gen, .service_id = service_id, .backend_id = backend_id};
    struct backend_value *b = bpf_map_lookup_elem(&fluxvm_quic_backends, &k);
    if (!b || (b->flags & FLUXVM_BACKEND_UNHEALTHY)) return 0;
    if (existing) {
        if (!(b->flags & (FLUXVM_BACKEND_READY | FLUXVM_BACKEND_DRAINING))) return 0;
    } else if (!(b->flags & FLUXVM_BACKEND_READY)) {
        return 0;
    }
    *out = b;
    return 1;
}

static __always_inline int select_backend(struct xdp_md *ctx, __u32 gen,
                                           const struct service_value *svc,
                                           struct affinity_key *a, __u16 sport,
                                           __u16 dport, __u8 family,
                                           struct backend_value **out)
{
    __u32 h = affinity_hash(a);
    struct affinity_value *av = bpf_map_lookup_elem(&fluxvm_quic_affinity, a);
    if (av && backend_usable(gen, svc->service_id, av->backend_id, 1, out)) {
        av->last_seen_ns = bpf_ktime_get_ns();
        stat_add(svc->service_id, 4, 1);
        emit_event(ctx, svc, av->backend_id, FLUXVM_EVENT_AFFINITY_HIT, h,
                   sport, dport, family, a->cid_len);
        return av->backend_id;
    }
    stat_add(svc->service_id, 5, 1);
    if (!svc->maglev_size) return 0;
    struct maglev_key mk = {.generation = gen, .service_id = svc->service_id,
                            .slot = h % svc->maglev_size};
    __u32 *bid = bpf_map_lookup_elem(&fluxvm_quic_maglev, &mk);
    struct backend_value *b = 0;
    if (!bid || !backend_usable(gen, svc->service_id, *bid, 0, &b)) {
        stat_add(svc->service_id, 7, 1);
        emit_event(ctx, svc, bid ? *bid : 0, FLUXVM_EVENT_BACKEND_MISS, h,
                   sport, dport, family, a->cid_len);
        return 0;
    }
    struct affinity_value nv = {.backend_id = *bid, .last_seen_ns = bpf_ktime_get_ns()};
    if (bpf_map_update_elem(&fluxvm_quic_affinity, a, &nv, BPF_ANY))
        stat_add(svc->service_id, 12, 1);
    if (av) stat_add(svc->service_id, 11, 1);
    emit_event(ctx, svc, *bid, av ? FLUXVM_EVENT_RESELECT : FLUXVM_EVENT_SELECT,
               h, sport, dport, family, a->cid_len);
    *out = b;
    return *bid;
}

static __always_inline int redirect_service(struct xdp_md *ctx, struct ethhdr *eth,
                                             __u32 gen, const struct service_value *svc,
                                             struct affinity_key *a, __u16 sport,
                                             __u16 dport, __u8 family)
{
    struct backend_value *b = 0;
    __u32 bid = select_backend(ctx, gen, svc, a, sport, dport, family, &b);
    if (!bid || !b) return XDP_PASS;
    __builtin_memcpy(eth->h_dest, b->dmac, ETH_ALEN);
    stat_add(svc->service_id, 8, 1);
    return bpf_redirect(b->ifindex, 0);
}

static __always_inline int handle4(struct xdp_md *ctx, struct ethhdr *eth,
                                    void *l3, void *data_end, __u32 gen)
{
    struct iphdr *iph = l3;
    if ((void *)(iph + 1) > data_end || iph->ihl < 5) return XDP_PASS;
    if ((void *)iph + iph->ihl * 4 > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;
    if ((bpf_ntohs(iph->frag_off) & 0x3fff) != 0) return XDP_PASS;
    struct udphdr *udp = (void *)iph + iph->ihl * 4;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp)) return XDP_PASS;
    // The verifier needs a compile-time-provable upper bound before allowing
    // pointer arithmetic with this scalar (udp_len < sizeof(*udp) alone only
    // proves a lower bound); mask it into a small range, matching the same
    // technique already used above for iph->ihl. 0x3fff (16383) comfortably
    // covers any realistic single-packet UDP length.
    udp_len &= 0x3fff;
    void *udp_end = (void *)udp + udp_len;
    if (udp_end > data_end) return XDP_PASS;
    struct service_key sk = {.generation = gen, .family = FLUXVM_AF_INET,
                             .protocol = IPPROTO_UDP, .port = bpf_ntohs(udp->dest)};
    __builtin_memcpy(sk.vip, &iph->daddr, 4);
    struct service_value *svc = bpf_map_lookup_elem(&fluxvm_quic_services, &sk);
    if (!svc) return XDP_PASS;
    stat_add(svc->service_id, 0, 1);
    stat_add(svc->service_id, 1, udp_len);
    struct affinity_key a = {.service_id = svc->service_id};
    int kind = 0;
    // Bounds-check parse_quic's reads against the real packet data_end, not
    // the locally-computed udp_end: the verifier's packet-pointer bounds
    // widening only trusts comparisons against the context's actual
    // data_end register, not an arbitrary derived pointer -- checking
    // against udp_end here was rejected with "invalid access to packet"
    // even though udp_end <= data_end was already proven above. Memory
    // safety is unaffected either way (udp_end <= data_end always holds);
    // this only changes which already-safe-to-read bytes parse_quic is
    // permitted to look at.
    int q = parse_quic((void *)(udp + 1), data_end, svc->short_dcid_len, &a, &kind);
    if (q < 0) {
        stat_add(svc->service_id, 10, 1);
        emit_event(ctx, svc, 0, FLUXVM_EVENT_PARSE_ERROR, 0, bpf_ntohs(udp->source),
                   bpf_ntohs(udp->dest), FLUXVM_AF_INET, 0);
        return XDP_PASS;
    }
    if (q == 0) {
        if (svc->flags & FLUXVM_SERVICE_F_QUIC_ONLY) {
            stat_add(svc->service_id, 9, 1);
            emit_event(ctx, svc, 0, FLUXVM_EVENT_NON_QUIC, 0, bpf_ntohs(udp->source),
                       bpf_ntohs(udp->dest), FLUXVM_AF_INET, 0);
            return XDP_PASS;
        }
        tuple_fallback4(&a, iph, bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
        stat_add(svc->service_id, 6, 1);
    } else if (kind == 1) stat_add(svc->service_id, 2, 1);
    else stat_add(svc->service_id, 3, 1);
    return redirect_service(ctx, eth, gen, svc, &a, bpf_ntohs(udp->source),
                            bpf_ntohs(udp->dest), FLUXVM_AF_INET);
}

static __always_inline int handle6(struct xdp_md *ctx, struct ethhdr *eth,
                                    void *l3, void *data_end, __u32 gen)
{
    struct ipv6hdr *ip6 = l3;
    if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (void *)(ip6 + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp)) return XDP_PASS;
    // The verifier needs a compile-time-provable upper bound before allowing
    // pointer arithmetic with this scalar (udp_len < sizeof(*udp) alone only
    // proves a lower bound); mask it into a small range, matching the same
    // technique already used above for iph->ihl. 0x3fff (16383) comfortably
    // covers any realistic single-packet UDP length.
    udp_len &= 0x3fff;
    void *udp_end = (void *)udp + udp_len;
    if (udp_end > data_end) return XDP_PASS;
    struct service_key sk = {.generation = gen, .family = FLUXVM_AF_INET6,
                             .protocol = IPPROTO_UDP, .port = bpf_ntohs(udp->dest)};
    __builtin_memcpy(sk.vip, ip6->daddr.s6_addr, 16);
    struct service_value *svc = bpf_map_lookup_elem(&fluxvm_quic_services, &sk);
    if (!svc) return XDP_PASS;
    stat_add(svc->service_id, 0, 1);
    stat_add(svc->service_id, 1, udp_len);
    struct affinity_key a = {.service_id = svc->service_id};
    int kind = 0;
    // Bounds-check parse_quic's reads against the real packet data_end, not
    // the locally-computed udp_end: the verifier's packet-pointer bounds
    // widening only trusts comparisons against the context's actual
    // data_end register, not an arbitrary derived pointer -- checking
    // against udp_end here was rejected with "invalid access to packet"
    // even though udp_end <= data_end was already proven above. Memory
    // safety is unaffected either way (udp_end <= data_end always holds);
    // this only changes which already-safe-to-read bytes parse_quic is
    // permitted to look at.
    int q = parse_quic((void *)(udp + 1), data_end, svc->short_dcid_len, &a, &kind);
    if (q < 0) {
        stat_add(svc->service_id, 10, 1);
        emit_event(ctx, svc, 0, FLUXVM_EVENT_PARSE_ERROR, 0, bpf_ntohs(udp->source),
                   bpf_ntohs(udp->dest), FLUXVM_AF_INET6, 0);
        return XDP_PASS;
    }
    if (q == 0) {
        if (svc->flags & FLUXVM_SERVICE_F_QUIC_ONLY) {
            stat_add(svc->service_id, 9, 1);
            emit_event(ctx, svc, 0, FLUXVM_EVENT_NON_QUIC, 0, bpf_ntohs(udp->source),
                       bpf_ntohs(udp->dest), FLUXVM_AF_INET6, 0);
            return XDP_PASS;
        }
        tuple_fallback6(&a, ip6, bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
        stat_add(svc->service_id, 6, 1);
    } else if (kind == 1) stat_add(svc->service_id, 2, 1);
    else stat_add(svc->service_id, 3, 1);
    return redirect_service(ctx, eth, gen, svc, &a, bpf_ntohs(udp->source),
                            bpf_ntohs(udp->dest), FLUXVM_AF_INET6);
}

SEC("xdp")
int fluxvm_quiclb(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __u16 proto = bpf_ntohs(eth->h_proto);
    void *l3 = eth + 1;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != ETH_P_8021Q && proto != ETH_P_8021AD) break;
        struct fluxvm_vlan_hdr *vh = l3;
        if ((void *)(vh + 1) > data_end) return XDP_PASS;
        proto = bpf_ntohs(vh->encapsulated_proto);
        l3 = vh + 1;
    }
    __u32 zero = 0;
    struct generation_value *g = bpf_map_lookup_elem(&fluxvm_quic_gen, &zero);
    if (!g || !g->generation) return XDP_PASS;
    if (proto == ETH_P_IP) return handle4(ctx, eth, l3, data_end, g->generation);
    if (proto == ETH_P_IPV6) return handle6(ctx, eth, l3, data_end, g->generation);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
