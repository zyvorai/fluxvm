/* Copyright 2026 Zyvor AI Labs · https://zyvor.dev */
/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLUXVM_POD_POLICY_BPF_H
#define FLUXVM_POD_POLICY_BPF_H

#include <linux/pkt_cls.h>

#define FLUXVM_MAX_POD 4096
#define FLUXVM_MAX_POD_PEER 16384
#define FLUXVM_MAX_POD_RULE 64

#define FLUXVM_PSPOL_ENABLED          (1u << 0)
#define FLUXVM_PSPOL_DEFAULT_DENY     (1u << 1)
#define FLUXVM_PSPOL_AUDIT            (1u << 2)
#define FLUXVM_PSPOL_RICH_RULES       (1u << 3)
#define FLUXVM_PSPOL_EGRESS_ISOLATED  (1u << 4)
#define FLUXVM_PSPOL_INGRESS_ISOLATED (1u << 5)

#define FLUXVM_POD_PEER_ALLOW 1u
#define FLUXVM_POD_PEER_DENY  2u

#define FLUXVM_POD_VERDICT_DENY  0
#define FLUXVM_POD_VERDICT_ALLOW 1
#define FLUXVM_POD_VERDICT_AUDIT 2

#define FLUXVM_POD_DIR_EGRESS  1u
#define FLUXVM_POD_DIR_INGRESS 2u
#define FLUXVM_POD_AF_INET     4u
#define FLUXVM_POD_AF_INET6    6u

/*
 * reserved0 and reserved1 were deliberately spare in Set 6S. Set 14 uses
 * them for rich rule count and wire schema version without changing the
 * 16-byte map-value ABI.
 */
struct fluxvm_pod_policy {
    __u32 flags;
    __u32 reserved0; /* rich rule count */
    __u32 reserved1; /* wire schema version */
    __u32 reserved2;
};

struct fluxvm_pid4_key {
    __u32 pod_id;
    __u32 address;
};

struct fluxvm_pid6_key {
    __u32 pod_id;
    __u8 address[16];
};

/* Set 13 exact peer+protocol+port compatibility ABI. */
struct fluxvm_pid4_port_key {
    __u32 pod_id;
    __u32 address;
    __u8 protocol;
    __u8 pad0;
    __u16 port;
};

struct fluxvm_pid6_port_key {
    __u32 pod_id;
    __u8 address[16];
    __u8 protocol;
    __u8 pad0;
    __u16 port;
};

/* Set 14: one OR-clause in the Kubernetes allow union. */
struct fluxvm_pod_rule {
    __u32 pod_id;
    __u8 direction;
    __u8 family;
    __u8 protocol;    /* 0 = any protocol */
    __u8 prefix_len;
    __u16 port_start; /* 0..0 with protocol != 0 = any port */
    __u16 port_end;
    __u8 address[16];
};

struct fluxvm_pod_policy_stat {
    __u64 allowed;
    __u64 dropped;
    __u64 audited;
};

/* FLUXVM_SECURE_CONTAINERS_SET17
 * Rule-attributed directional telemetry for the Set 14 rich-rule path.
 * `rule_index == FLUXVM_POD_RULE_MISS` means an isolated direction reached
 * the default deny/audit result without matching any allow rule. The map is
 * additive: old schema-v8 control planes ignore it and the policy wire/map
 * ABIs above stay unchanged. Per-CPU values avoid atomic contention on a
 * hot VM edge; userspace aggregates CPUs at scrape time. */
#define FLUXVM_POD_RULE_MISS 0xffffffffu
struct fluxvm_pod_rule_hit_key {
    __u32 pod_id;
    __u32 rule_index;
    __u8 direction;
    __u8 verdict;
    __u16 reserved;
};

struct fluxvm_pod_rule_hit_value {
    __u64 packets;
};

_Static_assert(sizeof(struct fluxvm_pod_policy) == 16, "pod policy ABI");
_Static_assert(sizeof(struct fluxvm_pid4_key) == 8, "pod pid4 ABI");
_Static_assert(sizeof(struct fluxvm_pid6_key) == 20, "pod pid6 ABI");
_Static_assert(sizeof(struct fluxvm_pid4_port_key) == 12, "pod pid4 port ABI");
_Static_assert(sizeof(struct fluxvm_pid6_port_key) == 24, "pod pid6 port ABI");
_Static_assert(sizeof(struct fluxvm_pod_rule) == 28, "pod rich rule ABI");
_Static_assert(sizeof(struct fluxvm_pod_policy_stat) == 24, "pod policy stat ABI");
_Static_assert(sizeof(struct fluxvm_pod_rule_hit_key) == 12, "pod rule-hit key ABI");
_Static_assert(sizeof(struct fluxvm_pod_rule_hit_value) == 8, "pod rule-hit value ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_POD);
    __type(key, __u32);
    __type(value, struct fluxvm_pod_policy);
} fluxvm_pspol SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_POD_PEER);
    __type(key, struct fluxvm_pid4_key);
    __type(value, __u32);
} fluxvm_pid4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_POD_PEER);
    __type(key, struct fluxvm_pid6_key);
    __type(value, __u32);
} fluxvm_pid6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_POD_PEER);
    __type(key, struct fluxvm_pid4_port_key);
    __type(value, __u32);
} fluxvm_pid4_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_POD_PEER);
    __type(key, struct fluxvm_pid6_port_key);
    __type(value, __u32);
} fluxvm_pid6_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_MAX_POD_RULE);
    __type(key, __u32);
    __type(value, struct fluxvm_pod_rule);
} fluxvm_prules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FLUXVM_MAX_POD);
    __type(key, __u32);
    __type(value, struct fluxvm_pod_policy_stat);
} fluxvm_ppstat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    /* 64 allow slots plus per-direction miss outcomes leave ample headroom
     * without turning telemetry into an unbounded cardinality source. */
    __uint(max_entries, 256);
    __type(key, struct fluxvm_pod_rule_hit_key);
    __type(value, struct fluxvm_pod_rule_hit_value);
} fluxvm_prhit SEC(".maps");

static __always_inline struct fluxvm_pod_policy_stat *
fluxvm_ppstat_for(__u32 pod_id)
{
    struct fluxvm_pod_policy_stat *s =
        bpf_map_lookup_elem(&fluxvm_ppstat, &pod_id);
    if (s)
        return s;

    struct fluxvm_pod_policy_stat zero = {};
    bpf_map_update_elem(&fluxvm_ppstat, &pod_id, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_ppstat, &pod_id);
}

static __always_inline void
fluxvm_count_pod_policy(__u32 pod_id, int verdict)
{
    struct fluxvm_pod_policy_stat *s = fluxvm_ppstat_for(pod_id);
    if (!s)
        return;
    if (verdict == 0)
        s->allowed += 1;
    else if (verdict == 1)
        s->dropped += 1;
    else if (verdict == 2)
        s->audited += 1;
}

static __always_inline void
fluxvm_count_pod_rule_hit(
    __u32 pod_id,
    __u32 rule_index,
    __u8 direction,
    __u8 verdict)
{
    struct fluxvm_pod_rule_hit_key key = {
        .pod_id = pod_id,
        .rule_index = rule_index,
        .direction = direction,
        .verdict = verdict,
    };
    struct fluxvm_pod_rule_hit_value *v =
        bpf_map_lookup_elem(&fluxvm_prhit, &key);
    if (v) {
        v->packets += 1;
        return;
    }
    struct fluxvm_pod_rule_hit_value initial = {.packets = 1};
    bpf_map_update_elem(&fluxvm_prhit, &key, &initial, BPF_NOEXIST);
}

static __always_inline int
fluxvm_prefix_match(
    const __u8 *packet,
    const __u8 *network,
    __u8 bits,
    __u8 family)
{
    __u8 max_bits = family == FLUXVM_POD_AF_INET ? 32 : 128;
    if (bits > max_bits)
        return 0;

    __u8 full = bits >> 3;
    __u8 rem = bits & 7;

    /* `packet` may be a raw packet pointer (e.g. ip6->daddr... for the v6
     * verdict path) or a local stack buffer (the v4 path's zero-extended
     * peer[16]). A *variable*-indexed access into a raw packet pointer
     * (`packet[full]` below, `full` coming from the rule's own
     * `prefix_len` in a map value) fails the verifier's bounds proof even
     * when `full` is provably in range: it doesn't get the same
     * packet_end bounds-widening trust a fixed-offset access does. Copy
     * the (at most 16-byte) address into a local buffer first, using only
     * compile-time-constant per-byte indices (verifier-safe against a raw
     * packet pointer the same way every other fixed-offset field access
     * in this codebase already is) -- everything below then indexes the
     * local copy, which the verifier bounds-checks as ordinary stack
     * memory, no extra branching required. */
    __u8 local[16];
#pragma unroll
    for (int i = 0; i < 16; i++)
        local[i] = packet[i];

    /* Guarded per-iteration check instead of an early `break`: clang's
     * unroll pass rejects a `#pragma unroll` loop that exits via `break`
     * (confirmed on this toolchain; the fix pattern is already established
     * elsewhere in this codebase for the identical class of bug -- see
     * parse_quic() in bpf/fluxvm_quiclb.bpf.c). `i < full` bounds which
     * bytes are compared without needing to leave the loop early. */
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i < full && local[i] != network[i])
            return 0;
    }
    if (!rem)
        return 1;
    /* `full` is mathematically <=15 here (rem != 0 implies bits isn't a
     * multiple of 8, so bits < 128 strictly, so full = bits>>3 <= 15) --
     * but a conditional `if (full >= 16) return 0;` guard gets proven dead
     * and eliminated by clang's own optimizer (which reasons about the
     * exact same fact at compile time), leaving the verifier without any
     * runtime-visible bound on `full`. An explicit, unconditional mask
     * can't be optimized away the same way and the verifier tracks AND
     * narrowly, so it directly proves what the eliminated branch would
     * have (same idiom already used elsewhere in this codebase to bound a
     * scalar for the verifier, e.g. `udp_len &= 0x3fff` in
     * bpf/fluxvm_quiclb.bpf.c). */
    full &= 0x0f;

    __u8 mask = (__u8)(0xffu << (8 - rem));
    return (local[full] & mask) == (network[full] & mask);
}

static __always_inline int
fluxvm_rule_matches(
    const struct fluxvm_pod_rule *r,
    __u32 pod_id,
    __u8 direction,
    __u8 family,
    const __u8 *peer,
    __u8 protocol,
    __u16 dport)
{
    if (!r || r->pod_id != pod_id || r->direction != direction ||
        r->family != family)
        return 0;
    if (!fluxvm_prefix_match(peer, r->address, r->prefix_len, family))
        return 0;
    if (r->protocol == 0)
        return 1;
    if (r->protocol != protocol)
        return 0;
    if (r->port_start == 0 && r->port_end == 0)
        return 1;
    return dport >= r->port_start && dport <= r->port_end;
}

static __always_inline int
fluxvm_pod_policy_rich_verdict(
    __u32 pod_id,
    __u8 direction,
    __u8 family,
    const __u8 *peer,
    __u8 protocol,
    __u16 dport)
{
    struct fluxvm_pod_policy *p = bpf_map_lookup_elem(&fluxvm_pspol, &pod_id);
    if (!p || !(p->flags & FLUXVM_PSPOL_ENABLED))
        return FLUXVM_POD_VERDICT_ALLOW;
    if (!(p->flags & FLUXVM_PSPOL_RICH_RULES))
        return -1; /* caller falls back to Set 6S/13 maps */

    int isolated = direction == FLUXVM_POD_DIR_INGRESS
        ? !!(p->flags & FLUXVM_PSPOL_INGRESS_ISOLATED)
        : !!(p->flags & FLUXVM_PSPOL_EGRESS_ISOLATED);
    if (!isolated)
        return FLUXVM_POD_VERDICT_ALLOW;

    __u32 count = p->reserved0;
    if (count > FLUXVM_MAX_POD_RULE)
        count = FLUXVM_MAX_POD_RULE;

#pragma clang loop unroll(disable)
    for (__u32 i = 0; i < FLUXVM_MAX_POD_RULE; i++) {
        if (i >= count)
            break;
        __u32 key = i;
        struct fluxvm_pod_rule *r = bpf_map_lookup_elem(&fluxvm_prules, &key);
        if (fluxvm_rule_matches(r, pod_id, direction, family, peer,
                                protocol, dport)) {
            fluxvm_count_pod_policy(pod_id, 0);
            fluxvm_count_pod_rule_hit(
                pod_id, i, direction, FLUXVM_POD_VERDICT_ALLOW);
            return FLUXVM_POD_VERDICT_ALLOW;
        }
    }

    if (p->flags & FLUXVM_PSPOL_AUDIT) {
        fluxvm_count_pod_policy(pod_id, 2);
        fluxvm_count_pod_rule_hit(
            pod_id, FLUXVM_POD_RULE_MISS, direction, FLUXVM_POD_VERDICT_AUDIT);
        return FLUXVM_POD_VERDICT_AUDIT;
    }
    fluxvm_count_pod_policy(pod_id, 1);
    fluxvm_count_pod_rule_hit(
        pod_id, FLUXVM_POD_RULE_MISS, direction, FLUXVM_POD_VERDICT_DENY);
    return FLUXVM_POD_VERDICT_DENY;
}

/* Set 14 rich tuple entry points. */
static __always_inline int
fluxvm_pod_policy_verdict4_tuple(
    __u32 pod_id,
    __u8 direction,
    __u32 peer_addr,
    __u8 protocol,
    __u16 dport)
{
    __u8 peer[16] = {};
    __builtin_memcpy(peer, &peer_addr, 4);
    int rich = fluxvm_pod_policy_rich_verdict(
        pod_id, direction, FLUXVM_POD_AF_INET, peer, protocol, dport);
    if (rich >= 0)
        return rich;

    struct fluxvm_pod_policy *p = bpf_map_lookup_elem(&fluxvm_pspol, &pod_id);
    if (!p)
        return FLUXVM_POD_VERDICT_ALLOW;

    struct fluxvm_pid4_key key = {
        .pod_id = pod_id,
        .address = peer_addr,
    };
    __u32 *v = bpf_map_lookup_elem(&fluxvm_pid4, &key);
    int allowed;
    if (v) {
        allowed = (*v != FLUXVM_POD_PEER_DENY);
    } else {
        struct fluxvm_pid4_port_key pkey = {
            .pod_id = pod_id,
            .address = peer_addr,
            .protocol = protocol,
            .port = dport,
        };
        __u32 *pv = bpf_map_lookup_elem(&fluxvm_pid4_port, &pkey);
        allowed = pv ? (*pv != FLUXVM_POD_PEER_DENY)
                     : !(p->flags & FLUXVM_PSPOL_DEFAULT_DENY);
    }

    if (!allowed && (p->flags & FLUXVM_PSPOL_AUDIT)) {
        fluxvm_count_pod_policy(pod_id, 2);
        return FLUXVM_POD_VERDICT_AUDIT;
    }
    fluxvm_count_pod_policy(pod_id, allowed ? 0 : 1);
    return allowed ? FLUXVM_POD_VERDICT_ALLOW : FLUXVM_POD_VERDICT_DENY;
}

static __always_inline int
fluxvm_pod_policy_verdict6_tuple(
    __u32 pod_id,
    __u8 direction,
    const __u8 *peer_addr,
    __u8 protocol,
    __u16 dport)
{
    int rich = fluxvm_pod_policy_rich_verdict(
        pod_id, direction, FLUXVM_POD_AF_INET6, peer_addr, protocol, dport);
    if (rich >= 0)
        return rich;

    struct fluxvm_pod_policy *p = bpf_map_lookup_elem(&fluxvm_pspol, &pod_id);
    if (!p)
        return FLUXVM_POD_VERDICT_ALLOW;

    struct fluxvm_pid6_key key = {.pod_id = pod_id};
    __builtin_memcpy(key.address, peer_addr, 16);
    __u32 *v = bpf_map_lookup_elem(&fluxvm_pid6, &key);
    int allowed;
    if (v) {
        allowed = (*v != FLUXVM_POD_PEER_DENY);
    } else {
        struct fluxvm_pid6_port_key pkey = {
            .pod_id = pod_id,
            .protocol = protocol,
            .port = dport,
        };
        __builtin_memcpy(pkey.address, peer_addr, 16);
        __u32 *pv = bpf_map_lookup_elem(&fluxvm_pid6_port, &pkey);
        allowed = pv ? (*pv != FLUXVM_POD_PEER_DENY)
                     : !(p->flags & FLUXVM_PSPOL_DEFAULT_DENY);
    }

    if (!allowed && (p->flags & FLUXVM_PSPOL_AUDIT)) {
        fluxvm_count_pod_policy(pod_id, 2);
        return FLUXVM_POD_VERDICT_AUDIT;
    }
    fluxvm_count_pod_policy(pod_id, allowed ? 0 : 1);
    return allowed ? FLUXVM_POD_VERDICT_ALLOW : FLUXVM_POD_VERDICT_DENY;
}

/* Exact Set 13 call ABI remains source-compatible. */
static __always_inline int
fluxvm_pod_policy_verdict4(
    __u32 pod_id,
    __u32 daddr,
    __u8 protocol,
    __u16 port)
{
    return fluxvm_pod_policy_verdict4_tuple(
        pod_id, FLUXVM_POD_DIR_EGRESS, daddr, protocol, port);
}

static __always_inline int
fluxvm_pod_policy_verdict6(
    __u32 pod_id,
    const __u8 *daddr,
    __u8 protocol,
    __u16 port)
{
    return fluxvm_pod_policy_verdict6_tuple(
        pod_id, FLUXVM_POD_DIR_EGRESS, daddr, protocol, port);
}

static __always_inline int
fluxvm_pod_policy_allowed4(
    __u32 pod_id,
    __u32 daddr,
    __u8 protocol,
    __u16 port)
{
    return fluxvm_pod_policy_verdict4(pod_id, daddr, protocol, port) !=
           FLUXVM_POD_VERDICT_DENY;
}

static __always_inline int
fluxvm_pod_policy_allowed6(
    __u32 pod_id,
    const __u8 *daddr,
    __u8 protocol,
    __u16 port)
{
    return fluxvm_pod_policy_verdict6(pod_id, daddr, protocol, port) !=
           FLUXVM_POD_VERDICT_DENY;
}

#endif /* FLUXVM_POD_POLICY_BPF_H */
