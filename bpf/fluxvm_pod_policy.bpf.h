/* Copyright 2026 Zyvor AI Labs · https://zyvor.dev */
/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLUXVM_POD_POLICY_BPF_H
#define FLUXVM_POD_POLICY_BPF_H

/* Set 6S: identity-aware Pod network policy for Secure Containers VM edges.
 *
 * Mirrors fluxvm_service_v6.bpf.h's fluxvm_spol/fluxvm_sid4/6 schema shape
 * (Service Fabric's proven per-service identity ACL), but as an independent
 * map set: Pod policy and VIP policy have separate lifecycles, separate
 * owners, and separate sizing, so they must not share a map instance even
 * though the verdict logic below is deliberately similar.
 *
 * "pod_id" here means a Kubernetes Pod identity (minted by
 * fluxvm-network::pod_identity from the Pod UID), not a process id -- do not
 * confuse with PID namespaces (a guest-side, Secure Containers Set 6R
 * concern with nothing to do with this header).
 *
 * These maps are loaded as part of fluxvm_tc.bpf.c's ELF and therefore, like
 * every other map in that object, are pinned per-VM by `bpftool prog load
 * ... pinmaps <vm-private-dir>` -- each Secure Containers Pod VM gets its own
 * private instance, never shared with any other VM's maps. Since one Secure
 * Containers VM is exactly one Pod today, clearing/repopulating these maps
 * on reconfigure is as safe as it already is for fluxvm_v4/fluxvm_v6.
 */

#include <linux/pkt_cls.h>

#define FLUXVM_MAX_POD 4096
#define FLUXVM_MAX_POD_PEER 16384

#define FLUXVM_PSPOL_ENABLED      (1u << 0)
#define FLUXVM_PSPOL_DEFAULT_DENY (1u << 1)
#define FLUXVM_PSPOL_AUDIT        (1u << 2)

#define FLUXVM_POD_PEER_ALLOW 1u
#define FLUXVM_POD_PEER_DENY  2u

/* Rich verdict used by dataplane schema v6 drop-reason accounting. Keep the
 * existing allowed4/6 wrappers below for source compatibility with any
 * out-of-tree program that includes this header. */
#define FLUXVM_POD_VERDICT_DENY  0
#define FLUXVM_POD_VERDICT_ALLOW 1
#define FLUXVM_POD_VERDICT_AUDIT 2

struct fluxvm_pod_policy {
    __u32 flags;
    __u32 reserved0;
    __u32 reserved1;
    __u32 reserved2;
};

/* Field named pod_id to mirror fluxvm_sid4_key.service_id; it is a Pod
 * identity, never a process id. */
struct fluxvm_pid4_key {
    __u32 pod_id;
    __u32 address;
};

struct fluxvm_pid6_key {
    __u32 pod_id;
    __u8 address[16];
};

/* Set 13 protocol extension: a peer with no entry in fluxvm_pid4/6 (the
 * address-wide allow/deny maps above) falls through to these port-scoped
 * maps instead of straight to the pod-level default_deny fallback. This
 * lets a Kubernetes NetworkPolicy egress rule with `ports` compile to an
 * exact protocol+port allow for that peer without widening it to every
 * port, which the address-only maps above cannot express. An address-wide
 * fluxvm_pid4/6 ALLOW entry still takes priority (checked first) -- that
 * matches Kubernetes NetworkPolicy's own union-of-rules semantics: if any
 * selected rule allows a peer without a port restriction, the peer is
 * allowed on every port regardless of what a different, more specific rule
 * also says about it. `protocol` is the raw IP protocol number
 * (IPPROTO_TCP/IPPROTO_UDP); `port` is host-byte-order to match the sport/
 * dport already decoded by fluxvm_tc.bpf.c's own L4 parsing before this
 * header's verdict functions are called. */
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

struct fluxvm_pod_policy_stat {
    __u64 allowed;
    __u64 dropped;
    __u64 audited;
};
_Static_assert(sizeof(struct fluxvm_pod_policy) == 16, "pod policy ABI");
_Static_assert(sizeof(struct fluxvm_pid4_key) == 8, "pod pid4 ABI");
_Static_assert(sizeof(struct fluxvm_pid6_key) == 20, "pod pid6 ABI");
_Static_assert(sizeof(struct fluxvm_pid4_port_key) == 12, "pod pid4 port ABI");
_Static_assert(sizeof(struct fluxvm_pid6_port_key) == 24, "pod pid6 port ABI");
_Static_assert(sizeof(struct fluxvm_pod_policy_stat) == 24, "pod policy stat ABI");

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
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FLUXVM_MAX_POD);
    __type(key, __u32);
    __type(value, struct fluxvm_pod_policy_stat);
} fluxvm_ppstat SEC(".maps");

static __always_inline struct fluxvm_pod_policy_stat *fluxvm_ppstat_for(__u32 pod_id)
{
    struct fluxvm_pod_policy_stat *s = bpf_map_lookup_elem(&fluxvm_ppstat, &pod_id);
    if (s)
        return s;
    struct fluxvm_pod_policy_stat zero = {};
    bpf_map_update_elem(&fluxvm_ppstat, &pod_id, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_ppstat, &pod_id);
}

static __always_inline void fluxvm_count_pod_policy(__u32 pod_id, int verdict)
{
    struct fluxvm_pod_policy_stat *s = fluxvm_ppstat_for(pod_id);
    if (!s)
        return;
    if (verdict == 0) s->allowed += 1;
    else if (verdict == 1) s->dropped += 1;
    else if (verdict == 2) s->audited += 1;
}

/* Returns 1 = allow, 0 = deny. A pod_id with no fluxvm_pspol entry, or one
 * whose policy is not FLUXVM_PSPOL_ENABLED, is treated as allow -- this hook
 * is additive on top of fluxvm_tc.bpf.c's own CIDR/L4/rate verdict, which
 * already fails closed on its own missing-iface-config case; an unconfigured
 * Pod policy must not turn an otherwise-allowed packet into a silent drop.
 *
 * `protocol`/`port` are the packet's own L4 protocol and destination port,
 * already decoded by the caller -- passed through here only to consult the
 * Set 13 port-scoped fallback map (fluxvm_pid4_port) when the peer has no
 * address-wide fluxvm_pid4 entry. A peer that IS present in fluxvm_pid4 is
 * resolved from that map alone, ignoring port, exactly as before Set 13. */
static __always_inline int fluxvm_pod_policy_verdict4(__u32 pod_id, __u32 daddr, __u8 protocol, __u16 port)
{
    struct fluxvm_pod_policy *p = bpf_map_lookup_elem(&fluxvm_pspol, &pod_id);
    if (!p || !(p->flags & FLUXVM_PSPOL_ENABLED))
        return FLUXVM_POD_VERDICT_ALLOW;
    struct fluxvm_pid4_key key = {.pod_id = pod_id, .address = daddr};
    __u32 *v = bpf_map_lookup_elem(&fluxvm_pid4, &key);
    int allowed;
    if (v) {
        allowed = (*v != FLUXVM_POD_PEER_DENY);
    } else {
        struct fluxvm_pid4_port_key pkey = {
            .pod_id = pod_id, .address = daddr, .protocol = protocol, .port = port,
        };
        __u32 *pv = bpf_map_lookup_elem(&fluxvm_pid4_port, &pkey);
        allowed = pv ? (*pv != FLUXVM_POD_PEER_DENY) : !(p->flags & FLUXVM_PSPOL_DEFAULT_DENY);
    }
    if (!allowed && (p->flags & FLUXVM_PSPOL_AUDIT)) {
        fluxvm_count_pod_policy(pod_id, 2);
        return FLUXVM_POD_VERDICT_AUDIT;
    }
    fluxvm_count_pod_policy(pod_id, allowed ? 0 : 1);
    return allowed ? FLUXVM_POD_VERDICT_ALLOW : FLUXVM_POD_VERDICT_DENY;
}

static __always_inline int fluxvm_pod_policy_verdict6(__u32 pod_id, const __u8 *daddr, __u8 protocol, __u16 port)
{
    struct fluxvm_pod_policy *p = bpf_map_lookup_elem(&fluxvm_pspol, &pod_id);
    if (!p || !(p->flags & FLUXVM_PSPOL_ENABLED))
        return FLUXVM_POD_VERDICT_ALLOW;
    struct fluxvm_pid6_key key = {.pod_id = pod_id};
    __builtin_memcpy(key.address, daddr, 16);
    __u32 *v = bpf_map_lookup_elem(&fluxvm_pid6, &key);
    int allowed;
    if (v) {
        allowed = (*v != FLUXVM_POD_PEER_DENY);
    } else {
        struct fluxvm_pid6_port_key pkey = {.pod_id = pod_id, .protocol = protocol, .port = port};
        __builtin_memcpy(pkey.address, daddr, 16);
        __u32 *pv = bpf_map_lookup_elem(&fluxvm_pid6_port, &pkey);
        allowed = pv ? (*pv != FLUXVM_POD_PEER_DENY) : !(p->flags & FLUXVM_PSPOL_DEFAULT_DENY);
    }
    if (!allowed && (p->flags & FLUXVM_PSPOL_AUDIT)) {
        fluxvm_count_pod_policy(pod_id, 2);
        return FLUXVM_POD_VERDICT_AUDIT;
    }
    fluxvm_count_pod_policy(pod_id, allowed ? 0 : 1);
    return allowed ? FLUXVM_POD_VERDICT_ALLOW : FLUXVM_POD_VERDICT_DENY;
}

static __always_inline int fluxvm_pod_policy_allowed4(__u32 pod_id, __u32 daddr, __u8 protocol, __u16 port)
{
    return fluxvm_pod_policy_verdict4(pod_id, daddr, protocol, port) != FLUXVM_POD_VERDICT_DENY;
}

static __always_inline int fluxvm_pod_policy_allowed6(__u32 pod_id, const __u8 *daddr, __u8 protocol, __u16 port)
{
    return fluxvm_pod_policy_verdict6(pod_id, daddr, protocol, port) != FLUXVM_POD_VERDICT_DENY;
}

#endif /* FLUXVM_POD_POLICY_BPF_H */
