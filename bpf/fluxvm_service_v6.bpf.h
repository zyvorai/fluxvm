/* Copyright 2026 Zyvor AI Labs · https://zyvor.dev */
/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLUXVM_SERVICE_V6_BPF_H
#define FLUXVM_SERVICE_V6_BPF_H

#include <linux/pkt_cls.h>

#define FLUXVM_SPOL_ENABLED       (1u << 0)
#define FLUXVM_SPOL_DEFAULT_DENY  (1u << 1)
#define FLUXVM_SPOL_AUDIT         (1u << 2)
#define FLUXVM_SPOL_L7_OBSERVE    (1u << 3)
#define FLUXVM_SPOL_L7_ENFORCE    (1u << 4)
#define FLUXVM_SID_ALLOW 1u
#define FLUXVM_SID_DENY  2u

#define FLUXVM_HA_OP_UPSERT 1u
#define FLUXVM_HA_OP_DELETE 2u
#define FLUXVM_HA_MAP_FCT4  1u
#define FLUXVM_HA_MAP_FCT6  2u
#define FLUXVM_HA_MAP_NAT4  3u
#define FLUXVM_HA_MAP_NAT6  4u

struct fluxvm_service_policy {
    __u32 flags;
    __u32 proxy_ifindex;
    __u32 bypass_mark;
    __u32 reserved;
};

struct fluxvm_sid4_key {
    __u32 service_id;
    __u32 address;
};

struct fluxvm_sid6_key {
    __u32 service_id;
    __u8 address[16];
};

struct fluxvm_policy_stat {
    __u64 allowed;
    __u64 dropped;
    __u64 audited;
    __u64 l7_redirected;
};

/* Fixed 128-byte queue record. Key/value maxima exactly fit the v4 service
 * state maps: fct6 key=40, nat6 key=40, nat6 value=56. */
struct fluxvm_ha_event {
    __u64 timestamp_ns;
    __u32 service_id;
    __u32 backend_id;
    __u8 operation;
    __u8 map_code;
    __u8 family;
    __u8 protocol;
    __u8 key_len;
    __u8 value_len;
    __u16 reserved;
    __u8 key[48];
    __u8 value[56];
};
_Static_assert(sizeof(struct fluxvm_service_policy) == 16, "service policy ABI");
_Static_assert(sizeof(struct fluxvm_sid4_key) == 8, "sid4 ABI");
_Static_assert(sizeof(struct fluxvm_sid6_key) == 20, "sid6 ABI");
_Static_assert(sizeof(struct fluxvm_policy_stat) == 32, "policy stat ABI");
_Static_assert(sizeof(struct fluxvm_ha_event) == 128, "HA event ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct fluxvm_service_policy);
} fluxvm_spol SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fluxvm_sid4_key);
    __type(value, __u32);
} fluxvm_sid4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct fluxvm_sid6_key);
    __type(value, __u32);
} fluxvm_sid6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct fluxvm_policy_stat);
} fluxvm_pstat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 32768);
    __type(value, struct fluxvm_ha_event);
} fluxvm_haq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} fluxvm_hadrop SEC(".maps");

static __always_inline struct fluxvm_policy_stat *fluxvm_pstat_for(__u32 sid)
{
    struct fluxvm_policy_stat *s = bpf_map_lookup_elem(&fluxvm_pstat, &sid);
    if (s)
        return s;
    struct fluxvm_policy_stat zero = {};
    bpf_map_update_elem(&fluxvm_pstat, &sid, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&fluxvm_pstat, &sid);
}

static __always_inline void fluxvm_count_policy(__u32 sid, int verdict)
{
    struct fluxvm_policy_stat *s = fluxvm_pstat_for(sid);
    if (!s)
        return;
    if (verdict == 0) s->allowed += 1;
    else if (verdict == 1) s->dropped += 1;
    else if (verdict == 2) s->audited += 1;
    else if (verdict == 3) s->l7_redirected += 1;
}

static __always_inline int fluxvm_policy_verdict4(__u32 sid, __u32 src, const struct fluxvm_service_policy *p)
{
    struct fluxvm_sid4_key key = {.service_id = sid, .address = src};
    __u32 *v = bpf_map_lookup_elem(&fluxvm_sid4, &key);
    if (v)
        return *v == FLUXVM_SID_DENY ? -1 : 1;
    return (p->flags & FLUXVM_SPOL_DEFAULT_DENY) ? -1 : 1;
}

static __always_inline int fluxvm_policy_verdict6(__u32 sid, const __u8 *src, const struct fluxvm_service_policy *p)
{
    struct fluxvm_sid6_key key = {.service_id = sid};
    __builtin_memcpy(key.address, src, 16);
    __u32 *v = bpf_map_lookup_elem(&fluxvm_sid6, &key);
    if (v)
        return *v == FLUXVM_SID_DENY ? -1 : 1;
    return (p->flags & FLUXVM_SPOL_DEFAULT_DENY) ? -1 : 1;
}

/* Return TC_ACT_UNSPEC to continue Service Fabric processing. */
static __always_inline int fluxvm_policy4_tc(struct __sk_buff *skb, __u32 sid, __u32 src, __u8 protocol)
{
    struct fluxvm_service_policy *p = bpf_map_lookup_elem(&fluxvm_spol, &sid);
    if (!p || !(p->flags & FLUXVM_SPOL_ENABLED))
        return TC_ACT_UNSPEC;
    if ((p->flags & FLUXVM_SPOL_L7_ENFORCE) && p->bypass_mark && skb->mark == p->bypass_mark) {
        skb->mark = 0;
        fluxvm_count_policy(sid, 0);
        return TC_ACT_UNSPEC;
    }
    if (fluxvm_policy_verdict4(sid, src, p) < 0) {
        if (p->flags & FLUXVM_SPOL_AUDIT) {
            fluxvm_count_policy(sid, 2);
            return TC_ACT_UNSPEC;
        }
        fluxvm_count_policy(sid, 1);
        return TC_ACT_SHOT;
    }
    if ((p->flags & FLUXVM_SPOL_L7_ENFORCE) && protocol == IPPROTO_TCP) {
        if (!p->proxy_ifindex) {
            fluxvm_count_policy(sid, 1);
            return TC_ACT_SHOT;
        }
        fluxvm_count_policy(sid, 3);
        return bpf_redirect(p->proxy_ifindex, 0);
    }
    if (p->flags & FLUXVM_SPOL_L7_OBSERVE)
        fluxvm_count_policy(sid, 2);
    else
        fluxvm_count_policy(sid, 0);
    return TC_ACT_UNSPEC;
}

static __always_inline int fluxvm_policy6_tc(struct __sk_buff *skb, __u32 sid, const __u8 *src, __u8 protocol)
{
    struct fluxvm_service_policy *p = bpf_map_lookup_elem(&fluxvm_spol, &sid);
    if (!p || !(p->flags & FLUXVM_SPOL_ENABLED))
        return TC_ACT_UNSPEC;
    if ((p->flags & FLUXVM_SPOL_L7_ENFORCE) && p->bypass_mark && skb->mark == p->bypass_mark) {
        skb->mark = 0;
        fluxvm_count_policy(sid, 0);
        return TC_ACT_UNSPEC;
    }
    if (fluxvm_policy_verdict6(sid, src, p) < 0) {
        if (p->flags & FLUXVM_SPOL_AUDIT) {
            fluxvm_count_policy(sid, 2);
            return TC_ACT_UNSPEC;
        }
        fluxvm_count_policy(sid, 1);
        return TC_ACT_SHOT;
    }
    if ((p->flags & FLUXVM_SPOL_L7_ENFORCE) && protocol == IPPROTO_TCP) {
        if (!p->proxy_ifindex) {
            fluxvm_count_policy(sid, 1);
            return TC_ACT_SHOT;
        }
        fluxvm_count_policy(sid, 3);
        return bpf_redirect(p->proxy_ifindex, 0);
    }
    if (p->flags & FLUXVM_SPOL_L7_OBSERVE)
        fluxvm_count_policy(sid, 2);
    else
        fluxvm_count_policy(sid, 0);
    return TC_ACT_UNSPEC;
}

/* XDP returns -1 to continue the native XDP LB. L7 enforce deliberately
 * returns XDP_PASS so the TC program remains the sole redirect owner. */
static __always_inline int fluxvm_policy4_xdp(__u32 sid, __u32 src)
{
    struct fluxvm_service_policy *p = bpf_map_lookup_elem(&fluxvm_spol, &sid);
    if (!p || !(p->flags & FLUXVM_SPOL_ENABLED))
        return -1;
    if (fluxvm_policy_verdict4(sid, src, p) < 0) {
        if (p->flags & FLUXVM_SPOL_AUDIT) { fluxvm_count_policy(sid, 2); return -1; }
        fluxvm_count_policy(sid, 1); return XDP_DROP;
    }
    if (p->flags & FLUXVM_SPOL_L7_ENFORCE) { fluxvm_count_policy(sid, 3); return XDP_PASS; }
    if (p->flags & FLUXVM_SPOL_L7_OBSERVE) fluxvm_count_policy(sid, 2);
    else fluxvm_count_policy(sid, 0);
    return -1;
}

static __always_inline int fluxvm_policy6_xdp(__u32 sid, const __u8 *src)
{
    struct fluxvm_service_policy *p = bpf_map_lookup_elem(&fluxvm_spol, &sid);
    if (!p || !(p->flags & FLUXVM_SPOL_ENABLED))
        return -1;
    if (fluxvm_policy_verdict6(sid, src, p) < 0) {
        if (p->flags & FLUXVM_SPOL_AUDIT) { fluxvm_count_policy(sid, 2); return -1; }
        fluxvm_count_policy(sid, 1); return XDP_DROP;
    }
    if (p->flags & FLUXVM_SPOL_L7_ENFORCE) { fluxvm_count_policy(sid, 3); return XDP_PASS; }
    if (p->flags & FLUXVM_SPOL_L7_OBSERVE) fluxvm_count_policy(sid, 2);
    else fluxvm_count_policy(sid, 0);
    return -1;
}

static __always_inline void fluxvm_ha_drop(__u32 sid)
{
    __u64 *v = bpf_map_lookup_elem(&fluxvm_hadrop, &sid);
    if (v) { *v += 1; return; }
    __u64 one = 1;
    bpf_map_update_elem(&fluxvm_hadrop, &sid, &one, BPF_NOEXIST);
}

#define FLUXVM_HA_EMIT_FN(_name, _key_t, _value_t, _map_code, _family)               \
static __always_inline void _name(__u32 sid, __u32 bid, __u8 op, __u8 proto,           \
                                  const _key_t *key, const _value_t *value)             \
{                                                                                       \
    struct fluxvm_ha_event event = {};                                                   \
    event.timestamp_ns = bpf_ktime_get_ns();                                             \
    event.service_id = sid; event.backend_id = bid; event.operation = op;               \
    event.map_code = _map_code; event.family = _family; event.protocol = proto;         \
    event.key_len = sizeof(*key);                                                        \
    __builtin_memcpy(event.key, key, sizeof(*key));                                      \
    if (value) {                                                                         \
        event.value_len = sizeof(*value);                                                \
        __builtin_memcpy(event.value, value, sizeof(*value));                            \
    }                                                                                    \
    if (bpf_map_push_elem(&fluxvm_haq, &event, 0) != 0)                                 \
        fluxvm_ha_drop(sid);                                                             \
}

FLUXVM_HA_EMIT_FN(fluxvm_ha_fct4, struct fct4_key, struct fct_value, FLUXVM_HA_MAP_FCT4, 4)
FLUXVM_HA_EMIT_FN(fluxvm_ha_fct6, struct fct6_key, struct fct_value, FLUXVM_HA_MAP_FCT6, 6)
FLUXVM_HA_EMIT_FN(fluxvm_ha_nat4, struct nat4_key, struct nat4_value, FLUXVM_HA_MAP_NAT4, 4)
FLUXVM_HA_EMIT_FN(fluxvm_ha_nat6, struct nat6_key, struct nat6_value, FLUXVM_HA_MAP_NAT6, 6)

#endif /* FLUXVM_SERVICE_V6_BPF_H */
