// Copyright 2026 Zyvor
// SPDX-License-Identifier: GPL-2.0-only
//
// Shared guest -> outer redirect tail for bridge-less ("direct") VMs.
//
// Included by fluxvm_tc.bpf.c (which runs it only after VM-edge policy allowed
// the packet) and by the test stub in bpf/tests/, so the exact code that ships
// is the code the netns test exercises. Include after <linux/bpf.h>,
// <linux/pkt_cls.h> and <bpf/bpf_helpers.h>.

#ifndef FLUXVM_DIRECT_BPF_H
#define FLUXVM_DIRECT_BPF_H

/* Bridge-less ("direct") attach. When a VM's tap has no bridge, an allowed
 * guest-originated packet is redirected straight to its outer device instead
 * of being handed to the stack. Keyed by the ifindex the program runs on;
 * absent entry (every bridged VM) leaves the verdict untouched. */
#define FLUXVM_DIRECT_PEER      1   /* bpf_redirect_peer: outer is a veth (pod eth0) */
#define FLUXVM_DIRECT_REDIRECT  2   /* bpf_redirect: outer is a plain device (uplink) */
#define FLUXVM_DIRECT_F_INGRESS 0x1 /* REDIRECT only: deliver to outer's ingress */

struct direct_out {
    __u32 peer_ifindex;
    __u32 mode;
    __u32 flags;
    __u32 pad;
};
_Static_assert(sizeof(struct direct_out) == 16, "direct out ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct direct_out);
} fluxvm_direct SEC(".maps");

/* Returns TC_ACT_OK when this ifindex is not a direct tap (bridged VMs). */
static __always_inline int fluxvm_direct_redirect(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct direct_out *d = bpf_map_lookup_elem(&fluxvm_direct, &ifindex);
    if (!d)
        return TC_ACT_OK;
    if (d->mode == FLUXVM_DIRECT_PEER)
        return bpf_redirect_peer(d->peer_ifindex, 0);
    if (d->mode == FLUXVM_DIRECT_REDIRECT)
        return bpf_redirect(d->peer_ifindex,
                            (d->flags & FLUXVM_DIRECT_F_INGRESS) ? BPF_F_INGRESS : 0);
    /* Unknown mode: fail closed rather than forward on a stale config. */
    return TC_ACT_SHOT;
}

#endif /* FLUXVM_DIRECT_BPF_H */
