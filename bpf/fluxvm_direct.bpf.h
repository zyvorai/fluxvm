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

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

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

/* ── Host-uplink ("l2-uplink") local steering ─────────────────────────────────────────────
 * Several VMs can share one physical uplink with no bridge, so frames between two of them, and
 * frames from the wire to a guest, must be switched by these maps. A physical switch will never
 * send a frame back out the port it arrived on, so guest <-> guest cannot go via the wire.
 *
 * Both maps are SHARED by every VM on the uplink (pinned once per uplink and reused by name when
 * each VM's programs are loaded); each VM adds and removes only its own entries. Values are the
 * ifindex of the guest's tap. Known bounds: IPv4 ARP only (no NDP), no host <-> guest traffic. */
#define FLUXVM_DIRECT_MAC_ENTRIES 1024
#define FLUXVM_DIRECT_IP_ENTRIES  1024

struct mac_key {
    __u8 addr[6];
    __u8 pad[2];
};
_Static_assert(sizeof(struct mac_key) == 8, "direct mac key ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_DIRECT_MAC_ENTRIES);
    __type(key, struct mac_key);
    __type(value, __u32); /* tap ifindex */
} fluxvm_dmac SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLUXVM_DIRECT_IP_ENTRIES);
    __type(key, __u32);   /* IPv4 address, network byte order */
    __type(value, __u32); /* tap ifindex */
} fluxvm_dip SEC(".maps");

#define FLUXVM_ARP_LEN   28 /* Ethernet/IPv4 ARP */
#define FLUXVM_ARP_OP_REQUEST 1

/* The tap ifindex a frame should be delivered to locally, or 0. An ARP request is steered by its
 * TARGET IP (that is how a peer discovers a guest, and how one guest discovers another); any
 * other frame by destination MAC. Broadcast/multicast that is not such an ARP request matches
 * nothing and goes wherever the caller sends unmatched frames. */
static __always_inline __u32 fluxvm_direct_steer_local(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        __u8 *arp = (__u8 *)(eth + 1);
        if ((void *)(arp + FLUXVM_ARP_LEN) > data_end)
            return 0;
        /* op at +6, target protocol address at +24 */
        if (arp[6] == 0 && arp[7] == FLUXVM_ARP_OP_REQUEST) {
            __u32 tpa;
            __builtin_memcpy(&tpa, arp + 24, 4);
            __u32 *tap = bpf_map_lookup_elem(&fluxvm_dip, &tpa);
            if (tap)
                return *tap;
        }
    }

    struct mac_key k = {};
    __builtin_memcpy(k.addr, eth->h_dest, 6);
    __u32 *tap = bpf_map_lookup_elem(&fluxvm_dmac, &k);
    return tap ? *tap : 0;
}

/* Returns TC_ACT_OK when this ifindex is not a direct tap (bridged VMs). */
static __always_inline int fluxvm_direct_redirect(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct direct_out *d = bpf_map_lookup_elem(&fluxvm_direct, &ifindex);
    if (!d)
        return TC_ACT_OK;
    if (d->mode == FLUXVM_DIRECT_PEER)
        return bpf_redirect_peer(d->peer_ifindex, 0);
    if (d->mode == FLUXVM_DIRECT_REDIRECT) {
        /* Uplink mode: another local guest (or an ARP for one) is delivered straight to its tap;
         * everything else leaves through the uplink. */
        __u32 local = fluxvm_direct_steer_local(skb);
        if (local && local != ifindex)
            return bpf_redirect(local, 0);
        return bpf_redirect(d->peer_ifindex,
                            (d->flags & FLUXVM_DIRECT_F_INGRESS) ? BPF_F_INGRESS : 0);
    }
    /* Unknown mode: fail closed rather than forward on a stale config. */
    return TC_ACT_SHOT;
}

#endif /* FLUXVM_DIRECT_BPF_H */
