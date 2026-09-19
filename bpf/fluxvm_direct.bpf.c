// Copyright 2026 Zyvor
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM direct (bridge-less) inbound redirect.
//
// Attach on TC ingress of the OUTER device that a VM's tap is paired with: a
// CNI pod's veth `eth0` (Cilium has already delivered the packet there with
// bpf_redirect_peer, exactly as it does for any pod), or a physical uplink.
// Frames are steered straight to the VM's tap with bpf_redirect, which goes
// through the tap's normal transmit path, so the tap's egress hooks (the
// Pod-ingress policy program, pref 49153) still run on every packet. This
// program never touches Cilium-owned maps or hooks: it only ever attaches
// inside the pod's own network namespace / to a device FluxVM owns.
//
// Guest -> outer needs no program here: it is the redirect tail of
// fluxvm_egress (fluxvm_tc.bpf.c), which runs after VM-edge policy.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_DIRECT_IN_PEER 1 /* outer is a veth: steer EVERYTHING to the tap */
#define FLUXVM_DIRECT_IN_L2   2 /* outer is an uplink: steer by destination MAC */

struct direct_in {
    __u32 tap_ifindex;
    __u32 mode;
};
_Static_assert(sizeof(struct direct_in) == 8, "direct in ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32); /* ifindex of the outer device this program runs on */
    __type(value, struct direct_in);
} fluxvm_direct_in SEC(".maps");

struct mac_key {
    __u8 addr[6];
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct mac_key);
    __type(value, __u32); /* tap ifindex */
} fluxvm_direct_mac SEC(".maps");

SEC("tc")
int fluxvm_direct_in_prog(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct direct_in *d = bpf_map_lookup_elem(&fluxvm_direct_in, &ifindex);
    /* Not configured: fail open to the normal stack. There is nothing to
     * protect here -- a direct tap has no bridge for the packet to fall into,
     * and VM-edge policy runs on the guest-originated direction. */
    if (!d)
        return TC_ACT_OK;

    if (d->mode == FLUXVM_DIRECT_IN_PEER)
        return bpf_redirect(d->tap_ifindex, 0);

    if (d->mode == FLUXVM_DIRECT_IN_L2) {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return TC_ACT_OK;
        struct mac_key k = {};
        __builtin_memcpy(k.addr, eth->h_dest, 6);
        __u32 *tap = bpf_map_lookup_elem(&fluxvm_direct_mac, &k);
        if (tap)
            return bpf_redirect(*tap, 0);
        /* Unknown / broadcast / multicast / the host's own MAC: the host
         * stack. Guest discovery of broadcast traffic is a documented bound
         * of the standalone mode. */
        return TC_ACT_OK;
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
