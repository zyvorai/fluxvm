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
#include "fluxvm_direct.bpf.h"

#define FLUXVM_DIRECT_IN_PEER 1 /* outer is a veth: steer EVERYTHING to the tap */
#define FLUXVM_DIRECT_IN_L2   2 /* outer is an uplink: steer by ARP target / destination MAC */

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

/* "Not mine" is TC_ACT_UNSPEC, never TC_ACT_OK. On TCX, OK is TCX_PASS and ends the chain, which
 * would hide the frame from the next VM's copy of this program on a shared uplink; UNSPEC
 * (TCX_NEXT) lets the chain continue and, at the end, hands the frame to the host stack. Legacy
 * cls_bpf treats UNSPEC the same way. */
SEC("tc")
int fluxvm_direct_in_prog(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct direct_in *d = bpf_map_lookup_elem(&fluxvm_direct_in, &ifindex);
    if (!d)
        return TC_ACT_UNSPEC;

    if (d->mode == FLUXVM_DIRECT_IN_PEER)
        return bpf_redirect(d->tap_ifindex, 0);

    if (d->mode == FLUXVM_DIRECT_IN_L2) {
        __u32 tap = fluxvm_direct_steer_local(skb);
        if (tap)
            return bpf_redirect(tap, 0);
        /* Unknown / broadcast / multicast / the host's own MAC: the host stack. */
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
