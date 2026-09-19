// Copyright 2026 Zyvor
// SPDX-License-Identifier: GPL-2.0-only
//
// TEST-ONLY. Stand-in for fluxvm_egress used by scripts/test-direct-datapath.sh
// when the real fluxvm_tc.bpf.o cannot be loaded by the running kernel's
// verifier. It has the same shape as the real program -- a policy verdict
// first, then the shared redirect tail -- with the (large) policy body replaced
// by a per-interface allow flag. Never installed; not built by build-ebpf.sh.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "../fluxvm_direct.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} stub_allow SEC(".maps");

SEC("tc")
int fluxvm_egress(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    __u32 *allow = bpf_map_lookup_elem(&stub_allow, &ifindex);
    if (!allow || !*allow)
        return TC_ACT_SHOT; /* fail closed, like the real program */
    return fluxvm_direct_redirect(skb);
}

char LICENSE[] SEC("license") = "GPL";
