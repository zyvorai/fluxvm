// Copyright 2026 Zyvor
// SPDX-License-Identifier: GPL-2.0-only
//
// TEST-ONLY oracle for scripts/test-pod-policy-verdict.py.
//
// The pod-policy prefix match was rewritten to remove its per-byte branches
// (they multiplied the verifier's paths past the 1,000,000-insn limit on Linux
// 7.x). This object carries the ORIGINAL implementation verbatim next to the
// shipped one and reports, for one (packet, network, family) input, how many of
// the 256 possible `bits` values they disagree on. Never installed.
//
// Input (skb data): [0:16] packet address, [16:32] network address, [32] family.
// Return: (shipped_matches << 16) | disagreements   (0xffff on short input)

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "../fluxvm_pod_policy.bpf.h"

static __always_inline int
old_prefix_match(const __u8 *packet, const __u8 *network, __u8 bits, __u8 family)
{
    __u8 max_bits = family == FLUXVM_POD_AF_INET ? 32 : 128;
    if (bits > max_bits)
        return 0;
    __u8 full = bits >> 3;
    __u8 rem = bits & 7;
    __u8 local[16];
#pragma unroll
    for (int i = 0; i < 16; i++)
        local[i] = packet[i];
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i < full && local[i] != network[i])
            return 0;
    }
    if (!rem)
        return 1;
    full &= 0x0f;
    __u8 mask = (__u8)(0xffu << (8 - rem));
    return (local[full] & mask) == (network[full] & mask);
}

SEC("tc")
int prefix_equiv(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    if (data + 33 > end)
        return 0xffff;
    __u8 packet[16], network[16];
#pragma unroll
    for (int i = 0; i < 16; i++) {
        packet[i] = ((__u8 *)data)[i];
        network[i] = ((__u8 *)data)[16 + i];
    }
    __u8 family = ((__u8 *)data)[32];

    __u32 disagree = 0, matches = 0;
#pragma clang loop unroll(disable)
    for (__u32 b = 0; b < 256; b++) {
        int o = old_prefix_match(packet, network, (__u8)b, family);
        int n = fluxvm_prefix_match(packet, network, (__u8)b, family);
        if (o != n)
            disagree++;
        if (n)
            matches++;
    }
    return (int)((matches << 16) | disagree);
}

char LICENSE[] SEC("license") = "GPL";
