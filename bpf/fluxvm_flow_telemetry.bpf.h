// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: GPL-2.0-only
// Shared production flow telemetry body. Include after flow structs/maps and
// verdict constants are defined. Extracted so host tests execute the same code.
#ifndef FLUXVM_FLOW_TELEMETRY_BPF_H
#define FLUXVM_FLOW_TELEMETRY_BPF_H

static __always_inline void record_flow_raw(
    struct __sk_buff *skb,
    __u32 identity,
    __u8 family,
    const __u8 *src,
    const __u8 *dst,
    __u16 sport,
    __u16 dport,
    __u8 protocol,
    __u8 verdict,
    __u32 sample_rate)
{
    struct flow_key key = {
        .identity = identity,
        .sport = sport,
        .dport = dport,
        .protocol = protocol,
        .verdict = verdict,
        .family = family,
        .pad = 0,
    };
    __builtin_memcpy(key.src, src, 16);
    __builtin_memcpy(key.dst, dst, 16);

    /* One clock read per packet, shared by aggregate and event timestamps. */
    __u64 now = bpf_ktime_get_ns();
    struct flow_value *value = bpf_map_lookup_elem(&fluxvm_flows, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        value->last_seen_ns = now;
    } else {
        struct flow_value initial = {
            .packets = 1,
            .bytes = skb->len,
            .last_seen_ns = now,
        };
        bpf_map_update_elem(&fluxvm_flows, &key, &initial, BPF_NOEXIST);
    }

    int emit = verdict == FLUXVM_VERDICT_DROP;
    /* Rate one always emits: avoid both PRNG and modulo in full-observation
     * mode. Rate zero still disables allowed-flow events; drops always emit. */
    if (!emit && sample_rate == 1)
        emit = 1;
    else if (!emit && sample_rate > 1)
        emit = (bpf_get_prandom_u32() % sample_rate) == 0;
    if (!emit)
        return;

    struct flow_event *event = bpf_ringbuf_reserve(&fluxvm_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = now;
    event->identity = identity;
    event->ifindex = skb->ifindex;
    __builtin_memcpy(event->src, src, 16);
    __builtin_memcpy(event->dst, dst, 16);
    event->bytes = skb->len;
    event->sport = sport;
    event->dport = dport;
    event->protocol = protocol;
    event->verdict = verdict;
    event->family = family;
    event->pad = 0;
    bpf_ringbuf_submit(event, 0);
}


#endif
