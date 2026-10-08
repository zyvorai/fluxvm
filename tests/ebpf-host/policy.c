// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: Apache-2.0
// Execute the production policy header with deterministic host map helpers.
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/bpf.h>
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define SEC(name)
static void *bpf_map_lookup_elem(const void *, const void *);
static long bpf_map_update_elem(const void *, const void *, const void *, uint64_t);
#include "../../bpf/fluxvm_pod_policy.bpf.h"

static struct fluxvm_pod_policy policy;
static struct fluxvm_pod_rule rules[64];
static struct fluxvm_pod_policy_stat stats;
static struct fluxvm_pod_rule_hit_value hit;
static struct fluxvm_pod_rule_hit_key last_hit;
static __u64 exact_mask, wildcard_mask;
static __u8 packet_proto;
static unsigned index_lookups, rule_lookups;
static int policy_present = 1, exact_present = 1, wildcard_present = 1;

static void *bpf_map_lookup_elem(const void *map, const void *key)
{
    if (map == &fluxvm_pspol)
        return policy_present && *(__u32 *)key == 7 ? &policy : NULL;
    if (map == &fluxvm_prules) {
        rule_lookups++;
        __u32 i = *(const __u32 *)key;
        return i < 64 ? &rules[i] : NULL;
    }
    if (map == &fluxvm_pridx) {
        index_lookups++;
        const struct fluxvm_pod_rule_index_key *k = key;
        if (k->protocol == 0) return wildcard_present ? &wildcard_mask : NULL;
        return exact_present && k->protocol == packet_proto ? &exact_mask : NULL;
    }
    if (map == &fluxvm_ppstat) return &stats;
    if (map == &fluxvm_prhit) {
        last_hit = *(const struct fluxvm_pod_rule_hit_key *)key;
        return &hit;
    }
    return NULL;
}
static long bpf_map_update_elem(const void *m, const void *k, const void *v, uint64_t f)
{ (void)m; (void)k; (void)v; (void)f; return 0; }

static uint32_t seed = 0x7139ab;
static uint32_t random32(void)
{ seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; return seed; }
static int reference_prefix(const __u8 *a, const __u8 *b, __u8 bits, __u8 family)
{
    if (bits > (family == 4 ? 32 : 128)) return 0;
    for (unsigned i = 0; i < bits; i++) {
        unsigned mask = 1u << (7 - i % 8);
        if ((a[i / 8] & mask) != (b[i / 8] & mask)) return 0;
    }
    return 1;
}
// Deliberately independent reference retaining the pre-patch predicate order.
static int reference_rule(const struct fluxvm_pod_rule *r, __u8 direction,
                          __u8 family, const __u8 *peer, __u8 proto, __u16 port)
{
    if (!r || r->pod_id != 7 || r->direction != direction || r->family != family) return 0;
    if (!reference_prefix(peer, r->address, r->prefix_len, family)) return 0;
    if (!r->protocol) return 1;
    if (r->protocol != proto) return 0;
    if (!r->port_start && !r->port_end) return 1;
    return port >= r->port_start && port <= r->port_end;
}
static void reset(void)
{
    memset(&stats, 0, sizeof(stats)); memset(&hit, 0, sizeof(hit));
    memset(&last_hit, 0, sizeof(last_hit)); index_lookups = rule_lookups = 0;
}
static void rule_equivalence(void)
{
    unsigned checks = 0;
    const __u16 ports[] = {0, 1, 442, 443, 444, 65535};
    const __u8 protocols[] = {0, 6, 17, 132};
    for (unsigned family = 4; family <= 6; family += 2)
        for (unsigned bits = 0; bits <= (family == 4 ? 33u : 129u); bits++)
            for (unsigned trial = 0; trial < 32; trial++) {
                struct fluxvm_pod_rule r = {.pod_id=7, .direction=1, .family=family,
                    .prefix_len=bits, .protocol=protocols[trial % 4],
                    .port_start=443, .port_end=443};
                __u8 peer[16];
                for (unsigned i = 0; i < 16; i++) r.address[i] = peer[i] = random32();
                if (trial & 1) peer[random32() % (family == 4 ? 4 : 16)] ^= 0x80;
                if (trial % 5 == 0) r.port_start = r.port_end = 0;
                if (trial % 7 == 0) { r.port_start=444; r.port_end=443; }
                for (unsigned proto = 0; proto < 4; proto++)
                    for (unsigned port = 0; port < 6; port++) {
                        int expected = reference_rule(&r, 1, family, peer, protocols[proto], ports[port]);
                        assert(fluxvm_rule_matches(&r, 7, 1, family, peer, protocols[proto], ports[port]) == expected);
                        checks++;
                    }
                assert(!fluxvm_rule_matches(&r, 8, 1, family, peer, 6, 443));
                assert(!fluxvm_rule_matches(&r, 7, 2, family, peer, 6, 443));
                assert(!fluxvm_rule_matches(NULL, 7, 1, family, peer, 6, 443));
            }
    printf("policy: %u rule equivalence cases passed\n", checks);
}
static void scan_equivalence(void)
{
    for (unsigned trial = 0; trial < 20000; trial++) {
        reset();
        __u8 family = trial & 1 ? 4 : 6, direction = trial & 2 ? 1 : 2;
        struct fluxvm_peer16 peer = {};
        packet_proto = trial % 3 == 0 ? 0 : (trial & 4 ? 6 : 17);
        __u16 port = trial & 8 ? 443 : 80;
        unsigned count = trial % 66; // includes 0, 63, 64 and count clamping
        policy.flags = FLUXVM_PSPOL_ENABLED | FLUXVM_PSPOL_RICH_RULES |
            FLUXVM_PSPOL_EGRESS_ISOLATED | FLUXVM_PSPOL_INGRESS_ISOLATED;
        if (trial & 16) policy.flags |= FLUXVM_PSPOL_AUDIT;
        policy.reserved0 = count;
        exact_present = trial % 17 != 0;
        wildcard_present = trial % 19 != 0;
        exact_mask = ((__u64)random32() << 32) | random32();
        wildcard_mask = ((__u64)random32() << 32) | random32();
        if (trial % 10 == 0) exact_mask = wildcard_mask = 0;
        if (trial % 11 == 0) { exact_mask = 1ULL << 63; wildcard_mask=0; }
        if (trial % 13 == 0) { exact_mask=0; wildcard_mask=1; }
        int audit = !!(policy.flags & FLUXVM_PSPOL_AUDIT);
        int expected = audit ? FLUXVM_POD_VERDICT_AUDIT : FLUXVM_POD_VERDICT_DENY;
        __u32 expected_slot = FLUXVM_POD_RULE_MISS;
        __u64 mask = (wildcard_present ? wildcard_mask : 0) |
            (packet_proto && exact_present ? exact_mask : 0);
        for (unsigned i = 0; i < 64; i++) {
            rules[i] = (struct fluxvm_pod_rule){.pod_id=7, .direction=direction,
                .family=family, .protocol=i % 4 == 0 ? 0 : 6,
                .prefix_len=0, .port_start=443, .port_end=443};
            if (i % 7 == 0) rules[i].pod_id=8;
            if (i % 9 == 0) { rules[i].prefix_len=8; rules[i].address[0]=1; }
            if (expected_slot == FLUXVM_POD_RULE_MISS && i < count && (mask & (1ULL << i)) &&
                reference_rule(&rules[i], direction, family, peer.b, packet_proto, port)) {
                expected=FLUXVM_POD_VERDICT_ALLOW; expected_slot=i;
            }
        }
        int got=fluxvm_pod_policy_rich_verdict(7, direction, family, peer.b, packet_proto, port);
        assert(got == expected);
        assert(last_hit.rule_index == expected_slot && last_hit.direction == direction);
        assert(last_hit.verdict == expected && hit.packets == 1);
        assert(index_lookups == (packet_proto ? 2u : 1u));
        assert(stats.allowed == (expected == FLUXVM_POD_VERDICT_ALLOW));
        assert(stats.audited == (expected == FLUXVM_POD_VERDICT_AUDIT));
        assert(stats.dropped == (expected == FLUXVM_POD_VERDICT_DENY));
        assert(rule_lookups <= (count > 64 ? 64 : count));
        if (!mask) assert(rule_lookups == 0);
    }
    // Disabled, unisolated and legacy fallback paths must avoid rule-index work.
    struct fluxvm_peer16 peer={};
    policy_present=0; reset();
    assert(fluxvm_pod_policy_rich_verdict(7,1,4,peer.b,6,443) == FLUXVM_POD_VERDICT_ALLOW);
    assert(index_lookups == 0);
    policy_present=1; policy.flags=FLUXVM_PSPOL_ENABLED; reset();
    assert(fluxvm_pod_policy_rich_verdict(7,1,4,peer.b,6,443) == -1);
    policy.flags |= FLUXVM_PSPOL_RICH_RULES;
    assert(fluxvm_pod_policy_rich_verdict(7,1,4,peer.b,6,443) == FLUXVM_POD_VERDICT_ALLOW);
    assert(index_lookups == 0);
    puts("policy: 20000 bitmap scans, verdict/counter attribution and fallback cases passed");
}
int main(void) { rule_equivalence(); scan_equivalence(); return 0; }
