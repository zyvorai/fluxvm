// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/bpf.h>
// Generated from production struct definitions by the host-test runner.
#include "flow-fixture.h"
#define FLUXVM_VERDICT_DROP 0
#define FLUXVM_VERDICT_ALLOW 1
static int fluxvm_flows, fluxvm_events;
static struct flow_value flow;
static struct flow_key recorded_key;
static struct flow_event event;
static int present, reserve_fails, update_fails;
static unsigned clocks, random_calls, submits, updates;
static __u32 random_value;
static __u64 bpf_ktime_get_ns(void) { clocks++; return 123456789 + clocks; }
static __u32 bpf_get_prandom_u32(void) { random_calls++; return random_value; }
static void *bpf_map_lookup_elem(const void *map, const void *key)
{
    assert(map == &fluxvm_flows);
    recorded_key=*(const struct flow_key *)key;
    return present ? &flow : NULL;
}
static long bpf_map_update_elem(const void *map, const void *key, const void *value, __u64 flags)
{
    assert(map == &fluxvm_flows && flags == BPF_NOEXIST);
    updates++;
    recorded_key=*(const struct flow_key *)key;
    if (update_fails) return -1;
    flow=*(const struct flow_value *)value; present=1; return 0;
}
static void *bpf_ringbuf_reserve(const void *map, __u64 size, __u64 flags)
{
    assert(map == &fluxvm_events && size == sizeof(event) && flags == 0);
    return reserve_fails ? NULL : &event;
}
static void bpf_ringbuf_submit(void *value, __u64 flags)
{ assert(value == &event && flags == 0); submits++; }
#include "../../bpf/fluxvm_flow_telemetry.bpf.h"

int main(void)
{
    const __u32 rates[]={0,1,2,3,1000,0x7fffffff,0xffffffff};
    const __u32 randoms[]={0,1,0xffffffff};
    unsigned cases=0;
    for (unsigned family=4; family<=6; family+=2)
      for (unsigned verdict=0; verdict<2; verdict++)
       for (unsigned r=0; r<7; r++)
        for (unsigned p=0; p<2; p++)
         for (unsigned fail=0; fail<2; fail++)
          for (unsigned update_fail=0; update_fail<2; update_fail++)
           for (unsigned rand=0; rand<3; rand++) {
            __u8 src[16]={10,0,0,1},dst[16]={10,0,0,2};
            if (family==6) { src[15]=1; dst[15]=2; }
            struct __sk_buff skb={.len=1500,.ifindex=31};
            present=p; reserve_fails=fail; update_fails=update_fail;
            clocks=random_calls=submits=updates=0; random_value=randoms[rand];
            memset(&event,0,sizeof(event));
            flow=(struct flow_value){.packets=7,.bytes=100};
            record_flow_raw(&skb,7,family,src,dst,1234,443,6,verdict,rates[r]);
            int expected_emit=verdict==FLUXVM_VERDICT_DROP ||
                (rates[r]>0 && random_value % rates[r]==0);
            assert(clocks==1);
            assert(random_calls==(verdict!=FLUXVM_VERDICT_DROP && rates[r]>1));
            assert(updates==!p);
            assert(submits==(expected_emit && !fail));
            assert(recorded_key.identity==7 && recorded_key.family==family &&
                   recorded_key.sport==1234 && recorded_key.dport==443 &&
                   recorded_key.protocol==6 && recorded_key.verdict==verdict && recorded_key.pad==0);
            assert(!memcmp(recorded_key.src,src,16) && !memcmp(recorded_key.dst,dst,16));
            if (p || !update_fail) {
                assert(flow.packets==(p ? 8u : 1u));
                assert(flow.bytes==(p ? 1600u : 1500u));
                assert(flow.last_seen_ns==123456790);
            }
            if (submits) {
                assert(event.timestamp_ns==123456790 && event.identity==7 && event.ifindex==31);
                assert(event.bytes==1500 && event.sport==1234 && event.dport==443 &&
                       event.protocol==6 && event.verdict==verdict && event.family==family && event.pad==0);
                assert(!memcmp(event.src,src,16) && !memcmp(event.dst,dst,16));
            }
            cases++;
           }
    printf("telemetry: %u sampling, counter, event and helper-call cases passed\n",cases);
    return 0;
}
