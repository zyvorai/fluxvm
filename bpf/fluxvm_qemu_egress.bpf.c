// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Sentinel Set 7S: per-VM outbound-IP restriction for the QEMU/VMM process.
//
// Attached (BPF_CGROUP_INET_EGRESS) to the same fluxvm.slice/{id}.scope
// cgroup as fluxvm_qemu_device.bpf.c. cgroup_skb only ever sees IP-family
// socket traffic -- QEMU's virtiofsd/vhost-user/QMP control channels are
// AF_UNIX and its guest VSOCK channel is AF_VSOCK, neither of which is
// network-reachable in the first place and neither of which this hook type
// can see or needs to restrict. What it *can* restrict, and the reason this
// program exists, is IP sockets QEMU's own process might open directly (as
// opposed to guest traffic crossing the TAP device, which is a completely
// separate path governed by fluxvm_tc.bpf.c/fluxvm_pod_policy.bpf.h): a
// compromised QEMU process should not be able to originate arbitrary
// outbound network connections. Loopback stays allowed for any local
// TCP/UDP control-plane use (e.g. a `-monitor telnet:127.0.0.1:PORT` style
// QEMU option, though FluxVM does not use one by default).

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define LINUX_AF_INET  2
#define LINUX_AF_INET6 10
// Fixed byte offsets of the destination address within a bare (no Ethernet
// framing -- cgroup_skb starts at L3) IPv4/IPv6 header. Not pulled from
// <linux/ip.h>/<linux/ipv6.h> to avoid a struct-layout/offsetof dependency
// for two numbers that are fixed by the IP/IPv6 RFCs themselves:
// IPv4: 1(ver/ihl)+1(tos)+2(len)+2(id)+2(frag)+1(ttl)+1(proto)+2(csum)+4(saddr) = 16.
// IPv6: 4(ver/class/flow)+2(len)+1(nexthdr)+1(hoplimit)+16(saddr) = 24.
#define IPV4_DADDR_OFFSET 16
#define IPV6_DADDR_OFFSET 24

SEC("cgroup_skb/egress")
int fluxvm_qemu_egress(struct __sk_buff *skb)
{
    if (skb->family == LINUX_AF_INET) {
        // cgroup_skb sees the packet starting at the IP header (no
        // Ethernet framing, unlike fluxvm_tc.bpf.c's TC attach).
        __u32 daddr;
        if (bpf_skb_load_bytes(skb, IPV4_DADDR_OFFSET, &daddr, sizeof(daddr)) < 0)
            return 1; // truncated/malformed read: fail open rather than
                      // wedge every IPv4 packet on a parse edge case.
        __u32 loopback_net = bpf_htonl(0x7f000000);
        __u32 mask = bpf_htonl(0xff000000);
        return (daddr & mask) == loopback_net ? 1 : 0;
    }
    if (skb->family == LINUX_AF_INET6) {
        __u8 daddr[16];
        if (bpf_skb_load_bytes(skb, IPV6_DADDR_OFFSET, &daddr, sizeof(daddr)) < 0)
            return 1;
        __u8 loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            if (daddr[i] != loopback[i])
                return 0;
        }
        return 1;
    }
    // Non-IP families (AF_UNIX, AF_VSOCK, AF_NETLINK, ...) never reach this
    // hook in the first place; this branch exists only for forward
    // compatibility with an address family this program does not know
    // about yet, and stays fail-open rather than breaking unrelated traffic.
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
