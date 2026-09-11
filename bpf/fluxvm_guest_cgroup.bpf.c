// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Sentinel Set 8S: per-container network policy inside the guest.
//
// Compiled with the same clang/BTF-map conventions as every other bpf/*.bpf.c
// object in this repo (see scripts/build-ebpf-guest.sh), but loaded and
// attached from inside the guest by fluxvm-container-agent using `aya`
// (a pure-Rust eBPF loader) instead of bpftool: the minimal guest image
// this binary runs in cannot be relied on to have bpftool/iproute2/kernel
// headers installed, unlike the host, which always does. This is a
// deliberate, narrowly-scoped exception to the project's normal
// "bpftool+tc, not aya/libbpf" rule (crates/fluxvm-network/src/ebpf.rs) --
// confirmed empirically that aya's loader accepts a plain clang-compiled,
// BTF-defined-map object with no special aya-side toolchain needed.
//
// One loaded instance of these two programs is shared across every
// container in the Pod VM (loaded once, attached again per container's own
// cgroup), so both programs key their maps by cgroup id
// (bpf_get_current_cgroup_id(), == that cgroup's inode number on cgroupfs)
// rather than needing a fresh map instance per container.
//
// Fail-closed-by-default, unlike the host-side Set 6S Pod policy: once
// fluxvm-container-agent attaches these programs to a container's cgroup at
// all (which it does unconditionally for every container, not only ones
// with an explicit policy), an unconfigured/not-yet-populated fluxvm_cpol
// entry denies non-loopback traffic rather than allowing it. Set 6S's
// "missing entry = allow" default exists for backward compatibility with
// the large existing population of non-Secure-Containers VMs that never opt
// in at all; there is no equivalent compatibility concern here since this
// program is brand new and only ever attached to containers that are, by
// definition, being policed by it.

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_CPOL_ENABLED       (1u << 0)
#define FLUXVM_CPOL_DEFAULT_ALLOW (1u << 1)
#define FLUXVM_CPOL_AUDIT         (1u << 2)
#define FLUXVM_CPOL_RICH          (1u << 3)
#define FLUXVM_CPOL_EGRESS_ISOLATED  (1u << 4)
#define FLUXVM_CPOL_INGRESS_ISOLATED (1u << 5)
#define FLUXVM_CDIR_EGRESS 1u
#define FLUXVM_CDIR_INGRESS 2u
#define FLUXVM_CAF_INET 4u
#define FLUXVM_CAF_INET6 6u
#define FLUXVM_MAX_CRULE 64u
#define FLUXVM_CPEER_ALLOW 1u
#define FLUXVM_CPEER_DENY  2u

#define LINUX_AF_INET  2
#define LINUX_AF_INET6 10
// See bpf/fluxvm_qemu_egress.bpf.c for why these are fixed literals rather
// than pulled from <linux/ip.h>/<linux/ipv6.h>.
#define IPV4_SADDR_OFFSET 12
#define IPV4_DADDR_OFFSET 16
#define IPV6_SADDR_OFFSET 8
#define IPV6_DADDR_OFFSET 24

struct fluxvm_container_policy {
    __u32 flags;
    __u32 reserved;
};

struct fluxvm_cid4_key {
    __u64 cgroup_id;
    __u32 address;
    // Explicit trailing padding: the u64 field forces 8-byte struct
    // alignment regardless, so this is documenting the compiler's own
    // padding rather than adding any, keeping the userspace encoder's
    // "must match this struct exactly" comment honest byte-for-byte.
    __u32 reserved;
};

struct fluxvm_cid6_key {
    __u64 cgroup_id;
    __u8 address[16];
};
/* FLUXVM_SECURE_CONTAINERS_SET19: CIDR/direction mirror of host Pod policy. */
struct fluxvm_crule_key { __u64 cgroup_id; __u32 slot; __u32 reserved; };
struct fluxvm_crule_value { __u8 direction; __u8 family; __u8 prefix_len; __u8 reserved; __u8 address[16]; };

_Static_assert(sizeof(struct fluxvm_container_policy) == 8, "container policy ABI");
_Static_assert(sizeof(struct fluxvm_cid4_key) == 16, "container cid4 ABI");
_Static_assert(sizeof(struct fluxvm_cid6_key) == 24, "container cid6 ABI");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct fluxvm_container_policy);
} fluxvm_cpol SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct fluxvm_cid4_key);
    __type(value, __u32);
} fluxvm_cid4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct fluxvm_cid6_key);
    __type(value, __u32);
} fluxvm_cid6 SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
    __type(key, struct fluxvm_crule_key); __type(value, struct fluxvm_crule_value);
} fluxvm_crules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} fluxvm_cdrops SEC(".maps");

static __always_inline int is_loopback4(__u32 addr_be)
{
    __u32 mask = bpf_htonl(0xff000000);
    __u32 loop = bpf_htonl(0x7f000000);
    return (addr_be & mask) == loop;
}

static __always_inline int is_loopback6(const __u8 *addr)
{
    __u8 loop[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (addr[i] != loop[i])
            return 0;
    }
    return 1;
}

static __always_inline void count_drop(__u64 cg)
{
    __u64 *v = bpf_map_lookup_elem(&fluxvm_cdrops, &cg);
    if (v) { *v += 1; return; }
    __u64 one = 1;
    bpf_map_update_elem(&fluxvm_cdrops, &cg, &one, BPF_NOEXIST);
}

// FLUXVM_SECURE_CONTAINERS_SET19: rich CIDR/direction mirror.
static __always_inline int cprefix(const __u8 *packet,const __u8 *network,__u8 bits,__u8 family)
{
    __u8 max=family==FLUXVM_CAF_INET?32:128; if(bits>max) return 0;
    __u8 full=bits>>3, rem=bits&7; __u8 local[16]={};
#pragma unroll
    for(int i=0;i<16;i++) local[i]=packet[i];
#pragma unroll
    for(int i=0;i<16;i++) if(i<full && local[i]!=network[i]) return 0;
    if(!rem) return 1; full &= 0x0f; __u8 mask=(__u8)(0xffu << (8-rem));
    return (local[full]&mask)==(network[full]&mask);
}
static __always_inline int rich_verdict(__u64 cg,__u8 direction,__u8 family,const __u8 *addr,
                                        struct fluxvm_container_policy *p)
{
    int isolated=direction==FLUXVM_CDIR_INGRESS ? !!(p->flags&FLUXVM_CPOL_INGRESS_ISOLATED) : !!(p->flags&FLUXVM_CPOL_EGRESS_ISOLATED);
    if(!isolated) return 1; __u32 count=p->reserved; if(count>FLUXVM_MAX_CRULE) count=FLUXVM_MAX_CRULE;
#pragma clang loop unroll(disable)
    for(__u32 i=0;i<FLUXVM_MAX_CRULE;i++) { if(i>=count) break; struct fluxvm_crule_key k={.cgroup_id=cg,.slot=i}; struct fluxvm_crule_value *r=bpf_map_lookup_elem(&fluxvm_crules,&k); if(r && r->direction==direction && r->family==family && cprefix(addr,r->address,r->prefix_len,family)) return 1; }
    if(p->flags&FLUXVM_CPOL_AUDIT) return 1; count_drop(cg); return 0;
}
static __always_inline int verdict4(__u64 cg,__u8 direction,__u32 addr)
{
    if(is_loopback4(addr)) return 1; struct fluxvm_container_policy *p=bpf_map_lookup_elem(&fluxvm_cpol,&cg);
    if(!p || !(p->flags&FLUXVM_CPOL_ENABLED)){count_drop(cg);return 0;}
    if(p->flags&FLUXVM_CPOL_RICH){ __u8 raw[16]={}; __builtin_memcpy(raw,&addr,4); return rich_verdict(cg,direction,FLUXVM_CAF_INET,raw,p); }
    struct fluxvm_cid4_key key={.cgroup_id=cg,.address=addr}; __u32 *v=bpf_map_lookup_elem(&fluxvm_cid4,&key);
    int allowed=v?(*v!=FLUXVM_CPEER_DENY):((p->flags&FLUXVM_CPOL_DEFAULT_ALLOW)!=0); if(allowed || (p->flags&FLUXVM_CPOL_AUDIT)) return 1; count_drop(cg); return 0;
}
static __always_inline int verdict6(__u64 cg,__u8 direction,const __u8 *addr)
{
    if(is_loopback6(addr)) return 1; struct fluxvm_container_policy *p=bpf_map_lookup_elem(&fluxvm_cpol,&cg);
    if(!p || !(p->flags&FLUXVM_CPOL_ENABLED)){count_drop(cg);return 0;}
    if(p->flags&FLUXVM_CPOL_RICH) return rich_verdict(cg,direction,FLUXVM_CAF_INET6,addr,p);
    struct fluxvm_cid6_key key={.cgroup_id=cg}; __builtin_memcpy(key.address,addr,16); __u32 *v=bpf_map_lookup_elem(&fluxvm_cid6,&key);
    int allowed=v?(*v!=FLUXVM_CPEER_DENY):((p->flags&FLUXVM_CPOL_DEFAULT_ALLOW)!=0); if(allowed || (p->flags&FLUXVM_CPOL_AUDIT)) return 1; count_drop(cg); return 0;
}

SEC("cgroup_skb/egress")
int fluxvm_guest_egress(struct __sk_buff *skb)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (skb->family == LINUX_AF_INET) {
        __u32 daddr;
        if (bpf_skb_load_bytes(skb, IPV4_DADDR_OFFSET, &daddr, sizeof(daddr)) < 0)
            return 1;
        return verdict4(cg, FLUXVM_CDIR_EGRESS, daddr);
    }
    if (skb->family == LINUX_AF_INET6) {
        __u8 daddr[16];
        if (bpf_skb_load_bytes(skb, IPV6_DADDR_OFFSET, &daddr, sizeof(daddr)) < 0)
            return 1;
        return verdict6(cg, FLUXVM_CDIR_EGRESS, daddr);
    }
    return 1;
}

SEC("cgroup_skb/ingress")
int fluxvm_guest_ingress(struct __sk_buff *skb)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (skb->family == LINUX_AF_INET) {
        __u32 saddr;
        if (bpf_skb_load_bytes(skb, IPV4_SADDR_OFFSET, &saddr, sizeof(saddr)) < 0)
            return 1;
        return verdict4(cg, FLUXVM_CDIR_INGRESS, saddr);
    }
    if (skb->family == LINUX_AF_INET6) {
        __u8 saddr[16];
        if (bpf_skb_load_bytes(skb, IPV6_SADDR_OFFSET, &saddr, sizeof(saddr)) < 0)
            return 1;
        return verdict6(cg, FLUXVM_CDIR_INGRESS, saddr);
    }
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
