// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Opt-in cgroup/connect4 acceleration for node-local host sockets talking to
// Service Fabric VIPs. Shares TC/XDP pinmaps (svc/backend/maglev). Fail-open:
// if maps miss or backend unhealthy, leave the connect unchanged so VM
// TAP/TC/XDP remains the canonical path.

#include <linux/bpf.h>
#include <linux/in.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_SVC_BACKEND_READY 1u
#define FLUXVM_SVC_BACKEND_UNHEALTHY 4u
#define FLUXVM_SVC_MODE_NAT 1u

struct svc4_key {
	__u32 address;
	__u16 port;
	__u8 protocol;
	__u8 pad;
};

struct svc_value {
	__u32 service_id;
	__u32 table_size;
	__u64 rate_bytes_per_sec;
	__u32 flow_sample_rate;
	__u8 mode;
	__u8 flags;
	__u16 pad;
};

struct backend_key {
	__u32 service_id;
	__u32 backend_id;
};

struct backend4_value {
	__u32 address;
	__u16 port;
	__u16 flags;
};

struct maglev_key {
	__u32 service_id;
	__u32 slot;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct svc4_key);
	__type(value, struct svc_value);
} fluxvm_svc4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct backend_key);
	__type(value, struct backend4_value);
} fluxvm_backend4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct maglev_key);
	__type(value, __u32);
} fluxvm_maglev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} fluxvm_sguard SEC(".maps");

static __always_inline __u32 mix32(__u32 x)
{
	x ^= x >> 16;
	x *= 0x7feb352du;
	x ^= x >> 15;
	x *= 0x846ca68bu;
	x ^= x >> 16;
	return x;
}

static __always_inline __u32 flow_hash4(
	__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u8 protocol)
{
	__u32 ports = ((__u32)sport << 16) | dport;
	return mix32(saddr ^ mix32(daddr) ^ mix32(ports) ^ ((__u32)protocol << 24));
}

SEC("cgroup/connect4")
int fvm_svc_connect4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	__u32 *guard = bpf_map_lookup_elem(&fluxvm_sguard, &zero);
	if (guard && *guard)
		return 1;

	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;

	__u16 dport_host = bpf_ntohs((__u16)ctx->user_port);
	struct svc4_key skey = {
		.address = ctx->user_ip4,
		.port = dport_host,
		.protocol = (__u8)ctx->protocol,
		.pad = 0,
	};
	struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc4, &skey);
	if (!svc || svc->table_size == 0)
		return 1;
	if (svc->mode != FLUXVM_SVC_MODE_NAT)
		return 1;

	__u32 h = flow_hash4(ctx->user_ip4, ctx->user_ip4, 0, dport_host,
			     (__u8)ctx->protocol);
	struct maglev_key mkey = {
		.service_id = svc->service_id,
		.slot = h % svc->table_size,
	};
	__u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
	if (!backend_id)
		return 1;

	struct backend_key bkey = {
		.service_id = svc->service_id,
		.backend_id = *backend_id,
	};
	struct backend4_value *be = bpf_map_lookup_elem(&fluxvm_backend4, &bkey);
	if (!be || !(be->flags & FLUXVM_SVC_BACKEND_READY) ||
	    (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY))
		return 1;

	ctx->user_ip4 = be->address;
	ctx->user_port = bpf_htons(be->port);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
