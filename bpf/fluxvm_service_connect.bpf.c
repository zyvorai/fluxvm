// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: GPL-2.0-only
//
// Opt-in cgroup/connect{4,6} acceleration for node-local host sockets talking
// to Service Fabric VIPs. Shares TC/XDP pinmaps (svc/backend/maglev/fct).
// Affinity parity with TC: prefer fluxvm_fct* when the backend is Ready or
// Draining (and not Unhealthy); else Maglev Ready selection. Fail-open: if
// maps miss or backend ineligible, leave the connect unchanged so VM TAP/TC/XDP
// remains the canonical path.

#include <linux/bpf.h>
#include <linux/in.h>
#include <stddef.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "fluxvm_service_maps.bpf.h"

#define FLUXVM_SVC_BACKEND_READY 1u
#define FLUXVM_SVC_BACKEND_DRAINING 2u
#define FLUXVM_SVC_BACKEND_UNHEALTHY 4u
#define FLUXVM_SVC_MODE_NAT 1u
#define FLUXVM_CT_UDP_NS 60000000000ULL
#define FLUXVM_CT_TCP_EST_NS 300000000000ULL

struct svc4_key {
	__u32 address;
	__u16 port;
	__u8 protocol;
	__u8 pad;
};

struct svc6_key {
	__u8 address[16];
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

struct backend6_value {
	__u8 address[16];
	__u16 port;
	__u16 flags;
};

struct maglev_key {
	__u32 service_id;
	__u32 slot;
};

struct fct4_key {
	__u32 client_address;
	__u32 vip_address;
	__u16 client_port;
	__u16 vip_port;
	__u8 protocol;
	__u8 pad[3];
};

struct fct6_key {
	__u8 client_address[16];
	__u8 vip_address[16];
	__u16 client_port;
	__u16 vip_port;
	__u8 protocol;
	__u8 pad[3];
};

struct fct_value {
	__u32 service_id;
	__u32 backend_id;
	__u64 last_seen_ns;
	__u64 expires_at_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUXVM_MAX_SVC);
	__type(key, struct svc4_key);
	__type(value, struct svc_value);
} fluxvm_svc4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUXVM_MAX_SVC);
	__type(key, struct svc6_key);
	__type(value, struct svc_value);
} fluxvm_svc6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUXVM_MAX_BACKEND);
	__type(key, struct backend_key);
	__type(value, struct backend4_value);
} fluxvm_backend4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUXVM_MAX_BACKEND);
	__type(key, struct backend_key);
	__type(value, struct backend6_value);
} fluxvm_backend6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLUXVM_MAX_MAGLEV);
	__type(key, struct maglev_key);
	__type(value, __u32);
} fluxvm_maglev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLUXVM_MAX_CT);
	__type(key, struct fct4_key);
	__type(value, struct fct_value);
} fluxvm_fct4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLUXVM_MAX_CT);
	__type(key, struct fct6_key);
	__type(value, struct fct_value);
} fluxvm_fct6 SEC(".maps");

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

static __always_inline __u32 hash_words6(
	const __u8 *src, const __u8 *dst, __u16 sport, __u16 dport, __u8 protocol)
{
	__u32 h = ((__u32)sport << 16) | dport;
#pragma unroll
	for (int i = 0; i < 4; i++) {
		__u32 a = 0, b = 0;
		__builtin_memcpy(&a, src + i * 4, 4);
		__builtin_memcpy(&b, dst + i * 4, 4);
		h = mix32(h ^ a ^ mix32(b));
	}
	return mix32(h ^ ((__u32)protocol << 24));
}

static __always_inline __u64 connect_timeout_ns(__u8 protocol)
{
	if (protocol == IPPROTO_UDP)
		return FLUXVM_CT_UDP_NS;
	return FLUXVM_CT_TCP_EST_NS;
}

/* connect{4,6} ctx forbids msg_src_*; use bpf_sock when present. */
static __always_inline __u16 connect_sport(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	if (!sk)
		return 0;
	/* bpf_sock.src_port is host byte order. */
	return (__u16)sk->src_port;
}

static __always_inline __u32 connect_saddr4(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	if (!sk)
		return 0;
	return sk->src_ip4;
}

static __always_inline void connect_saddr6(struct bpf_sock_addr *ctx, __u8 *out)
{
	struct bpf_sock *sk = ctx->sk;
	if (!sk) {
		__builtin_memset(out, 0, 16);
		return;
	}
	__builtin_memcpy(out, sk->src_ip6, 16);
}

/* TC affinity parity: Ready|Draining, not Unhealthy; refresh TTL on hit. */
static __always_inline int affinity4_connect(
	__u32 sid, __u32 client, __u32 vip, __u16 sport, __u16 dport,
	__u8 protocol, __u32 *backend_id)
{
	struct fct4_key key = {
		.client_address = client,
		.vip_address = vip,
		.client_port = sport,
		.vip_port = dport,
		.protocol = protocol,
		.pad = {0, 0, 0},
	};
	struct fct_value *ct = bpf_map_lookup_elem(&fluxvm_fct4, &key);
	__u64 now = bpf_ktime_get_ns();
	if (!ct || ct->service_id != sid)
		return 0;
	if (ct->expires_at_ns <= now) {
		bpf_map_delete_elem(&fluxvm_fct4, &key);
		return 0;
	}
	struct backend_key bk = {.service_id = sid, .backend_id = ct->backend_id};
	struct backend4_value *be = bpf_map_lookup_elem(&fluxvm_backend4, &bk);
	if (!be || !(be->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING)) ||
	    (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY)) {
		bpf_map_delete_elem(&fluxvm_fct4, &key);
		return 0;
	}
	ct->last_seen_ns = now;
	ct->expires_at_ns = now + connect_timeout_ns(protocol);
	*backend_id = ct->backend_id;
	return 1;
}

static __always_inline int affinity6_connect(
	__u32 sid, const __u8 *client, const __u8 *vip, __u16 sport, __u16 dport,
	__u8 protocol, __u32 *backend_id)
{
	struct fct6_key key = {};
	key.client_port = sport;
	key.vip_port = dport;
	key.protocol = protocol;
	__builtin_memcpy(key.client_address, client, 16);
	__builtin_memcpy(key.vip_address, vip, 16);
	struct fct_value *ct = bpf_map_lookup_elem(&fluxvm_fct6, &key);
	__u64 now = bpf_ktime_get_ns();
	if (!ct || ct->service_id != sid)
		return 0;
	if (ct->expires_at_ns <= now) {
		bpf_map_delete_elem(&fluxvm_fct6, &key);
		return 0;
	}
	struct backend_key bk = {.service_id = sid, .backend_id = ct->backend_id};
	struct backend6_value *be = bpf_map_lookup_elem(&fluxvm_backend6, &bk);
	if (!be || !(be->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING)) ||
	    (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY)) {
		bpf_map_delete_elem(&fluxvm_fct6, &key);
		return 0;
	}
	ct->last_seen_ns = now;
	ct->expires_at_ns = now + connect_timeout_ns(protocol);
	*backend_id = ct->backend_id;
	return 1;
}

static __always_inline int backend4_eligible(
	struct backend4_value *be, int pinned)
{
	if (!be || (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY))
		return 0;
	if (pinned)
		return !!(be->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING));
	return !!(be->flags & FLUXVM_SVC_BACKEND_READY);
}

static __always_inline int backend6_eligible(
	struct backend6_value *be, int pinned)
{
	if (!be || (be->flags & FLUXVM_SVC_BACKEND_UNHEALTHY))
		return 0;
	if (pinned)
		return !!(be->flags & (FLUXVM_SVC_BACKEND_READY | FLUXVM_SVC_BACKEND_DRAINING));
	return !!(be->flags & FLUXVM_SVC_BACKEND_READY);
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

	__u8 protocol = (__u8)ctx->protocol;
	__u16 dport_host = bpf_ntohs((__u16)ctx->user_port);
	__u32 vip = ctx->user_ip4;
	__u32 saddr = connect_saddr4(ctx);
	__u32 client = saddr ? saddr : vip;
	__u16 sport = connect_sport(ctx);

	struct svc4_key skey = {
		.address = vip,
		.port = dport_host,
		.protocol = protocol,
		.pad = 0,
	};
	struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc4, &skey);
	if (!svc || svc->mode != FLUXVM_SVC_MODE_NAT)
		return 1;

	__u32 bid = 0;
	int pinned = affinity4_connect(svc->service_id, client, vip, sport,
				       dport_host, protocol, &bid);
	if (!pinned) {
		if (svc->table_size == 0)
			return 1;
		__u32 h = flow_hash4(client, vip, sport, dport_host, protocol);
		struct maglev_key mkey = {
			.service_id = svc->service_id,
			.slot = h % svc->table_size,
		};
		__u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
		if (!backend_id)
			return 1;
		bid = *backend_id;
	}

	struct backend_key bkey = {
		.service_id = svc->service_id,
		.backend_id = bid,
	};
	struct backend4_value *be = bpf_map_lookup_elem(&fluxvm_backend4, &bkey);
	if (!backend4_eligible(be, pinned))
		return 1;

	ctx->user_ip4 = be->address;
	ctx->user_port = bpf_htons(be->port);
	return 1;
}

SEC("cgroup/connect6")
int fvm_svc_connect6(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	__u32 *guard = bpf_map_lookup_elem(&fluxvm_sguard, &zero);
	if (guard && *guard)
		return 1;

	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;

	__u8 protocol = (__u8)ctx->protocol;
	__u16 dport_host = bpf_ntohs((__u16)ctx->user_port);
	__u16 sport = connect_sport(ctx);

	__u8 vip[16];
	__u8 client[16];
	__builtin_memcpy(vip, ctx->user_ip6, 16);
	connect_saddr6(ctx, client);
	/* Unspecified source → hash/affinity against VIP (same as connect4). */
	{
		__u32 c0 = 0, c1 = 0, c2 = 0, c3 = 0;
		__builtin_memcpy(&c0, client, 4);
		__builtin_memcpy(&c1, client + 4, 4);
		__builtin_memcpy(&c2, client + 8, 4);
		__builtin_memcpy(&c3, client + 12, 4);
		if (!(c0 | c1 | c2 | c3))
			__builtin_memcpy(client, vip, 16);
	}

	struct svc6_key skey = {
		.port = dport_host,
		.protocol = protocol,
		.pad = 0,
	};
	__builtin_memcpy(skey.address, vip, 16);
	struct svc_value *svc = bpf_map_lookup_elem(&fluxvm_svc6, &skey);
	if (!svc || svc->mode != FLUXVM_SVC_MODE_NAT)
		return 1;

	__u32 bid = 0;
	int pinned = affinity6_connect(svc->service_id, client, vip, sport,
				       dport_host, protocol, &bid);
	if (!pinned) {
		if (svc->table_size == 0)
			return 1;
		__u32 h = hash_words6(client, vip, sport, dport_host, protocol);
		struct maglev_key mkey = {
			.service_id = svc->service_id,
			.slot = h % svc->table_size,
		};
		__u32 *backend_id = bpf_map_lookup_elem(&fluxvm_maglev, &mkey);
		if (!backend_id)
			return 1;
		bid = *backend_id;
	}

	struct backend_key bkey = {
		.service_id = svc->service_id,
		.backend_id = bid,
	};
	struct backend6_value *be = bpf_map_lookup_elem(&fluxvm_backend6, &bkey);
	if (!backend6_eligible(be, pinned))
		return 1;

	/* Write user_ip6 word-by-word; memcpy into ctx is rejected / fused. */
	{
		__u32 w0 = 0, w1 = 0, w2 = 0, w3 = 0;
		__builtin_memcpy(&w0, be->address, 4);
		__builtin_memcpy(&w1, be->address + 4, 4);
		__builtin_memcpy(&w2, be->address + 8, 4);
		__builtin_memcpy(&w3, be->address + 12, 4);
		ctx->user_ip6[0] = w0;
		ctx->user_ip6[1] = w1;
		ctx->user_ip6[2] = w2;
		ctx->user_ip6[3] = w3;
	}
	ctx->user_port = bpf_htons(be->port);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
