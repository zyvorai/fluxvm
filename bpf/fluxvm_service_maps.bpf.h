/* Copyright 2026 Zyvor AI Labs · https://zyvor.dev */
/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FLUXVM_SERVICE_MAPS_BPF_H
#define FLUXVM_SERVICE_MAPS_BPF_H

/*
 * Compile-time map capacity tiers for Service Fabric objects.
 *
 * Build with -DFLUXVM_MAP_TIER=S|M|L (letter tokens). Unset defaults to M,
 * matching historical max_entries and fluxvm_service.bpf.o.
 *
 * Capacities must stay in sync with crates/fluxvm-network map_tier helpers.
 */

#define FLUXVM_MAP_TIER_TOK_S 1
#define FLUXVM_MAP_TIER_TOK_M 2
#define FLUXVM_MAP_TIER_TOK_L 3

#define FLUXVM_MAP_TIER_CAT(a, b) a##b
#define FLUXVM_MAP_TIER_NUM(t) FLUXVM_MAP_TIER_CAT(FLUXVM_MAP_TIER_TOK_, t)

#ifndef FLUXVM_MAP_TIER
# define FLUXVM_MAP_TIER_VAL FLUXVM_MAP_TIER_TOK_M
#else
# define FLUXVM_MAP_TIER_VAL FLUXVM_MAP_TIER_NUM(FLUXVM_MAP_TIER)
#endif

#if FLUXVM_MAP_TIER_VAL == FLUXVM_MAP_TIER_TOK_S
# define FLUXVM_MAX_SVC       1024
# define FLUXVM_MAX_BACKEND   4096
# define FLUXVM_MAX_MAGLEV    65536
# define FLUXVM_MAX_CT        32768
# define FLUXVM_MAX_NAT       32768
# define FLUXVM_MAX_SFLOWS    16384
# define FLUXVM_MAX_SID       16384
# define FLUXVM_MAX_HAQ       8192
#elif FLUXVM_MAP_TIER_VAL == FLUXVM_MAP_TIER_TOK_L
# define FLUXVM_MAX_SVC       8192
# define FLUXVM_MAX_BACKEND   32768
# define FLUXVM_MAX_MAGLEV    524288
# define FLUXVM_MAX_CT        262144
# define FLUXVM_MAX_NAT       262144
# define FLUXVM_MAX_SFLOWS    131072
# define FLUXVM_MAX_SID       131072
# define FLUXVM_MAX_HAQ       65536
#else
/* M — historical defaults */
# define FLUXVM_MAX_SVC       4096
# define FLUXVM_MAX_BACKEND   16384
# define FLUXVM_MAX_MAGLEV    262144
# define FLUXVM_MAX_CT        131072
# define FLUXVM_MAX_NAT       131072
# define FLUXVM_MAX_SFLOWS    65536
# define FLUXVM_MAX_SID       65536
# define FLUXVM_MAX_HAQ       32768
#endif

#endif /* FLUXVM_SERVICE_MAPS_BPF_H */
