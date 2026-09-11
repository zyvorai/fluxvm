// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//! Portable mirror of Set 19's verifier-bounded IPv6 extension-header walk.
//!
//! The production walk lives in `bpf/fluxvm_tc.bpf.c` /
//! `bpf/fluxvm_pod_ingress.bpf.c`. This Rust table keeps CI covering the
//! contract without loading BPF objects.

#![allow(dead_code)]

/// IPv6 next-header values exercised by Set 19.
pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPPROTO_NONE: u8 = 59;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_SCTP: u8 = 132;

/// Maximum extension headers the BPF walk will chase (verifier budget).
pub const MAX_IPV6_EXT_HEADERS: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkOutcome {
    /// Final L4 protocol and byte offset from start of IPv6 header payload.
    L4 { protocol: u8, payload_off: usize },
    /// Stop without L4 (ESP / NoNext / depth exceeded / truncated).
    Stop,
}

/// Walk a sequence of `(next_header, header_len_bytes)` descriptors the same
/// way the BPF helper does: Hop-by-Hop / Routing / DestOpts advance by
/// length; Fragment advances 8; AH advances by (payloadlen+2)*4; ESP and
/// NoNext stop; unknown next-header is treated as final L4.
pub fn walk_ipv6_extensions(
    mut next: u8,
    headers: &[(u8 /*this hdr*/, u8 /*hdrlen field or 0*/)],
) -> WalkOutcome {
    let mut off = 0usize;
    for (i, &(hdr, hdrlen)) in headers.iter().enumerate() {
        if i >= MAX_IPV6_EXT_HEADERS {
            return WalkOutcome::Stop;
        }
        if hdr != next {
            return WalkOutcome::Stop;
        }
        match hdr {
            IPPROTO_ESP | IPPROTO_NONE => return WalkOutcome::Stop,
            IPPROTO_FRAGMENT => {
                off = off.saturating_add(8);
                // Test vector encodes the "next" after fragment in hdrlen slot.
                next = hdrlen;
            }
            IPPROTO_AH => {
                let len = (u16::from(hdrlen) + 2) * 4;
                off = off.saturating_add(usize::from(len));
                // Next header carried in the vector's following entry match.
                if let Some(&(n, _)) = headers.get(i + 1) {
                    // AH's next is passed as the *next* descriptor's hdr in tests;
                    // production reads it from the AH header. For the table we
                    // encode AH next in the low bits by requiring the next
                    // descriptor's hdr to be the subsequent protocol.
                    next = n;
                    continue;
                }
                return WalkOutcome::Stop;
            }
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                let len = (usize::from(hdrlen) + 1) * 8;
                off = off.saturating_add(len);
                if let Some(&(n, _)) = headers.get(i + 1) {
                    next = n;
                    continue;
                }
                return WalkOutcome::Stop;
            }
            _ => {
                return WalkOutcome::L4 {
                    protocol: hdr,
                    payload_off: off,
                };
            }
        }
    }
    WalkOutcome::L4 {
        protocol: next,
        payload_off: off,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_tcp_is_l4() {
        assert_eq!(
            walk_ipv6_extensions(IPPROTO_TCP, &[]),
            WalkOutcome::L4 {
                protocol: IPPROTO_TCP,
                payload_off: 0
            }
        );
    }

    #[test]
    fn hop_by_hop_then_tcp() {
        // hdrlen=0 → (0+1)*8 = 8 bytes
        let out = walk_ipv6_extensions(IPPROTO_HOPOPTS, &[(IPPROTO_HOPOPTS, 0), (IPPROTO_TCP, 0)]);
        assert_eq!(
            out,
            WalkOutcome::L4 {
                protocol: IPPROTO_TCP,
                payload_off: 8
            }
        );
    }

    #[test]
    fn fragment_then_sctp() {
        let out = walk_ipv6_extensions(IPPROTO_FRAGMENT, &[(IPPROTO_FRAGMENT, IPPROTO_SCTP)]);
        assert_eq!(
            out,
            WalkOutcome::L4 {
                protocol: IPPROTO_SCTP,
                payload_off: 8
            }
        );
    }

    #[test]
    fn esp_stops() {
        assert_eq!(
            walk_ipv6_extensions(IPPROTO_ESP, &[(IPPROTO_ESP, 0)]),
            WalkOutcome::Stop
        );
    }

    #[test]
    fn none_stops() {
        assert_eq!(
            walk_ipv6_extensions(IPPROTO_NONE, &[(IPPROTO_NONE, 0)]),
            WalkOutcome::Stop
        );
    }

    #[test]
    fn depth_cap_stops() {
        let mut hdrs = Vec::new();
        for _ in 0..MAX_IPV6_EXT_HEADERS + 1 {
            hdrs.push((IPPROTO_DSTOPTS, 0u8));
        }
        assert_eq!(
            walk_ipv6_extensions(IPPROTO_DSTOPTS, &hdrs),
            WalkOutcome::Stop
        );
    }
}
