// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal DHCPv4 client packets (RFC 2131): DISCOVER/REQUEST out, OFFER/ACK/NAK in. The socket and interface
//! work lives in `main.rs`; this is the portable, tested encoding.

use std::net::Ipv4Addr;

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;

const MAGIC: [u8; 4] = [99, 130, 83, 99];
const FIXED_LEN: usize = 236;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub message_type: u8,
    pub address: Ipv4Addr,
    pub server_id: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_seconds: Option<u32>,
}

impl Reply {
    /// Prefix length from the netmask (default /24, which is what vz NAT hands out).
    pub fn prefix_len(&self) -> u32 {
        self.netmask.map_or(24, |m| u32::from(m).count_ones())
    }
}

fn header(xid: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0u8; FIXED_LEN];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    // Broadcast flag: the client has no address yet and cannot take unicast replies.
    p[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    p[28..34].copy_from_slice(&mac);
    p.extend_from_slice(&MAGIC);
    p
}

fn finish(mut p: Vec<u8>) -> Vec<u8> {
    // subnet mask, router, DNS, host name, lease time
    p.extend_from_slice(&[55, 5, 1, 3, 6, 12, 51]);
    p.push(255);
    while p.len() < 300 {
        p.push(0);
    }
    p
}

pub fn discover(xid: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut p = header(xid, mac);
    p.extend_from_slice(&[53, 1, DISCOVER]);
    finish(p)
}

pub fn request(xid: u32, mac: [u8; 6], offer: &Reply) -> Vec<u8> {
    let mut p = header(xid, mac);
    p.extend_from_slice(&[53, 1, REQUEST]);
    p.extend_from_slice(&[50, 4]);
    p.extend_from_slice(&offer.address.octets());
    if let Some(s) = offer.server_id {
        p.extend_from_slice(&[54, 4]);
        p.extend_from_slice(&s.octets());
    }
    finish(p)
}

/// Parse a server reply addressed to this exchange; anything else (wrong xid, malformed, not a reply) is `None`.
pub fn parse(buf: &[u8], xid: u32, mac: [u8; 6]) -> Option<Reply> {
    if buf.len() < FIXED_LEN + 4
        || buf[0] != 2
        || buf[4..8] != xid.to_be_bytes()
        || buf[28..34] != mac
    {
        return None;
    }
    if buf[FIXED_LEN..FIXED_LEN + 4] != MAGIC {
        return None;
    }
    let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let mut r = Reply {
        message_type: 0,
        address: ip(&buf[16..20]),
        server_id: None,
        netmask: None,
        router: None,
        dns: Vec::new(),
        lease_seconds: None,
    };
    let mut i = FIXED_LEN + 4;
    while i < buf.len() {
        let code = buf[i];
        match code {
            0 => {
                i += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let len = *buf.get(i + 1)? as usize;
        let v = buf.get(i + 2..i + 2 + len)?;
        match (code, len) {
            (53, 1) => r.message_type = v[0],
            (1, 4) => r.netmask = Some(ip(v)),
            (3, l) if l >= 4 => r.router = Some(ip(v)),
            (6, l) if l >= 4 => r.dns = v.as_chunks::<4>().0.iter().map(|c| Ipv4Addr::from(*c)).collect(),
            (51, 4) => r.lease_seconds = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            (54, 4) => r.server_id = Some(ip(v)),
            _ => {}
        }
        i += 2 + len;
    }
    matches!(r.message_type, OFFER | ACK | NAK).then_some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0x46, 0x4c, 0x00, 0x00, 0x01];

    fn reply(xid: u32, kind: u8) -> Vec<u8> {
        let mut p = header(xid, MAC);
        p[0] = 2;
        p[16..20].copy_from_slice(&[192, 168, 64, 7]);
        p.extend_from_slice(&[
            53, 1, kind, 0, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 64, 1,
        ]);
        p.extend_from_slice(&[6, 8, 192, 168, 64, 1, 1, 1, 1, 1, 51, 4, 0, 0, 0x0e, 0x10]);
        p.extend_from_slice(&[54, 4, 192, 168, 64, 1, 255]);
        p
    }

    #[test]
    fn requests_are_well_formed() {
        let d = discover(0xdead_beef, MAC);
        assert_eq!(&d[..4], &[1, 1, 6, 0]);
        assert_eq!(&d[4..8], &0xdead_beefu32.to_be_bytes());
        assert_eq!(&d[10..12], &[0x80, 0]);
        assert_eq!(&d[28..34], &MAC);
        assert_eq!(&d[236..243], &[99, 130, 83, 99, 53, 1, DISCOVER]);
        assert!(d.len() >= 300);

        let offer = parse(&reply(9, OFFER), 9, MAC).unwrap();
        let r = request(9, MAC, &offer);
        let opts = &r[240..];
        assert!(opts.windows(3).any(|w| w == [53, 1, REQUEST]));
        assert!(opts.windows(6).any(|w| w == [50, 4, 192, 168, 64, 7]));
        assert!(opts.windows(6).any(|w| w == [54, 4, 192, 168, 64, 1]));
    }

    #[test]
    fn replies_parse() {
        let r = parse(&reply(9, ACK), 9, MAC).unwrap();
        assert_eq!(r.message_type, ACK);
        assert_eq!(r.address, Ipv4Addr::new(192, 168, 64, 7));
        assert_eq!(r.router, Some(Ipv4Addr::new(192, 168, 64, 1)));
        assert_eq!(
            r.dns,
            [Ipv4Addr::new(192, 168, 64, 1), Ipv4Addr::new(1, 1, 1, 1)]
        );
        assert_eq!(r.lease_seconds, Some(3600));
        assert_eq!(r.prefix_len(), 24);
    }

    #[test]
    fn foreign_or_broken_replies_are_ignored() {
        assert!(parse(&reply(9, ACK), 10, MAC).is_none());
        assert!(parse(&reply(9, ACK), 9, [0; 6]).is_none());
        assert!(parse(&discover(9, MAC), 9, MAC).is_none());
        let mut cut = reply(9, ACK);
        cut.truncate(250);
        cut.push(6);
        cut.push(40);
        assert!(parse(&cut, 9, MAC).is_none());
        assert!(parse(&reply(9, REQUEST), 9, MAC).is_none());
    }
}
