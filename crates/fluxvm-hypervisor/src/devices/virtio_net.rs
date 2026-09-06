// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::devices::virtio_mmio::VirtioState;
use crate::error::Result;
use crate::memory::GuestMemory;
use crate::tap::Tap;

const VRING_DESC_F_NEXT: u16 = 1;

fn gather(mem: &GuestMemory, desc_base: u64, head: u16) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut idx = head;
    for _ in 0..16 {
        let mut raw = [0u8; 16];
        mem.read_at(desc_base + idx as u64 * 16, &mut raw)?;
        let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        let mut buf = vec![0u8; len as usize];
        mem.read_at(addr, &mut buf)?;
        out.extend_from_slice(&buf);
        if flags & VRING_DESC_F_NEXT == 0 {
            break;
        }
        idx = next;
    }
    Ok(out)
}

fn used_push(
    mem: &mut GuestMemory,
    used_gpa: u64,
    qnum: u32,
    desc_id: u16,
    written: u32,
) -> Result<()> {
    let idx = mem.read_u16(used_gpa + 2)?;
    let slot = (idx as u32) % qnum;
    let elem = used_gpa + 4 + slot as u64 * 8;
    mem.write_at(elem, &(desc_id as u32).to_le_bytes())?;
    mem.write_at(elem + 4, &written.to_le_bytes())?;
    mem.write_u16(used_gpa + 2, idx.wrapping_add(1))?;
    Ok(())
}

fn inject_rx(mem: &mut GuestMemory, st: &mut VirtioState, frame: &[u8]) -> Result<bool> {
    let q = &mut st.queues[0];
    if q.ready == 0 || q.num == 0 {
        return Ok(false);
    }
    let avail_idx = mem.read_u16(q.avail + 2)?;
    if q.last_avail == avail_idx {
        return Ok(false);
    }
    let slot = (q.last_avail as u32) % q.num;
    let head = mem.read_u16(q.avail + 4 + slot as u64 * 2)?;
    let mut raw = [0u8; 16];
    mem.read_at(q.desc + head as u64 * 16, &mut raw)?;
    let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    let mut pkt = vec![0u8; 12];
    pkt.extend_from_slice(frame);
    if pkt.len() > len as usize {
        pkt.truncate(len as usize);
    }
    mem.write_at(addr, &pkt)?;
    used_push(mem, q.used, q.num, head, pkt.len() as u32)?;
    q.last_avail = q.last_avail.wrapping_add(1);
    Ok(true)
}

fn gateway_reply(frame: &[u8], guest_mac: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 42 {
        return None;
    }
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    let gw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    if etype == 0x0806 {
        let op = u16::from_be_bytes([frame[20], frame[21]]);
        let tpa = &frame[38..42];
        if op == 1 && tpa == [192, 168, 100, 1] {
            let mut r = vec![0u8; 42];
            r[0..6].copy_from_slice(&guest_mac);
            r[6..12].copy_from_slice(&gw_mac);
            r[12] = 0x08;
            r[13] = 0x06;
            r[14] = 0x00;
            r[15] = 0x01;
            r[16] = 0x08;
            r[17] = 0x00;
            r[18] = 0x06;
            r[19] = 0x04;
            r[20] = 0x00;
            r[21] = 0x02;
            r[22..28].copy_from_slice(&gw_mac);
            r[28..32].copy_from_slice(&[192, 168, 100, 1]);
            r[32..38].copy_from_slice(&guest_mac);
            r[38..42].copy_from_slice(&[192, 168, 100, 2]);
            return Some(r);
        }
    }
    if etype == 0x0800 && frame.len() >= 42 && frame[23] == 1 && frame[34] == 8 {
        let mut r = frame.to_vec();
        r[0..6].copy_from_slice(&guest_mac);
        r[6..12].copy_from_slice(&gw_mac);
        r[26..30].copy_from_slice(&[192, 168, 100, 1]);
        r[30..34].copy_from_slice(&[192, 168, 100, 2]);
        r[34] = 0;
        r[24] = 0;
        r[25] = 0;
        let ihl = ((r[14] & 0xf) as usize) * 4;
        let sum = inet_cksum(&r[14..14 + ihl]);
        r[24] = (sum >> 8) as u8;
        r[25] = sum as u8;
        r[36] = 0;
        r[37] = 0;
        let c = inet_cksum(&r[34..]);
        r[36] = (c >> 8) as u8;
        r[37] = c as u8;
        return Some(r);
    }
    None
}

fn inet_cksum(p: &[u8]) -> u16 {
    let mut s = 0u32;
    let mut i = 0;
    while i + 1 < p.len() {
        s += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
        i += 2;
    }
    if i < p.len() {
        s += (p[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !s as u16
}

pub fn handle_notify(
    mem: &mut GuestMemory,
    st: &mut VirtioState,
    tap: Option<&Tap>,
    qsel: u32,
) -> Result<u32> {
    if qsel != 1 {
        return Ok(0);
    }
    let qnum;
    let desc;
    let avail;
    let used;
    {
        let q = &st.queues[1];
        if q.ready == 0 || q.num == 0 {
            return Ok(0);
        }
        qnum = q.num;
        desc = q.desc;
        avail = q.avail;
        used = q.used;
    }
    let mut frames = 0u32;
    loop {
        let avail_idx = mem.read_u16(avail + 2)?;
        if st.queues[1].last_avail == avail_idx {
            break;
        }
        let slot = (st.queues[1].last_avail as u32) % qnum;
        let head = mem.read_u16(avail + 4 + slot as u64 * 2)?;
        let buf = gather(mem, desc, head)?;
        used_push(mem, used, qnum, head, buf.len() as u32)?;
        st.queues[1].last_avail = st.queues[1].last_avail.wrapping_add(1);
        let frame = if buf.len() > 12 { &buf[12..] } else { &[] };
        if frame.is_empty() {
            continue;
        }
        frames += 1;
        let et = if frame.len() >= 14 {
            u16::from_be_bytes([frame[12], frame[13]])
        } else {
            0
        };
        eprintln!("[net] TX {} bytes ethertype={et:#06x}", frame.len());
        if let Some(tap) = tap {
            let _ = tap.write_frame(frame);
        }
        let mac = st.mac;
        if let Some(reply) = gateway_reply(frame, mac) {
            let _ = inject_rx(mem, st, &reply);
            eprintln!("[net] RX gateway {} bytes", reply.len());
        }
    }
    Ok(frames)
}

// Keep parse_mac used by config.
pub struct VirtioNetConfig {
    pub tap: String,
    pub mac: [u8; 6],
    pub vhost: bool,
    pub queues: u8,
    pub mbit_limit: u32,
}

impl VirtioNetConfig {
    pub fn parse_mac(s: &str) -> crate::error::Result<[u8; 6]> {
        let parts: Vec<_> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(crate::error::FluxError::Network(format!("bad MAC {s}")));
        }
        let mut mac = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(p, 16)
                .map_err(|_| crate::error::FluxError::Network(format!("bad MAC {s}")))?;
        }
        Ok(mac)
    }
}
