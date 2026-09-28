// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::devices::rate_limiter::RateLimiter;
use crate::devices::virtio_mmio::{QueueState, VirtioState};
use crate::error::Result;
use crate::memory::GuestMemory;
use crate::tap::Tap;
use std::sync::atomic::{fence, Ordering};

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;
const VRING_DESC_F_INDIRECT: u16 = 4;
const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

/// `virtio_net_hdr` with `VIRTIO_F_VERSION_1` (includes `num_buffers`); no
/// offloads or mergeable buffers are advertised, so it is all zero apart from
/// `num_buffers = 1`.
pub const NET_HDR_LEN: usize = 12;
/// Largest frame read from the tap in one go.
pub const RX_FRAME_MAX: usize = 65536;

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
    // The element must be visible before the index that publishes it.
    fence(Ordering::Release);
    mem.write_u16(used_gpa + 2, idx.wrapping_add(1))?;
    fence(Ordering::SeqCst);
    Ok(())
}

/// Outcome of trying to place one frame into the guest's RX queue.
#[derive(Debug, PartialEq, Eq)]
pub enum RxDelivery {
    /// Frame copied and published; `interrupt` is false when the guest set
    /// `VRING_AVAIL_F_NO_INTERRUPT`.
    Delivered { written: u32, interrupt: bool },
    /// Queue not ready or the guest has posted no buffer.
    NoBuffer,
    /// The next buffer chain cannot hold header + frame; it stays queued.
    TooSmall,
    /// Malformed ring or chain (bad index, loop, read-only or out-of-RAM
    /// descriptor); the buffer is retired unused where possible.
    Invalid,
}

fn rx_pending(mem: &GuestMemory, q: &QueueState) -> Result<u16> {
    if q.ready == 0 || q.num == 0 {
        return Ok(0);
    }
    Ok(mem.read_u16(q.avail + 2)?.wrapping_sub(q.last_avail))
}

/// Write `hdr` then `frame` into the device-writable descriptors `segs`.
fn scatter(mem: &mut GuestMemory, segs: &[(u64, u32)], hdr: &[u8], frame: &[u8]) -> Result<()> {
    let mut src: [&[u8]; 2] = [hdr, frame];
    let mut si = 0;
    for &(addr, len) in segs {
        let mut a = addr;
        let mut room = len as usize;
        while room > 0 && si < src.len() {
            let s = src[si];
            if s.is_empty() {
                si += 1;
                continue;
            }
            let n = s.len().min(room);
            mem.write_at(a, &s[..n])?;
            src[si] = &s[n..];
            a += n as u64;
            room -= n;
        }
    }
    Ok(())
}

/// Copy `frame` (behind a zeroed virtio-net header) into the next RX buffer
/// chain the guest posted on queue 0 and publish it on the used ring.
pub fn rx_deliver(mem: &mut GuestMemory, q: &mut QueueState, frame: &[u8]) -> Result<RxDelivery> {
    let pending = rx_pending(mem, q)?;
    if pending == 0 {
        return Ok(RxDelivery::NoBuffer);
    }
    if pending as u32 > q.num {
        return Ok(RxDelivery::Invalid);
    }
    let slot = (q.last_avail as u32) % q.num;
    let head = mem.read_u16(q.avail + 4 + slot as u64 * 2)?;

    let mut segs: Vec<(u64, u32)> = Vec::new();
    let mut capacity = 0u64;
    let mut bad = false;
    let mut idx = head;
    let mut steps = 0u32;
    loop {
        if idx as u32 >= q.num || steps >= q.num {
            bad = true;
            break;
        }
        steps += 1;
        let mut raw = [0u8; 16];
        if mem.read_at(q.desc + idx as u64 * 16, &mut raw).is_err() {
            bad = true;
            break;
        }
        let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        if flags & VRING_DESC_F_WRITE == 0 || flags & VRING_DESC_F_INDIRECT != 0 {
            bad = true;
            break;
        }
        segs.push((addr, len));
        capacity += len as u64;
        if flags & VRING_DESC_F_NEXT == 0 {
            break;
        }
        idx = next;
    }

    let need = (NET_HDR_LEN + frame.len()) as u64;
    if !bad && capacity < need {
        return Ok(RxDelivery::TooSmall);
    }
    if !bad {
        let mut hdr = [0u8; NET_HDR_LEN];
        hdr[10] = 1;
        bad = scatter(mem, &segs, &hdr, frame).is_err();
    }
    if bad {
        if (head as u32) < q.num {
            used_push(mem, q.used, q.num, head, 0)?;
        }
        q.last_avail = q.last_avail.wrapping_add(1);
        return Ok(RxDelivery::Invalid);
    }
    used_push(mem, q.used, q.num, head, need as u32)?;
    q.last_avail = q.last_avail.wrapping_add(1);
    let flags = mem.read_u16(q.avail)?;
    Ok(RxDelivery::Delivered {
        written: need as u32,
        interrupt: flags & VRING_AVAIL_F_NO_INTERRUPT == 0,
    })
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NetStats {
    pub rx_frames: u64,
    pub rx_bytes: u64,
    pub rx_no_buffer: u64,
    pub rx_too_small: u64,
    pub rx_invalid: u64,
    pub rx_rate_limited: u64,
    pub tx_frames: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RxPump {
    /// Tap drained; keep polling it.
    Idle,
    /// Guest has no free RX buffer; stop polling the tap until it kicks queue 0.
    NoBuffers,
    /// Budget exhausted with frames possibly still pending.
    More,
}

/// Move up to `budget` frames from the tap into guest RX buffers. Returns the
/// pump state and whether the guest interrupt line should be raised.
pub fn rx_pump(
    mem: &mut GuestMemory,
    st: &mut VirtioState,
    tap: &Tap,
    limiter: Option<&RateLimiter>,
    stats: &mut NetStats,
    scratch: &mut [u8],
    budget: usize,
) -> Result<(RxPump, bool)> {
    let mut irq = false;
    for _ in 0..budget {
        // Look for a buffer before reading so a frame is never taken from the
        // tap with nowhere to put it.
        if rx_pending(mem, &st.queues[0])? == 0 {
            return Ok((RxPump::NoBuffers, irq));
        }
        let Some(n) = tap.read_frame(scratch)? else {
            return Ok((RxPump::Idle, irq));
        };
        let frame = &scratch[..n];
        if let Some(lim) = limiter {
            if !lim.consume(n as u64) {
                stats.rx_rate_limited += 1;
                continue;
            }
        }
        match rx_deliver(mem, &mut st.queues[0], frame)? {
            RxDelivery::Delivered { interrupt, .. } => {
                stats.rx_frames += 1;
                stats.rx_bytes += n as u64;
                irq |= interrupt;
            }
            RxDelivery::NoBuffer => stats.rx_no_buffer += 1,
            RxDelivery::TooSmall => stats.rx_too_small += 1,
            RxDelivery::Invalid => stats.rx_invalid += 1,
        }
    }
    Ok((RxPump::More, irq))
}

fn inject_rx(mem: &mut GuestMemory, st: &mut VirtioState, frame: &[u8]) -> Result<bool> {
    Ok(matches!(
        rx_deliver(mem, &mut st.queues[0], frame)?,
        RxDelivery::Delivered { .. }
    ))
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
    limiter: Option<&crate::devices::rate_limiter::RateLimiter>,
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
        if let Some(lim) = limiter {
            if !lim.consume(buf.len() as u64) {
                break;
            }
        }
        used_push(mem, used, qnum, head, buf.len() as u32)?;
        st.queues[1].last_avail = st.queues[1].last_avail.wrapping_add(1);
        let frame = if buf.len() > 12 { &buf[12..] } else { &[] };
        if frame.is_empty() {
            continue;
        }
        frames += 1;
        match tap {
            Some(tap) => {
                let _ = tap.write_frame(frame);
            }
            // The canned gateway only stands in when there is no tap; with a
            // tap the host stack answers for 192.168.100.1 itself.
            None => {
                let mac = st.mac;
                if let Some(reply) = gateway_reply(frame, mac) {
                    let _ = inject_rx(mem, st, &reply);
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    const DESC: u64 = 0x1000;
    const AVAIL: u64 = 0x2000;
    const USED: u64 = 0x3000;
    const NUM: u32 = 8;

    fn setup() -> (GuestMemory, QueueState) {
        let mem = GuestMemory::allocate(1 << 20).unwrap();
        let q = QueueState {
            num: NUM,
            ready: 1,
            desc: DESC,
            avail: AVAIL,
            used: USED,
            last_avail: 0,
        };
        (mem, q)
    }

    fn set_desc(mem: &mut GuestMemory, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let mut raw = [0u8; 16];
        raw[0..8].copy_from_slice(&addr.to_le_bytes());
        raw[8..12].copy_from_slice(&len.to_le_bytes());
        raw[12..14].copy_from_slice(&flags.to_le_bytes());
        raw[14..16].copy_from_slice(&next.to_le_bytes());
        mem.write_at(DESC + i as u64 * 16, &raw).unwrap();
    }

    fn post(mem: &mut GuestMemory, ring_pos: u16, head: u16) {
        mem.write_u16(AVAIL + 4 + (ring_pos as u64 % NUM as u64) * 2, head)
            .unwrap();
        mem.write_u16(AVAIL + 2, ring_pos.wrapping_add(1)).unwrap();
    }

    fn used_idx(mem: &GuestMemory) -> u16 {
        mem.read_u16(USED + 2).unwrap()
    }

    fn used_elem(mem: &GuestMemory, slot: u64) -> (u32, u32) {
        let mut b = [0u8; 8];
        mem.read_at(USED + 4 + slot * 8, &mut b).unwrap();
        (
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
        )
    }

    fn frame(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8 + 1).collect()
    }

    #[test]
    fn no_buffer_when_queue_not_ready_or_empty() {
        let (mut mem, mut q) = setup();
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::NoBuffer
        );
        post(&mut mem, 0, 0);
        q.ready = 0;
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::NoBuffer
        );
        assert_eq!(used_idx(&mem), 0);
    }

    #[test]
    fn single_descriptor_exact_fit() {
        let (mut mem, mut q) = setup();
        let f = frame(100);
        set_desc(
            &mut mem,
            0,
            0x8000,
            (NET_HDR_LEN + f.len()) as u32,
            VRING_DESC_F_WRITE,
            0,
        );
        post(&mut mem, 0, 0);
        let r = rx_deliver(&mut mem, &mut q, &f).unwrap();
        assert_eq!(
            r,
            RxDelivery::Delivered {
                written: (NET_HDR_LEN + 100) as u32,
                interrupt: true
            }
        );
        let mut got = vec![0u8; NET_HDR_LEN + 100];
        mem.read_at(0x8000, &mut got).unwrap();
        assert_eq!(&got[..10], &[0u8; 10]);
        assert_eq!(&got[10..12], &[1, 0]);
        assert_eq!(&got[12..], &f[..]);
        assert_eq!(used_idx(&mem), 1);
        assert_eq!(used_elem(&mem, 0), (0, 112));
        assert_eq!(q.last_avail, 1);
    }

    #[test]
    fn short_chain_spans_descriptors() {
        let (mut mem, mut q) = setup();
        let f = frame(300);
        // header split from data, data split across two more buffers.
        set_desc(
            &mut mem,
            3,
            0x8000,
            12,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            5,
        );
        set_desc(
            &mut mem,
            5,
            0x9000,
            100,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            1,
        );
        set_desc(&mut mem, 1, 0xA000, 4096, VRING_DESC_F_WRITE, 0);
        post(&mut mem, 0, 3);
        let r = rx_deliver(&mut mem, &mut q, &f).unwrap();
        assert!(matches!(r, RxDelivery::Delivered { written: 312, .. }));
        let mut a = [0u8; 12];
        mem.read_at(0x8000, &mut a).unwrap();
        assert_eq!(a[10], 1);
        let mut b = vec![0u8; 100];
        mem.read_at(0x9000, &mut b).unwrap();
        assert_eq!(&b[..], &f[..100]);
        let mut c = vec![0u8; 200];
        mem.read_at(0xA000, &mut c).unwrap();
        assert_eq!(&c[..], &f[100..]);
        assert_eq!(used_elem(&mem, 0), (3, 312));
    }

    #[test]
    fn oversize_frame_leaves_buffer_queued() {
        let (mut mem, mut q) = setup();
        set_desc(&mut mem, 0, 0x8000, 111, VRING_DESC_F_WRITE, 0);
        post(&mut mem, 0, 0);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(100)).unwrap(),
            RxDelivery::TooSmall
        );
        assert_eq!(q.last_avail, 0);
        assert_eq!(used_idx(&mem), 0);
        // A smaller frame still fits the same buffer afterwards.
        assert!(matches!(
            rx_deliver(&mut mem, &mut q, &frame(99)).unwrap(),
            RxDelivery::Delivered { .. }
        ));
    }

    #[test]
    fn ring_indices_wrap_around() {
        let (mut mem, mut q) = setup();
        q.last_avail = 0xfffe;
        mem.write_u16(USED + 2, 0xfffe).unwrap();
        for k in 0..4u16 {
            let head = k as u16;
            set_desc(
                &mut mem,
                head,
                0x8000 + head as u64 * 0x1000,
                2048,
                VRING_DESC_F_WRITE,
                0,
            );
            mem.write_u16(AVAIL + 4 + ((0xfffeu32 + k as u32) % NUM) as u64 * 2, head)
                .unwrap();
        }
        mem.write_u16(AVAIL + 2, 0xfffe_u16.wrapping_add(4))
            .unwrap();
        for k in 0..4 {
            let r = rx_deliver(&mut mem, &mut q, &frame(64 + k)).unwrap();
            assert!(matches!(r, RxDelivery::Delivered { .. }));
        }
        assert_eq!(q.last_avail, 2);
        assert_eq!(used_idx(&mem), 2);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(64)).unwrap(),
            RxDelivery::NoBuffer
        );
        // Second delivery landed in slot (0xffff % 8) with head 1.
        assert_eq!(used_elem(&mem, 0xffff % 8).0, 1);
    }

    #[test]
    fn invalid_descriptors_are_retired_not_wedged() {
        let (mut mem, mut q) = setup();
        // Read-only (device cannot write) descriptor.
        set_desc(&mut mem, 0, 0x8000, 2048, 0, 0);
        post(&mut mem, 0, 0);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Invalid
        );
        assert_eq!((q.last_avail, used_idx(&mem)), (1, 1));
        assert_eq!(used_elem(&mem, 0), (0, 0));

        // Address past the end of RAM.
        set_desc(&mut mem, 1, 1 << 30, 2048, VRING_DESC_F_WRITE, 0);
        post(&mut mem, 1, 1);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Invalid
        );
        assert_eq!(q.last_avail, 2);

        // Descriptor index outside the queue.
        post(&mut mem, 2, NUM as u16 + 3);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Invalid
        );
        assert_eq!(q.last_avail, 3);

        // Cycle: 4 -> 4.
        set_desc(
            &mut mem,
            4,
            0x8000,
            16,
            VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            4,
        );
        post(&mut mem, 3, 4);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Invalid
        );
        assert_eq!(q.last_avail, 4);

        // Indirect descriptors are not negotiated.
        set_desc(
            &mut mem,
            5,
            0x8000,
            2048,
            VRING_DESC_F_WRITE | VRING_DESC_F_INDIRECT,
            0,
        );
        post(&mut mem, 4, 5);
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Invalid
        );

        // A good buffer afterwards still works.
        set_desc(&mut mem, 6, 0x8000, 2048, VRING_DESC_F_WRITE, 0);
        post(&mut mem, 5, 6);
        assert!(matches!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Delivered { .. }
        ));
    }

    #[test]
    fn avail_index_running_ahead_of_queue_size_is_invalid() {
        let (mut mem, mut q) = setup();
        mem.write_u16(AVAIL + 2, NUM as u16 + 1).unwrap();
        assert_eq!(
            rx_deliver(&mut mem, &mut q, &frame(60)).unwrap(),
            RxDelivery::Invalid
        );
        assert_eq!(q.last_avail, 0);
    }

    #[test]
    fn interrupt_suppression_flag_is_honoured() {
        let (mut mem, mut q) = setup();
        set_desc(&mut mem, 0, 0x8000, 2048, VRING_DESC_F_WRITE, 0);
        post(&mut mem, 0, 0);
        mem.write_u16(AVAIL, VRING_AVAIL_F_NO_INTERRUPT).unwrap();
        let r = rx_deliver(&mut mem, &mut q, &frame(60)).unwrap();
        assert!(matches!(
            r,
            RxDelivery::Delivered {
                interrupt: false,
                ..
            }
        ));
    }

    #[test]
    fn maximum_frame_fits_a_64k_buffer() {
        let (mut mem, mut q) = setup();
        let f = frame(65535);
        set_desc(&mut mem, 0, 0x10000, 65536 + 16, VRING_DESC_F_WRITE, 0);
        post(&mut mem, 0, 0);
        assert!(matches!(
            rx_deliver(&mut mem, &mut q, &f).unwrap(),
            RxDelivery::Delivered { written: 65547, .. }
        ));
    }
}
