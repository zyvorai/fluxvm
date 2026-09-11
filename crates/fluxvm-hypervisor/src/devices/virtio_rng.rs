// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Firecracker-style virtio-rng / entropy over MMIO.

use crate::devices::virtio_mmio::VirtioState;
use crate::error::Result;
use crate::memory::GuestMemory;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

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

fn fill_random(buf: &mut [u8]) {
    #[cfg(target_os = "linux")]
    {
        let _ = unsafe {
            libc::getrandom(
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17).wrapping_add(0x5a);
        }
    }
}

pub fn handle_notify(mem: &mut GuestMemory, st: &mut VirtioState, _qsel: u32) -> Result<u32> {
    let q = &mut st.queues[0];
    if q.ready == 0 || q.num == 0 {
        return Ok(0);
    }
    let mut n = 0u32;
    loop {
        let avail_idx = mem.read_u16(q.avail + 2)?;
        if q.last_avail == avail_idx {
            break;
        }
        let slot = (q.last_avail as u32) % q.num;
        let head = mem.read_u16(q.avail + 4 + slot as u64 * 2)?;
        let mut idx = head;
        let mut written = 0u32;
        for _ in 0..16 {
            let mut raw = [0u8; 16];
            mem.read_at(q.desc + idx as u64 * 16, &mut raw)?;
            let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
            let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
            if flags & VRING_DESC_F_WRITE != 0 && len > 0 {
                let mut buf = vec![0u8; len as usize];
                fill_random(&mut buf);
                mem.write_at(addr, &buf)?;
                written = written.saturating_add(len);
            }
            if flags & VRING_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }
        used_push(mem, q.used, q.num, head, written)?;
        q.last_avail = q.last_avail.wrapping_add(1);
        n += 1;
        if n > 64 {
            break;
        }
    }
    Ok(n)
}
