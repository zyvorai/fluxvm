// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Firecracker-style virtio-balloon over MMIO.
//! Inflate: `madvise(MADV_DONTNEED)` guest pages; deflate: touch pages back.

use crate::devices::virtio_mmio::VirtioState;
use crate::error::Result;
use crate::memory::GuestMemory;

const VRING_DESC_F_NEXT: u16 = 1;
const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;

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

fn process_pfns(mem: &mut GuestMemory, q_idx: usize, st: &mut VirtioState, inflate: bool) -> Result<u32> {
    let q = &mut st.queues[q_idx];
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
        for _ in 0..32 {
            let mut raw = [0u8; 16];
            mem.read_at(q.desc + idx as u64 * 16, &mut raw)?;
            let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
            let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
            let count = (len as usize) / 4;
            for i in 0..count {
                let mut pfnb = [0u8; 4];
                mem.read_at(addr + (i as u64) * 4, &mut pfnb)?;
                let pfn = u32::from_le_bytes(pfnb);
                let gpa = (pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT;
                if inflate {
                    mem.advise_dontneed(gpa, 4096);
                    st.balloon_actual = st.balloon_actual.saturating_add(1);
                } else {
                    mem.touch_page(gpa);
                    st.balloon_actual = st.balloon_actual.saturating_sub(1);
                }
            }
            if flags & VRING_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }
        used_push(mem, q.used, q.num, head, 0)?;
        q.last_avail = q.last_avail.wrapping_add(1);
        n += 1;
        if n > 64 {
            break;
        }
    }
    Ok(n)
}

pub fn handle_notify(mem: &mut GuestMemory, st: &mut VirtioState, qsel: u32) -> Result<u32> {
    match qsel {
        0 => process_pfns(mem, 0, st, true),  // inflate
        1 => process_pfns(mem, 1, st, false), // deflate
        _ => Ok(0),
    }
}
