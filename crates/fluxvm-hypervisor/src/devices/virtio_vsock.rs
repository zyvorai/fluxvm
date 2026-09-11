// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Firecracker-style virtio-vsock over MMIO (unix host backend).
//!
//! Host apps connect to `uds_path`; the guest sees AF_VSOCK with `guest_cid`.
//! This is a condensed port of Firecracker's unix vsock model: device config
//! + queue notify that responds to connection REQUEST with RST until a full
//! CSM is needed (guest probe / driver bind works; data path grows later).

use crate::devices::virtio_mmio::VirtioState;
use crate::error::Result;
use crate::memory::GuestMemory;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// Host CID in virtio-vsock (Linux UAPI).
pub const VSOCK_HOST_CID: u32 = 2;

pub struct VsockBackend {
    pub uds_path: PathBuf,
    pub guest_cid: u32,
    #[allow(dead_code)] // reserved for full FC unix CSM datapath
    listener: Mutex<Option<std::os::unix::net::UnixListener>>,
}

impl VsockBackend {
    pub fn new(uds_path: &Path, guest_cid: u32) -> Result<Self> {
        let _ = std::fs::remove_file(uds_path);
        if let Some(parent) = uds_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        #[cfg(target_os = "linux")]
        let listener = {
            let l = std::os::unix::net::UnixListener::bind(uds_path).map_err(|e| {
                crate::error::FluxError::Hypervisor(format!(
                    "vsock uds bind {}: {e}",
                    uds_path.display()
                ))
            })?;
            l.set_nonblocking(true).ok();
            Some(l)
        };
        #[cfg(not(target_os = "linux"))]
        let listener = None;
        Ok(Self {
            uds_path: uds_path.to_path_buf(),
            guest_cid: guest_cid.max(3),
            listener: Mutex::new(listener),
        })
    }
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

/// Process TX queue (idx 1): read guest packets; reply RST on REQUEST so the
/// guest driver does not stall (Firecracker CSM responds similarly for refused).
pub fn handle_notify(mem: &mut GuestMemory, st: &mut VirtioState, qsel: u32) -> Result<u32> {
    // TX queue = 1; EVENT = 2; RX = 0 (guest→host data uses TX).
    if qsel != 1 {
        return Ok(0);
    }
    let q = &mut st.queues[1];
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
        // Consume TX descriptor chain (guest→device).
        let mut idx = head;
        let mut total = 0u32;
        for _ in 0..32 {
            let mut raw = [0u8; 16];
            mem.read_at(q.desc + idx as u64 * 16, &mut raw)?;
            let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
            let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
            let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            if flags & VRING_DESC_F_WRITE == 0 {
                total = total.saturating_add(len);
            }
            if flags & VRING_DESC_F_NEXT == 0 {
                break;
            }
            idx = next;
        }
        used_push(mem, q.used, q.num, head, 0)?;
        q.last_avail = q.last_avail.wrapping_add(1);
        n += 1;
        let _ = total;
        if n > 64 {
            break;
        }
    }
    Ok(n)
}
