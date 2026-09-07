// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Virtio-blk (legacy requestq) over virtio-mmio for the in-tree KVM engine.

use crate::devices::virtio_mmio::VirtioState;
use crate::error::{FluxError, Result};
use crate::memory::GuestMemory;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const SECTOR_SIZE: u64 = 512;
pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

#[derive(Debug, Clone)]
pub struct VirtioBlockConfig {
    pub path: PathBuf,
    pub read_only: bool,
}

pub struct BlockBackend {
    pub file: Mutex<File>,
    pub capacity_sectors: u64,
    pub read_only: bool,
    pub path: PathBuf,
}

impl BlockBackend {
    pub fn open(path: &Path, read_only: bool) -> Result<Arc<Self>> {
        let file = if read_only {
            OpenOptions::new().read(true).open(path)
        } else {
            OpenOptions::new().read(true).write(true).open(path)
        }
        .map_err(|e| FluxError::Hypervisor(format!("open block image {}: {e}", path.display())))?;
        let len = file
            .metadata()
            .map_err(|e| FluxError::Hypervisor(format!("stat block image: {e}")))?
            .len();
        let capacity_sectors = len.div_ceil(SECTOR_SIZE);
        Ok(Arc::new(Self {
            file: Mutex::new(file),
            capacity_sectors,
            read_only,
            path: path.to_path_buf(),
        }))
    }
}

/// Size of the image in bytes (helper for probes / tests).
pub fn open_image(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)?.len())
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

struct DescChain {
    head: u16,
    /// (gpa, len, device_write)
    parts: Vec<(u64, u32, bool)>,
}

fn walk_chain(mem: &GuestMemory, desc_base: u64, head: u16) -> Result<DescChain> {
    let mut parts = Vec::new();
    let mut idx = head;
    for _ in 0..64 {
        let mut raw = [0u8; 16];
        mem.read_at(desc_base + idx as u64 * 16, &mut raw)?;
        let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        parts.push((addr, len, flags & VRING_DESC_F_WRITE != 0));
        if flags & VRING_DESC_F_NEXT == 0 {
            break;
        }
        idx = next;
    }
    Ok(DescChain { head, parts })
}

fn process_request(mem: &mut GuestMemory, backend: &BlockBackend, chain: &DescChain) -> Result<u32> {
    if chain.parts.len() < 2 {
        return Ok(0);
    }
    // Header is first descriptor (device-read / guest→device).
    let (hdr_gpa, hdr_len, _) = chain.parts[0];
    if hdr_len < 16 {
        return Ok(0);
    }
    let mut hdr = [0u8; 16];
    mem.read_at(hdr_gpa, &mut hdr)?;
    let req_type = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let sector = u64::from_le_bytes(hdr[8..16].try_into().unwrap());

    // Status is last descriptor (device-write).
    let (status_gpa, status_len, status_w) = *chain.parts.last().unwrap();
    if !status_w || status_len < 1 {
        return Ok(0);
    }

    let data_parts = &chain.parts[1..chain.parts.len() - 1];
    let mut status = VIRTIO_BLK_S_OK;
    let mut bytes_written_to_guest = 0u32;

    match req_type {
        VIRTIO_BLK_T_IN => {
            let mut offset = sector * SECTOR_SIZE;
            let mut file = backend.file.lock().unwrap();
            for &(gpa, len, device_write) in data_parts {
                if !device_write {
                    status = VIRTIO_BLK_S_IOERR;
                    break;
                }
                let mut buf = vec![0u8; len as usize];
                if file.seek(SeekFrom::Start(offset)).is_err()
                    || file.read_exact(&mut buf).is_err()
                {
                    // Short read at EOF: zero-fill remainder.
                    let _ = file.seek(SeekFrom::Start(offset));
                    let n = file.read(&mut buf).unwrap_or(0);
                    buf[n..].fill(0);
                }
                mem.write_at(gpa, &buf)?;
                offset += len as u64;
                bytes_written_to_guest += len;
            }
        }
        VIRTIO_BLK_T_OUT => {
            if backend.read_only {
                status = VIRTIO_BLK_S_IOERR;
            } else {
                let mut offset = sector * SECTOR_SIZE;
                let mut file = backend.file.lock().unwrap();
                for &(gpa, len, device_write) in data_parts {
                    if device_write {
                        status = VIRTIO_BLK_S_IOERR;
                        break;
                    }
                    let mut buf = vec![0u8; len as usize];
                    mem.read_at(gpa, &mut buf)?;
                    if file.seek(SeekFrom::Start(offset)).is_err() || file.write_all(&buf).is_err()
                    {
                        status = VIRTIO_BLK_S_IOERR;
                        break;
                    }
                    offset += len as u64;
                }
            }
        }
        VIRTIO_BLK_T_FLUSH => {
            let mut file = backend.file.lock().unwrap();
            if file.flush().is_err() {
                status = VIRTIO_BLK_S_IOERR;
            }
        }
        VIRTIO_BLK_T_GET_ID => {
            let id = b"fluxvm-blk0\0";
            if let Some(&(gpa, len, device_write)) = data_parts.first() {
                if device_write {
                    let n = (id.len()).min(len as usize);
                    mem.write_at(gpa, &id[..n])?;
                    bytes_written_to_guest = n as u32;
                }
            }
        }
        _ => status = VIRTIO_BLK_S_UNSUPP,
    }

    mem.write_at(status_gpa, &[status])?;
    // used.len ≈ data written to guest + status
    Ok(bytes_written_to_guest.saturating_add(1))
}

pub fn handle_notify(
    mem: &mut GuestMemory,
    st: &mut VirtioState,
    backend: &BlockBackend,
    _qsel: u32,
) -> Result<u32> {
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
        let chain = walk_chain(mem, q.desc, head)?;
        let written = process_request(mem, backend, &chain).unwrap_or(1);
        used_push(mem, q.used, q.num, chain.head, written)?;
        q.last_avail = q.last_avail.wrapping_add(1);
        n += 1;
        if n > 64 {
            break;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn open_raw_image_reports_sectors() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        f.flush().unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        assert_eq!(backend.capacity_sectors, 8);
    }
}
