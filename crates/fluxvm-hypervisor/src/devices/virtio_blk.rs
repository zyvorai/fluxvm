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

// Bound bounce-buffer memory independently of guest descriptor lengths.
const IO_CHUNK_SIZE: usize = 1024 * 1024;
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
        let mut file = if read_only {
            OpenOptions::new().read(true).open(path)
        } else {
            OpenOptions::new().read(true).write(true).open(path)
        }
        .map_err(|e| FluxError::Hypervisor(format!("open block image {}: {e}", path.display())))?;
        let len = file
            .metadata()
            .map_err(|e| FluxError::Hypervisor(format!("stat block image: {e}")))?
            .len();
        // The in-tree backend maps guest sectors directly to host offsets.
        // Interpreting a qcow2 header as a raw disk can corrupt the image.
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(FluxError::Io)?;
        if magic == *b"QFI\xfb" {
            return Err(FluxError::Unsupported(format!(
                "qcow2 image {} requires conversion to raw before using the in-tree KVM backend",
                path.display()
            )));
        }
        if magic == *b"KDMV" || magic == *b"vhdx" {
            return Err(FluxError::Unsupported(format!(
                "image {} contains a VMDK/VHDX header, not raw sectors",
                path.display()
            )));
        }
        if len >= SECTOR_SIZE {
            file.seek(SeekFrom::End(-(SECTOR_SIZE as i64)))
                .map_err(FluxError::Io)?;
            let mut footer = [0u8; 8];
            file.read_exact(&mut footer).map_err(FluxError::Io)?;
            if footer == *b"conectix" {
                return Err(FluxError::Unsupported(format!(
                    "image {} contains a VHD footer, not raw sectors",
                    path.display()
                )));
            }
        }
        file.seek(SeekFrom::Start(0)).map_err(FluxError::Io)?;
        if len == 0 || len % SECTOR_SIZE != 0 {
            return Err(FluxError::Unsupported(format!(
                "raw disk {} must have nonzero, 512-byte-aligned capacity (got {len} bytes)",
                path.display()
            )));
        }
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

fn walk_chain(mem: &GuestMemory, desc_base: u64, head: u16, qnum: u32) -> Result<DescChain> {
    let mut parts = Vec::new();
    let mut idx = head;
    let mut seen = [0u16; 64];
    for hop in 0..qnum.min(64) as usize {
        if u32::from(idx) >= qnum || seen[..hop].contains(&idx) {
            return Err(FluxError::Device {
                device: "virtio-blk",
                msg: "descriptor index out of range or chain cycle".into(),
            });
        }
        seen[hop] = idx;
        let mut raw = [0u8; 16];
        let addr = desc_base
            .checked_add(u64::from(idx) * 16)
            .ok_or_else(|| FluxError::Memory("descriptor GPA overflow".into()))?;
        mem.read_at(addr, &mut raw)?;
        let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        if flags & 4 != 0 {
            return Err(FluxError::Unsupported(
                "virtio-blk indirect descriptors are not supported".into(),
            ));
        }
        let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        parts.push((addr, len, flags & VRING_DESC_F_WRITE != 0));
        if flags & VRING_DESC_F_NEXT == 0 {
            return Ok(DescChain { head, parts });
        }
        idx = next;
    }
    Err(FluxError::Device {
        device: "virtio-blk",
        msg: "unterminated descriptor chain".into(),
    })
}

fn valid_io_request(
    mem: &GuestMemory,
    backend: &BlockBackend,
    data_parts: &[(u64, u32, bool)],
    sector: u64,
    device_writes: bool,
) -> bool {
    let mut total = 0u64;
    for &(gpa, len, writable) in data_parts {
        if writable != device_writes
            || !matches!(gpa.checked_add(u64::from(len)), Some(end) if end <= mem.len() as u64)
        {
            return false;
        }
        let Some(next) = total.checked_add(u64::from(len)) else {
            return false;
        };
        total = next;
    }
    if !total.is_multiple_of(SECTOR_SIZE) || total > u64::from(u32::MAX - 1) {
        return false;
    }
    matches!(
        (sector.checked_mul(SECTOR_SIZE).and_then(|start| start.checked_add(total)),
         backend.capacity_sectors.checked_mul(SECTOR_SIZE)),
        (Some(end), Some(capacity)) if end <= capacity
    )
}

fn process_request(
    mem: &mut GuestMemory,
    backend: &BlockBackend,
    chain: &DescChain,
    scratch: &mut Vec<u8>,
) -> Result<u32> {
    if chain.parts.len() < 2 {
        return Ok(0);
    }
    // Header is first descriptor (device-read / guest→device).
    let (hdr_gpa, hdr_len, hdr_w) = chain.parts[0];
    if hdr_len < 16 || hdr_w {
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

    if (req_type == VIRTIO_BLK_T_IN || req_type == VIRTIO_BLK_T_OUT)
        && !valid_io_request(
            mem,
            backend,
            data_parts,
            sector,
            req_type == VIRTIO_BLK_T_IN,
        )
    {
        mem.write_at(status_gpa, &[VIRTIO_BLK_S_IOERR])?;
        return Ok(1);
    }

    match req_type {
        VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT => {
            let reading = req_type == VIRTIO_BLK_T_IN;
            if !reading && backend.read_only {
                status = VIRTIO_BLK_S_IOERR;
            } else {
                // One seek per request and no guest-sized heap allocation.
                // Keep a bounce buffer: guest RAM may change while vCPUs run.
                let chunk = data_parts
                    .iter()
                    .map(|(_, len, _)| *len as usize)
                    .max()
                    .unwrap_or(0)
                    .min(IO_CHUNK_SIZE);
                if chunk > scratch.len() {
                    scratch.reserve_exact(chunk - scratch.len());
                    scratch.resize(chunk, 0);
                }
                let mut file = backend.file.lock().unwrap();
                if file.seek(SeekFrom::Start(sector * SECTOR_SIZE)).is_err() {
                    status = VIRTIO_BLK_S_IOERR;
                } else {
                    'parts: for &(gpa, len, _) in data_parts {
                        let mut done = 0usize;
                        while done < len as usize {
                            let n = (len as usize - done).min(scratch.len());
                            let buf = &mut scratch[..n];
                            let addr = gpa + done as u64;
                            if reading {
                                if file.read_exact(buf).is_err() {
                                    status = VIRTIO_BLK_S_IOERR;
                                    break 'parts;
                                }
                                mem.write_at(addr, buf)?;
                                bytes_written_to_guest += n as u32;
                            } else {
                                mem.read_at(addr, buf)?;
                                if file.write_all(buf).is_err() {
                                    status = VIRTIO_BLK_S_IOERR;
                                    break 'parts;
                                }
                            }
                            done += n;
                        }
                    }
                }
            }
        }
        VIRTIO_BLK_T_FLUSH => {
            let file = backend.file.lock().unwrap();
            if file.sync_data().is_err() {
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
    limiter: Option<&crate::devices::rate_limiter::RateLimiter>,
) -> Result<u32> {
    let q = &mut st.queues[0];
    if q.ready == 0 || q.num == 0 {
        return Ok(0);
    }
    let mut n = 0u32;
    let mut scratch = Vec::new();
    loop {
        let avail_idx = mem.read_u16(q.avail + 2)?;
        if q.last_avail == avail_idx {
            break;
        }
        let slot = (q.last_avail as u32) % q.num;
        let head = mem.read_u16(q.avail + 4 + slot as u64 * 2)?;
        let chain = walk_chain(mem, q.desc, head, q.num)?;
        // Rough size estimate for rate limiting.
        let bytes: u64 = chain.parts.iter().map(|(_, l, _)| *l as u64).sum();
        if let Some(lim) = limiter {
            if !lim.consume(bytes) {
                break;
            }
        }
        let written = process_request(mem, backend, &chain, &mut scratch).unwrap_or(1);
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

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn process_request(
        mem: &mut GuestMemory,
        backend: &BlockBackend,
        chain: &DescChain,
    ) -> Result<u32> {
        super::process_request(mem, backend, chain, &mut Vec::new())
    }

    #[test]
    fn open_raw_image_reports_sectors() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        f.flush().unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        assert_eq!(backend.capacity_sectors, 8);
    }

    #[test]
    fn rejects_qcow2_before_exposing_it_as_raw_sectors() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"QFI\xfb").unwrap();
        f.as_file().set_len(4096).unwrap();
        let err = BlockBackend::open(f.path(), false).err().unwrap();
        assert!(format!("{err}").contains("qcow2"));
    }

    #[test]
    fn rejects_vmdk_before_exposing_it_as_raw_sectors() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"KDMV").unwrap();
        f.as_file().set_len(4096).unwrap();
        let err = BlockBackend::open(f.path(), false).err().unwrap();
        assert!(format!("{err}").contains("VMDK"));
    }

    #[test]
    fn rejects_vhd_footer_before_exposing_it_as_raw_sectors() {
        let mut f = NamedTempFile::new().unwrap();
        let mut bytes = vec![0u8; 4096];
        bytes[3584..3592].copy_from_slice(b"conectix");
        f.write_all(&bytes).unwrap();
        let err = BlockBackend::open(f.path(), false).err().unwrap();
        assert!(format!("{err}").contains("VHD footer"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_write_past_end_without_growing_disk() {
        let f = NamedTempFile::new().unwrap();
        f.as_file().set_len(4096).unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        let mut mem = GuestMemory::allocate(4096).unwrap();
        let mut header = [0u8; 16];
        header[..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        header[8..].copy_from_slice(&7u64.to_le_bytes());
        mem.write_at(0, &header).unwrap();
        let chain = DescChain {
            head: 0,
            parts: vec![(0, 16, false), (128, 1024, false), (2048, 1, true)],
        };
        assert_eq!(process_request(&mut mem, &backend, &chain).unwrap(), 1);
        assert_eq!(mem.as_slice()[2048], VIRTIO_BLK_S_IOERR);
        assert_eq!(f.as_file().metadata().unwrap().len(), 4096);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_late_invalid_descriptor_without_partial_disk_write() {
        let f = NamedTempFile::new().unwrap();
        f.as_file().set_len(4096).unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        let mut mem = GuestMemory::allocate(4096).unwrap();
        let mut header = [0u8; 16];
        header[..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        mem.write_at(0, &header).unwrap();
        mem.write_at(128, &[0xa5; 512]).unwrap();
        let chain = DescChain {
            head: 0,
            parts: vec![
                (0, 16, false),
                (128, 512, false),
                (1024, 512, true), // Wrong direction after valid data.
                (2048, 1, true),
            ],
        };
        assert_eq!(process_request(&mut mem, &backend, &chain).unwrap(), 1);
        assert_eq!(mem.as_slice()[2048], VIRTIO_BLK_S_IOERR);
        let mut bytes = [0u8; 512];
        File::open(f.path())
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        assert_eq!(bytes, [0u8; 512]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_cyclic_descriptor_chain() {
        let mut mem = GuestMemory::allocate(4096).unwrap();
        let mut desc = [0u8; 16];
        desc[12..14].copy_from_slice(&VRING_DESC_F_NEXT.to_le_bytes());
        mem.write_at(256, &desc).unwrap();
        let err = walk_chain(&mem, 256, 0, 1).err().unwrap();
        assert!(format!("{err}").contains("chain"));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn chunked_io_roundtrip_across_descriptors() {
        let f = NamedTempFile::new().unwrap();
        let size = IO_CHUNK_SIZE * 2 + 512;
        f.as_file().set_len((size + 512) as u64).unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        let mut mem = GuestMemory::allocate(size + 8192 - 512).unwrap();
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        mem.write_at(4096, &data).unwrap();
        let chain = DescChain {
            head: 0,
            // Deliberately split on a non-sector boundary.
            parts: vec![
                (0, 16, false),
                (4096, 513, false),
                (4609, (size - 513) as u32, false),
                (128, 1, true),
            ],
        };
        let mut header = [0u8; 16];
        header[..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        header[8..].copy_from_slice(&1u64.to_le_bytes());
        mem.write_at(0, &header).unwrap();
        let mut scratch = Vec::new();
        assert_eq!(
            super::process_request(&mut mem, &backend, &chain, &mut scratch).unwrap(),
            1
        );
        assert_eq!(scratch.len(), IO_CHUNK_SIZE);
        assert!(scratch.capacity() <= IO_CHUNK_SIZE);
        let scratch_ptr = scratch.as_ptr();
        assert_eq!(mem.as_slice()[128], VIRTIO_BLK_S_OK);
        mem.as_slice_mut()[4096..4096 + size].fill(0);
        header[..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
        mem.write_at(0, &header).unwrap();
        let read_chain = DescChain {
            head: 0,
            parts: chain
                .parts
                .iter()
                .enumerate()
                .map(|(i, &(gpa, len, w))| (gpa, len, if i == 1 || i == 2 { true } else { w }))
                .collect(),
        };
        assert_eq!(
            super::process_request(&mut mem, &backend, &read_chain, &mut scratch).unwrap(),
            size as u32 + 1
        );
        assert_eq!(scratch.as_ptr(), scratch_ptr);
        assert_eq!(&mem.as_slice()[4096..4096 + size], data.as_slice());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn truncated_backing_file_reports_io_error() {
        let f = NamedTempFile::new().unwrap();
        f.as_file().set_len(4096).unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        f.as_file().set_len(0).unwrap();
        let mut mem = GuestMemory::allocate(4096).unwrap();
        let chain = DescChain {
            head: 0,
            parts: vec![(0, 16, false), (512, 512, true), (128, 1, true)],
        };
        assert_eq!(process_request(&mut mem, &backend, &chain).unwrap(), 1);
        assert_eq!(mem.as_slice()[128], VIRTIO_BLK_S_IOERR);
    }

    /// Host-only microbenchmark; excludes VM boot, KVM and durability flushes.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn bench_block_bounce_buffer() {
        let size = 16 * 1024 * 1024;
        let f = NamedTempFile::new().unwrap();
        f.as_file().set_len(size as u64).unwrap();
        let backend = BlockBackend::open(f.path(), false).unwrap();
        let mut mem = GuestMemory::allocate(size + 4096).unwrap();
        mem.as_slice_mut()[4096..].fill(0xa5);
        let chain = DescChain {
            head: 0,
            parts: vec![(0, 16, false), (4096, size as u32, true), (128, 1, true)],
        };
        let mut scratch = Vec::new();
        for _ in 0..4 {
            super::process_request(&mut mem, &backend, &chain, &mut scratch).unwrap();
        }
        let start = std::time::Instant::now();
        for _ in 0..64 {
            super::process_request(&mut mem, &backend, &chain, &mut scratch).unwrap();
        }
        eprintln!(
            "block-read MiB/s={:.1}",
            1024.0 / start.elapsed().as_secs_f64()
        );
    }
}
