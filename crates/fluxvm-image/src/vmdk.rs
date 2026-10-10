// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Native reader for sparse and stream-optimized VMDK extents. All offsets in the
//! format are little-endian sector numbers. Unsupported variants use qemu-img.

use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

const SECTOR: u64 = 512;
const MAX_GRAIN: u64 = 16 * 1024 * 1024;

pub enum ConvertResult {
    Converted,
    Unsupported,
}

pub fn is_sparse_vmdk(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    Ok(f.read(&mut magic)? == 4 && magic == *b"KDMV")
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn sector_offset(sector: u64, size: u64, file_len: u64) -> Result<u64> {
    let offset = sector
        .checked_mul(SECTOR)
        .context("VMDK sector offset overflow")?;
    if offset.checked_add(size).is_none_or(|end| end > file_len) {
        bail!("VMDK metadata or grain exceeds source file");
    }
    Ok(offset)
}

fn read_at<const N: usize>(f: &mut File, offset: u64) -> Result<[u8; N]> {
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = [0; N];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn descriptor_property<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().trim_matches('"'))
    })
}

fn read_cid(path: &Path) -> Result<Option<String>> {
    let mut input = File::open(path)?;
    let file_len = input.metadata()?.len();
    if file_len < 4 {
        bail!("truncated VMDK parent");
    }
    let magic = read_at::<4>(&mut input, 0)?;
    let descriptor = if magic == *b"KDMV" {
        let header = read_at::<512>(&mut input, 0)?;
        let size = u64le(&header, 36)
            .checked_mul(SECTOR)
            .context("parent descriptor overflow")?;
        if size == 0 || size > 1024 * 1024 {
            return Ok(None);
        }
        let offset = sector_offset(u64le(&header, 28), size, file_len)?;
        let mut data = vec![0; size as usize];
        input.seek(SeekFrom::Start(offset))?;
        input.read_exact(&mut data)?;
        data
    } else {
        if file_len > 1024 * 1024 {
            return Ok(None);
        }
        fs::read(path)?
    };
    let text = String::from_utf8_lossy(&descriptor);
    Ok(descriptor_property(text.trim_end_matches('\0'), "CID").map(str::to_owned))
}

pub fn convert_sparse_to_raw(source: &Path, target: &Path) -> Result<ConvertResult> {
    convert_sparse_inner(source, target, None, 0)
}

/// `extent_sectors` is supplied only by a validated external descriptor. A
/// split sparse extent does not contain an embedded descriptor of its own.
pub fn convert_sparse_extent_to_raw(
    source: &Path,
    target: &Path,
    extent_sectors: Option<u64>,
) -> Result<ConvertResult> {
    convert_sparse_inner(source, target, extent_sectors, 0)
}

fn convert_sparse_inner(
    source: &Path,
    target: &Path,
    extent_sectors: Option<u64>,
    depth: usize,
) -> Result<ConvertResult> {
    if depth >= 8 {
        return Ok(ConvertResult::Unsupported);
    }
    let mut input = File::open(source)?;
    let file_len = input.metadata()?.len();
    if file_len < SECTOR {
        bail!("truncated VMDK header");
    }
    let header = read_at::<512>(&mut input, 0)?;
    if &header[..4] != b"KDMV" {
        return Ok(ConvertResult::Unsupported);
    }
    let version = u32le(&header, 4);
    let flags = u32le(&header, 8);
    let capacity = u64le(&header, 12);
    let grain_sectors = u64le(&header, 20);
    let descriptor_offset = u64le(&header, 28);
    let descriptor_sectors = u64le(&header, 36);
    let entries_per_table = u32le(&header, 44) as u64;
    let redundant_directory_sector = u64le(&header, 48);
    let mut directory_sector = u64le(&header, 56);
    let compression = u16::from_le_bytes(header[77..79].try_into().unwrap());

    let stream = compression == 1 && flags & 0x1_0000 != 0;
    if !matches!(version, 1..=3)
        || flags & !0x3_0007 != 0
        || (!stream && (compression != 0 || flags & 0x3_0000 != 0))
        || (stream && extent_sectors.is_some())
        || descriptor_sectors == 0 && extent_sectors.is_none()
    {
        return Ok(ConvertResult::Unsupported);
    }
    if stream && directory_sector == u64::MAX {
        if file_len < 2 * SECTOR {
            bail!("truncated stream-optimized VMDK footer");
        }
        let footer = read_at::<512>(&mut input, file_len - 2 * SECTOR)?;
        if &footer[..4] != b"KDMV" || u64le(&footer, 12) != capacity {
            bail!("invalid stream-optimized VMDK footer");
        }
        directory_sector = u64le(&footer, 56);
    }
    let directory_sector = if flags & 2 != 0 {
        redundant_directory_sector
    } else {
        directory_sector
    };
    if capacity == 0
        || grain_sectors == 0
        || !grain_sectors.is_power_of_two()
        || entries_per_table == 0
        || entries_per_table > 1_000_000
        || directory_sector == 0
    {
        bail!("invalid VMDK sparse geometry");
    }
    let grain_bytes = grain_sectors
        .checked_mul(SECTOR)
        .context("VMDK grain size overflow")?;
    if grain_bytes > MAX_GRAIN {
        return Ok(ConvertResult::Unsupported);
    }
    let mut parent: Option<PathBuf> = None;
    if let Some(expected) = extent_sectors {
        if capacity != expected || descriptor_sectors != 0 {
            return Ok(ConvertResult::Unsupported);
        }
    } else {
        let desc_len = descriptor_sectors
            .checked_mul(SECTOR)
            .context("VMDK descriptor overflow")?;
        if desc_len > 1024 * 1024 {
            return Ok(ConvertResult::Unsupported);
        }
        let offset = sector_offset(descriptor_offset, desc_len, file_len)?;
        let mut desc = vec![0; desc_len as usize];
        input.seek(SeekFrom::Start(offset))?;
        input.read_exact(&mut desc)?;
        let desc = String::from_utf8_lossy(&desc);
        let desc = desc.trim_end_matches('\0');
        let parent_cid = descriptor_property(desc, "parentCID");
        let expected_type = if stream {
            "createType=\"streamOptimized\""
        } else {
            "createType=\"monolithicSparse\""
        };
        if !desc.lines().any(|line| line.trim() == expected_type) || parent_cid.is_none() {
            return Ok(ConvertResult::Unsupported);
        }
        if !parent_cid.unwrap().eq_ignore_ascii_case("ffffffff") {
            let hint = descriptor_property(desc, "parentFileNameHint")
                .context("VMDK delta is missing parentFileNameHint")?;
            let relative = Path::new(hint);
            if relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            {
                bail!("VMDK parent must be in the descriptor directory");
            }
            let directory = source
                .parent()
                .context("VMDK has no directory")?
                .canonicalize()?;
            let path = directory.join(relative).canonicalize()?;
            if !path.starts_with(&directory) || path == source.canonicalize()? {
                bail!("invalid VMDK parent path");
            }
            let actual = read_cid(&path)?;
            if !actual
                .as_deref()
                .is_some_and(|cid| cid.eq_ignore_ascii_case(parent_cid.unwrap()))
            {
                bail!("VMDK parent CID mismatch");
            }
            parent = Some(path);
        }
    }

    let virtual_bytes = capacity
        .checked_mul(SECTOR)
        .context("VMDK capacity overflow")?;
    if virtual_bytes > 1u64 << 56 {
        return Ok(ConvertResult::Unsupported);
    }
    let total_grains = capacity.div_ceil(grain_sectors);
    let directory_entries = total_grains.div_ceil(entries_per_table);
    let directory_bytes = directory_entries
        .checked_mul(4)
        .context("VMDK directory overflow")?;
    let table_bytes = entries_per_table
        .checked_mul(4)
        .context("VMDK table overflow")?;
    if directory_entries > 16_000_000 || table_bytes > 4 * 1024 * 1024 {
        return Ok(ConvertResult::Unsupported);
    }
    let directory_offset = sector_offset(directory_sector, directory_bytes, file_len)?;
    let mut directory = vec![0u8; directory_bytes as usize];
    input.seek(SeekFrom::Start(directory_offset))?;
    input.read_exact(&mut directory)?;

    let temp = target.with_extension(format!("fluxvm-{}.partial", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        if let Some(parent) = &parent {
            let converted = if is_sparse_vmdk(parent)? {
                convert_sparse_inner(parent, &temp, None, depth + 1)?
            } else {
                crate::vmdk_descriptor::convert_descriptor_to_raw(parent, &temp)?
            };
            if !matches!(converted, ConvertResult::Converted) {
                bail!("unsupported VMDK parent format");
            }
            if fs::metadata(&temp)?.len() != virtual_bytes {
                bail!("VMDK parent and child capacities differ");
            }
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create(!temp.exists())
            .open(&temp)?;
        output.set_len(virtual_bytes)?;
        let mut grain = vec![0u8; grain_bytes as usize];
        let mut table = vec![0u8; table_bytes as usize];
        for dir_idx in 0..directory_entries {
            let table_sector = u32le(&directory, dir_idx as usize * 4) as u64;
            if table_sector == 0 {
                continue;
            }
            if flags & 4 != 0 && table_sector == 1 {
                if parent.is_some() {
                    let start = dir_idx * entries_per_table * grain_bytes;
                    let end = (start + entries_per_table * grain_bytes).min(virtual_bytes);
                    grain.fill(0);
                    output.seek(SeekFrom::Start(start))?;
                    let mut remaining = end - start;
                    while remaining != 0 {
                        let len = remaining.min(grain_bytes) as usize;
                        output.write_all(&grain[..len])?;
                        remaining -= len as u64;
                    }
                }
                continue;
            }
            let table_offset = sector_offset(table_sector, table_bytes, file_len)?;
            input.seek(SeekFrom::Start(table_offset))?;
            input.read_exact(&mut table)?;
            for table_idx in 0..entries_per_table {
                let grain_idx = dir_idx * entries_per_table + table_idx;
                if grain_idx >= total_grains {
                    break;
                }
                let data_sector = u32le(&table, table_idx as usize * 4) as u64;
                if data_sector == 0 {
                    continue;
                }
                let guest_offset = grain_idx * grain_bytes;
                let len = (virtual_bytes - guest_offset).min(grain_bytes) as usize;
                if flags & 4 != 0 && data_sector == 1 {
                    if parent.is_some() {
                        output.seek(SeekFrom::Start(guest_offset))?;
                        grain[..len].fill(0);
                        output.write_all(&grain[..len])?;
                    }
                    continue;
                }
                if stream {
                    let marker_offset = sector_offset(data_sector, 12, file_len)?;
                    let marker = read_at::<12>(&mut input, marker_offset)?;
                    let lba = u64le(&marker, 0);
                    let compressed_len = u32le(&marker, 8) as u64;
                    if lba != grain_idx * grain_sectors
                        || compressed_len == 0
                        || compressed_len > 2 * MAX_GRAIN
                    {
                        bail!("invalid VMDK compressed grain marker");
                    }
                    sector_offset(data_sector, 12 + compressed_len, file_len)?;
                    let mut compressed = vec![0; compressed_len as usize];
                    input.seek(SeekFrom::Start(marker_offset + 12))?;
                    input.read_exact(&mut compressed)?;
                    let mut decoded = Vec::with_capacity(len);
                    ZlibDecoder::new(&compressed[..])
                        .take(grain_bytes + 1)
                        .read_to_end(&mut decoded)?;
                    if decoded.len() != len {
                        bail!("VMDK compressed grain size mismatch");
                    }
                    grain[..len].copy_from_slice(&decoded);
                } else {
                    let data_offset = sector_offset(data_sector, len as u64, file_len)?;
                    input.seek(SeekFrom::Start(data_offset))?;
                    input.read_exact(&mut grain[..len])?;
                }
                if parent.is_some() || grain[..len].iter().any(|&byte| byte != 0) {
                    output.seek(SeekFrom::Start(guest_offset))?;
                    output.write_all(&grain[..len])?;
                }
            }
        }
        output.sync_all()?;
        fs::rename(&temp, target).with_context(|| format!("publishing {}", target.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    Ok(ConvertResult::Converted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::ZlibEncoder};

    fn fixture(path: &Path, parent: bool) {
        let mut bytes = vec![0u8; 8 * 512];
        bytes[..4].copy_from_slice(b"KDMV");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..20].copy_from_slice(&8u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&2u64.to_le_bytes());
        bytes[28..36].copy_from_slice(&1u64.to_le_bytes());
        bytes[36..44].copy_from_slice(&1u64.to_le_bytes());
        bytes[44..48].copy_from_slice(&4u32.to_le_bytes());
        bytes[56..64].copy_from_slice(&2u64.to_le_bytes());
        let desc = if parent {
            "createType=\"monolithicSparse\"\nCID=22222222\nparentCID=11111111\nparentFileNameHint=\"base.vmdk\"\n"
        } else {
            "createType=\"monolithicSparse\"\nCID=11111111\nparentCID=ffffffff\n"
        };
        bytes[512..512 + desc.len()].copy_from_slice(desc.as_bytes());
        bytes[1024..1028].copy_from_slice(&3u32.to_le_bytes());
        bytes[1536..1540].copy_from_slice(&4u32.to_le_bytes());
        bytes[2048..3072].fill(0x5a);
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn converts_sparse_grain_and_preserves_holes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.vmdk");
        let dst = dir.path().join("base.raw");
        fixture(&src, false);
        assert!(matches!(
            convert_sparse_to_raw(&src, &dst).unwrap(),
            ConvertResult::Converted
        ));
        let raw = fs::read(dst).unwrap();
        assert_eq!(raw.len(), 4096);
        assert!(raw[..1024].iter().all(|&b| b == 0x5a));
        assert!(raw[1024..].iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn image_pipeline_uses_native_reader_without_qemu_img() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.vmdk");
        let dst = dir.path().join("base.raw");
        fixture(&src, false);
        let cfg = fluxvm_core::config::Config {
            qemu_img_binary: "/definitely/missing/qemu-img".into(),
            ..Default::default()
        };
        crate::convert_image(&cfg, &src, &dst, "raw").await.unwrap();
        assert_eq!(fs::metadata(dst).unwrap().len(), 4096);
    }

    #[test]
    fn delta_needs_backing_chain() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("delta.vmdk");
        fixture(&src, true);
        assert!(convert_sparse_to_raw(&src, &dir.path().join("out.raw")).is_err());
    }

    #[test]
    fn delta_inherits_parent_grains() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.vmdk");
        let delta = dir.path().join("delta.vmdk");
        let dst = dir.path().join("flattened.raw");
        fixture(&base, false);
        let mut parent_bytes = fs::read(&base).unwrap();
        parent_bytes[1540..1544].copy_from_slice(&6u32.to_le_bytes());
        parent_bytes[3072..4096].fill(0x44);
        fs::write(&base, parent_bytes).unwrap();
        fixture(&delta, true);
        let mut delta_bytes = fs::read(&delta).unwrap();
        delta_bytes[2048..3072].fill(0x99);
        fs::write(&delta, delta_bytes).unwrap();
        assert!(matches!(
            convert_sparse_to_raw(&delta, &dst).unwrap(),
            ConvertResult::Converted
        ));
        let raw = fs::read(dst).unwrap();
        assert!(raw[..1024].iter().all(|&b| b == 0x99));
        assert!(raw[1024..2048].iter().all(|&b| b == 0x44));
    }

    #[test]
    fn rejects_parent_cid_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.vmdk");
        let delta = dir.path().join("delta.vmdk");
        fixture(&base, false);
        fixture(&delta, true);
        let mut bytes = fs::read(&base).unwrap();
        bytes[512..1024].copy_from_slice(&[0u8; 512]);
        let desc = b"createType=\"monolithicSparse\"\nCID=deadbeef\nparentCID=ffffffff\n";
        bytes[512..512 + desc.len()].copy_from_slice(desc);
        fs::write(&base, bytes).unwrap();
        let dst = dir.path().join("out.raw");
        assert!(convert_sparse_to_raw(&delta, &dst).is_err());
        assert!(!dst.exists());
    }

    #[test]
    fn uses_redundant_directory_and_zeroed_grain_entries() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("base.vmdk");
        let dst = dir.path().join("base.raw");
        fixture(&src, false);
        let mut bytes = fs::read(&src).unwrap();
        bytes[8..12].copy_from_slice(&6u32.to_le_bytes());
        bytes[48..56].copy_from_slice(&6u64.to_le_bytes());
        bytes[6 * 512..6 * 512 + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[1536 + 4..1536 + 8].copy_from_slice(&1u32.to_le_bytes());
        fs::write(&src, bytes).unwrap();
        assert!(matches!(
            convert_sparse_to_raw(&src, &dst).unwrap(),
            ConvertResult::Converted
        ));
        let raw = fs::read(dst).unwrap();
        assert_eq!(&raw[..1024], &[0x5a; 1024]);
        assert!(raw[1024..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn converts_stream_optimized_compressed_grain() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("stream.vmdk");
        let dst = dir.path().join("stream.raw");
        fixture(&src, false);
        let mut bytes = fs::read(&src).unwrap();
        bytes.resize(10 * 512, 0);
        bytes[8..12].copy_from_slice(&0x3_0000u32.to_le_bytes());
        bytes[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[77..79].copy_from_slice(&1u16.to_le_bytes());
        let desc = b"createType=\"streamOptimized\"\nparentCID=ffffffff\n";
        bytes[512..1024].fill(0);
        bytes[512..512 + desc.len()].copy_from_slice(desc);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[0x5a; 1024]).unwrap();
        let compressed = encoder.finish().unwrap();
        bytes[2048..2056].copy_from_slice(&0u64.to_le_bytes());
        bytes[2056..2060].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
        bytes[2060..2060 + compressed.len()].copy_from_slice(&compressed);
        let mut footer = bytes[..512].to_vec();
        footer[56..64].copy_from_slice(&2u64.to_le_bytes());
        bytes[8 * 512..9 * 512].copy_from_slice(&footer);
        fs::write(&src, bytes).unwrap();
        assert!(matches!(
            convert_sparse_to_raw(&src, &dst).unwrap(),
            ConvertResult::Converted
        ));
        let raw = fs::read(dst).unwrap();
        assert!(raw[..1024].iter().all(|&b| b == 0x5a));
    }

    #[test]
    fn truncated_grain_fails_without_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("bad.vmdk");
        fixture(&src, false);
        File::options()
            .write(true)
            .open(&src)
            .unwrap()
            .set_len(2200)
            .unwrap();
        let dst = dir.path().join("out.raw");
        assert!(convert_sparse_to_raw(&src, &dst).is_err());
        assert!(!dst.exists());
    }
}
