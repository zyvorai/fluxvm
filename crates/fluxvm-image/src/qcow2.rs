// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Native qcow2 (v2/v3) to raw conversion for standalone images: no backing file, encryption, external data file
//! or extended L2 entries. Clusters may be deflate- or zstd-compressed. All header fields are big-endian. Anything
//! else is reported as unsupported so the caller can fall back to qemu-img.

use crate::vmdk::ConvertResult;
use anyhow::{Context, Result, bail};
use flate2::read::DeflateDecoder;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::FileExt,
    path::Path,
};

const MAGIC: &[u8; 4] = b"QFI\xfb";
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const COMPRESSED: u64 = 1 << 62;
const ZERO: u64 = 1;
/// Incompatible features tolerated: dirty refcounts (bit 0) and the compression-type field (bit 3).
const KNOWN_INCOMPATIBLE: u64 = 0b1001;
const MAX_L1_BYTES: u64 = 64 * 1024 * 1024;

pub fn is_qcow2(path: &Path) -> Result<bool> {
    let mut magic = [0u8; 4];
    Ok(File::open(path)?.read(&mut magic)? == 4 && &magic == MAGIC)
}

fn u32be(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64be(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Compression {
    Deflate,
    Zstd,
}

pub fn convert_to_raw(source: &Path, target: &Path) -> Result<ConvertResult> {
    let input = File::open(source)?;
    let file_len = input.metadata()?.len();
    let mut header = [0u8; 112];
    let n = input.read_at(&mut header, 0)?;
    if n < 72 || &header[..4] != MAGIC {
        bail!("truncated qcow2 header");
    }
    let version = u32be(&header, 4);
    let backing_offset = u64be(&header, 8);
    let cluster_bits = u32be(&header, 20);
    let size = u64be(&header, 24);
    let crypt = u32be(&header, 32);
    let l1_size = u64::from(u32be(&header, 36));
    let l1_offset = u64be(&header, 40);
    let mut compression = Compression::Deflate;
    if version == 3 {
        if n < 104 {
            bail!("truncated qcow2 v3 header");
        }
        let incompatible = u64be(&header, 72);
        if incompatible & !KNOWN_INCOMPATIBLE != 0 {
            return Ok(ConvertResult::Unsupported);
        }
        let header_len = u32be(&header, 100);
        if incompatible & 0b1000 != 0 && header_len > 104 && n > 104 {
            compression = match header[104] {
                0 => Compression::Deflate,
                1 => Compression::Zstd,
                _ => return Ok(ConvertResult::Unsupported),
            };
        }
    }
    if !matches!(version, 2 | 3)
        || backing_offset != 0
        || crypt != 0
        || !(9..=21).contains(&cluster_bits)
    {
        return Ok(ConvertResult::Unsupported);
    }
    let cluster = 1u64 << cluster_bits;
    let l2_entries = cluster / 8;
    let needed_l1 = size.div_ceil(cluster * l2_entries);
    if l1_size < needed_l1 || l1_size * 8 > MAX_L1_BYTES {
        bail!("qcow2 L1 table does not cover the disk");
    }
    let in_file = |off: u64, len: u64| off.checked_add(len).is_some_and(|end| end <= file_len);
    if !in_file(l1_offset, needed_l1 * 8) {
        bail!("qcow2 L1 table lies outside the file");
    }
    let mut l1 = vec![0u8; (needed_l1 * 8) as usize];
    input.read_exact_at(&mut l1, l1_offset)?;

    let output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(target)
        .with_context(|| format!("creating {}", target.display()))?;
    output.set_len(size)?;

    // Compressed data offsets are only 62 - (cluster_bits - 8) bits wide; the rest counts extra 512-byte sectors.
    let csize_shift = 62 - (cluster_bits - 8);
    let coffset_mask = (1u64 << csize_shift) - 1;
    let mut l2 = vec![0u8; cluster as usize];
    let mut data = vec![0u8; cluster as usize];
    let mut packed = Vec::new();
    for (i, entry) in l1.as_chunks::<8>().0.iter().enumerate() {
        let l2_offset = u64::from_be_bytes(*entry) & OFFSET_MASK;
        if l2_offset == 0 {
            continue;
        }
        if !in_file(l2_offset, cluster) {
            bail!("qcow2 L2 table {i} lies outside the file");
        }
        input.read_exact_at(&mut l2, l2_offset)?;
        for (j, e) in l2.as_chunks::<8>().0.iter().enumerate() {
            let e = u64::from_be_bytes(*e);
            let guest = (i as u64 * l2_entries + j as u64) * cluster;
            if guest >= size {
                break;
            }
            let len = cluster.min(size - guest) as usize;
            if e & COMPRESSED != 0 {
                let host = e & coffset_mask;
                let sectors = (e & !COMPRESSED & ((1u64 << 62) - 1)) >> csize_shift;
                let span = ((sectors + 1) * 512 - (host & 511)).min(file_len.saturating_sub(host));
                if span == 0 || host >= file_len {
                    bail!("qcow2 compressed cluster at guest offset {guest} lies outside the file");
                }
                packed.resize(span as usize, 0);
                input.read_exact_at(&mut packed, host)?;
                let out = &mut data[..cluster as usize];
                match compression {
                    Compression::Deflate => DeflateDecoder::new(&packed[..])
                        .read_exact(out)
                        .context("inflating a qcow2 cluster")?,
                    Compression::Zstd => zstd::stream::read::Decoder::new(&packed[..])?
                        .read_exact(out)
                        .context("decompressing a qcow2 zstd cluster")?,
                }
            } else {
                let host = e & OFFSET_MASK;
                if e & ZERO != 0 || host == 0 {
                    continue;
                }
                if !in_file(host, len as u64) {
                    bail!("qcow2 data cluster at guest offset {guest} lies outside the file");
                }
                input.read_exact_at(&mut data[..len], host)?;
            }
            // Leave all-zero clusters as holes so the raw image stays sparse.
            if data[..len].iter().any(|&b| b != 0) {
                output.write_all_at(&data[..len], guest)?;
            }
        }
    }
    output.sync_all()?;
    Ok(ConvertResult::Converted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression as Level, write::DeflateEncoder};
    use std::io::Write;

    /// A v3 qcow2 with 64 KiB clusters and a 256 KiB disk: cluster 0 plain data, 1 deflate-compressed,
    /// 2 marked zero, 3 unallocated.
    fn sample(dir: &Path) -> (std::path::PathBuf, Vec<u8>) {
        let cluster = 65536usize;
        let size = 4 * cluster;
        let mut expect = vec![0u8; size];
        expect[..cluster].fill(0xab);
        for (k, b) in expect[cluster..2 * cluster].iter_mut().enumerate() {
            *b = (k % 251) as u8;
        }
        let mut enc = DeflateEncoder::new(Vec::new(), Level::default());
        enc.write_all(&expect[cluster..2 * cluster]).unwrap();
        let packed = enc.finish().unwrap();

        // Layout: header @0, L1 @1 cluster, L2 @2 clusters, data @3 clusters, compressed @4 clusters.
        let mut img = vec![0u8; 4 * cluster];
        img[..4].copy_from_slice(MAGIC);
        img[4..8].copy_from_slice(&3u32.to_be_bytes());
        img[20..24].copy_from_slice(&16u32.to_be_bytes());
        img[24..32].copy_from_slice(&(size as u64).to_be_bytes());
        img[36..40].copy_from_slice(&1u32.to_be_bytes());
        img[40..48].copy_from_slice(&(cluster as u64).to_be_bytes());
        img[96..100].copy_from_slice(&4u32.to_be_bytes());
        img[100..104].copy_from_slice(&104u32.to_be_bytes());
        img[cluster..cluster + 8].copy_from_slice(&((2 * cluster) as u64 | 1 << 63).to_be_bytes());
        let l2 = 2 * cluster;
        img[l2..l2 + 8].copy_from_slice(&((3 * cluster) as u64 | 1 << 63).to_be_bytes());
        let host = 4 * cluster as u64;
        let sectors = (packed.len() as u64).div_ceil(512) - 1;
        let shift = 62 - (16 - 8);
        img[l2 + 8..l2 + 16].copy_from_slice(&(COMPRESSED | sectors << shift | host).to_be_bytes());
        img[l2 + 16..l2 + 24].copy_from_slice(&ZERO.to_be_bytes());
        img[3 * cluster..4 * cluster].fill(0xab);
        img.extend_from_slice(&packed);
        let path = dir.join("t.qcow2");
        std::fs::write(&path, img).unwrap();
        (path, expect)
    }

    #[test]
    fn converts_plain_compressed_zero_and_unallocated_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let (src, expect) = sample(dir.path());
        assert!(is_qcow2(&src).unwrap());
        let out = dir.path().join("t.raw");
        assert!(matches!(
            convert_to_raw(&src, &out).unwrap(),
            ConvertResult::Converted
        ));
        assert_eq!(std::fs::read(out).unwrap(), expect);
    }

    #[test]
    fn backing_files_and_encryption_are_left_to_qemu_img() {
        let dir = tempfile::tempdir().unwrap();
        let (src, _) = sample(dir.path());
        let mut img = std::fs::read(&src).unwrap();
        img[8..16].copy_from_slice(&512u64.to_be_bytes());
        std::fs::write(&src, &img).unwrap();
        let out = dir.path().join("t.raw");
        assert!(matches!(
            convert_to_raw(&src, &out).unwrap(),
            ConvertResult::Unsupported
        ));
        img[8..16].copy_from_slice(&0u64.to_be_bytes());
        img[32..36].copy_from_slice(&1u32.to_be_bytes());
        std::fs::write(&src, &img).unwrap();
        assert!(matches!(
            convert_to_raw(&src, &out).unwrap(),
            ConvertResult::Unsupported
        ));
    }

    #[test]
    fn a_table_outside_the_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (src, _) = sample(dir.path());
        let mut img = std::fs::read(&src).unwrap();
        img[40..48].copy_from_slice(&(1u64 << 40).to_be_bytes());
        std::fs::write(&src, &img).unwrap();
        assert!(convert_to_raw(&src, &dir.path().join("t.raw")).is_err());
    }
}
