// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Text VMDK descriptor support for split sparse and flat base disks.

use crate::vmdk::{self, ConvertResult};
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

const SECTOR: u64 = 512;

#[derive(Debug)]
enum ExtentKind {
    Flat { name: String, offset: u64 },
    Sparse { name: String },
    Zero,
}

#[derive(Debug)]
struct Extent {
    sectors: u64,
    kind: ExtentKind,
}

pub fn is_descriptor(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    let mut prefix = [0; 64];
    let len = f.read(&mut prefix)?;
    Ok(prefix[..len].starts_with(b"# Disk DescriptorFile"))
}

fn property<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().trim_matches('"'))
    })
}

fn parse_extent(line: &str) -> Result<Option<Extent>> {
    let line = line.trim();
    if !line.starts_with("RW ") && !line.starts_with("RDONLY ") && !line.starts_with("NOACCESS ") {
        return Ok(None);
    }
    if !line.starts_with("RW ") {
        return Ok(None);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() < 3 {
        bail!("invalid VMDK extent description");
    }
    let sectors: u64 = fields[1].parse().context("invalid VMDK extent capacity")?;
    if sectors == 0 {
        bail!("empty VMDK extent");
    }
    let kind = if fields[2] == "ZERO" {
        ExtentKind::Zero
    } else {
        let first = line
            .find('"')
            .context("VMDK extent filename must be quoted")?;
        let last = line[first + 1..]
            .find('"')
            .context("unterminated VMDK filename")?
            + first
            + 1;
        let name = line[first + 1..last].to_owned();
        match fields[2] {
            "SPARSE" => ExtentKind::Sparse { name },
            "FLAT" => {
                let offset = line[last + 1..]
                    .trim()
                    .parse()
                    .context("invalid FLAT offset")?;
                ExtentKind::Flat { name, offset }
            }
            _ => return Ok(None),
        }
    };
    Ok(Some(Extent { sectors, kind }))
}

fn local_extent(base: &Path, name: &str) -> Result<PathBuf> {
    let relative = Path::new(name);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("VMDK extent path must be a local filename");
    }
    let directory = base
        .parent()
        .context("VMDK descriptor has no directory")?
        .canonicalize()?;
    let path = directory.join(relative).canonicalize()?;
    if !path.starts_with(&directory) {
        bail!("VMDK extent escapes descriptor directory");
    }
    Ok(path)
}

pub fn convert_descriptor_to_raw(source: &Path, target: &Path) -> Result<ConvertResult> {
    let metadata = fs::metadata(source)?;
    if metadata.len() > 1024 * 1024 {
        return Ok(ConvertResult::Unsupported);
    }
    let text = fs::read_to_string(source)?;
    if !text.starts_with("# Disk DescriptorFile") {
        return Ok(ConvertResult::Unsupported);
    }
    let kind = property(&text, "createType").unwrap_or("");
    if !matches!(
        kind,
        "twoGbMaxExtentSparse"
            | "2GbMaxExtentSparse"
            | "twoGbMaxExtentFlat"
            | "2GbMaxExtentFlat"
            | "monolithicFlat"
            | "vmfs"
    ) || !property(&text, "parentCID").is_some_and(|cid| cid.eq_ignore_ascii_case("ffffffff"))
        || property(&text, "parentFileNameHint").is_some()
    {
        return Ok(ConvertResult::Unsupported);
    }
    let mut extents = Vec::new();
    for line in text.lines() {
        let extent_line = ["RW ", "RDONLY ", "NOACCESS "]
            .iter()
            .any(|prefix| line.trim().starts_with(prefix));
        match parse_extent(line)? {
            Some(extent) => extents.push(extent),
            None if extent_line => return Ok(ConvertResult::Unsupported),
            None => {}
        }
    }
    if extents.is_empty() || extents.len() > 4096 {
        return Ok(ConvertResult::Unsupported);
    }
    let sectors = extents.iter().try_fold(0u64, |sum, extent| {
        sum.checked_add(extent.sectors)
            .context("VMDK capacity overflow")
    })?;
    let total = sectors.checked_mul(SECTOR).context("VMDK size overflow")?;
    // Validate all referenced paths before creating output. A descriptor may
    // contain filenames with spaces but cannot access arbitrary host paths.
    let sources: Vec<_> = extents
        .iter()
        .map(|extent| match &extent.kind {
            ExtentKind::Zero => Ok(None),
            ExtentKind::Sparse { name } | ExtentKind::Flat { name, .. } => {
                local_extent(source, name).map(Some)
            }
        })
        .collect::<Result<_>>()?;

    let temp = target.with_extension(format!("fluxvm-{}.partial", uuid::Uuid::new_v4()));
    let result = (|| -> Result<ConvertResult> {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        output.set_len(total)?;
        let mut guest_offset = 0u64;
        for (extent, path) in extents.iter().zip(&sources) {
            let count = extent.sectors * SECTOR;
            match (&extent.kind, path) {
                (ExtentKind::Zero, _) => {}
                (ExtentKind::Flat { offset, .. }, Some(path)) => {
                    let mut input = File::open(path)?;
                    let source_offset =
                        offset.checked_mul(SECTOR).context("FLAT offset overflow")?;
                    let source_len = input.metadata()?.len();
                    if source_offset
                        .checked_add(count)
                        .is_none_or(|end| end > source_len)
                    {
                        bail!("truncated VMDK FLAT extent");
                    }
                    input.seek(SeekFrom::Start(source_offset))?;
                    output.seek(SeekFrom::Start(guest_offset))?;
                    let copied = std::io::copy(&mut input.take(count), &mut output)?;
                    if copied != count {
                        bail!("short VMDK FLAT extent");
                    }
                }
                (ExtentKind::Sparse { .. }, Some(path)) => {
                    let part =
                        target.with_extension(format!("fluxvm-{}.extent", uuid::Uuid::new_v4()));
                    let converted =
                        vmdk::convert_sparse_extent_to_raw(path, &part, Some(extent.sectors));
                    match converted {
                        Ok(ConvertResult::Converted) => {}
                        Ok(ConvertResult::Unsupported) => {
                            let _ = fs::remove_file(&part);
                            return Ok(ConvertResult::Unsupported);
                        }
                        Err(err) => {
                            let _ = fs::remove_file(&part);
                            return Err(err);
                        }
                    }
                    let mut input = File::open(&part)?;
                    output.seek(SeekFrom::Start(guest_offset))?;
                    let copied = std::io::copy(&mut input, &mut output);
                    let _ = fs::remove_file(&part);
                    if copied? != count {
                        bail!("short VMDK SPARSE extent");
                    }
                }
                _ => bail!("missing VMDK extent"),
            }
            guest_offset += count;
        }
        output.sync_all()?;
        fs::rename(&temp, target)?;
        Ok(ConvertResult::Converted)
    })();
    if !matches!(&result, Ok(ConvertResult::Converted)) {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_flat_extents_with_offsets_and_zeros() {
        let dir = tempfile::tempdir().unwrap();
        let desc = dir.path().join("disk.vmdk");
        fs::write(
            dir.path().join("one-f001.vmdk"),
            [vec![0; 512], vec![0x5a; 512]].concat(),
        )
        .unwrap();
        fs::write(&desc, "# Disk DescriptorFile\nCID=11111111\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\nRW 1 FLAT \"one-f001.vmdk\" 1\nRW 1 ZERO\n").unwrap();
        let dst = dir.path().join("out.raw");
        assert!(matches!(
            convert_descriptor_to_raw(&desc, &dst).unwrap(),
            ConvertResult::Converted
        ));
        let raw = fs::read(dst).unwrap();
        assert_eq!(raw.len(), 1024);
        assert!(raw[..512].iter().all(|&b| b == 0x5a));
        assert!(raw[512..].iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_extent_escape() {
        let dir = tempfile::tempdir().unwrap();
        assert!(local_extent(&dir.path().join("disk.vmdk"), "../secret").is_err());
    }

    #[test]
    fn joins_split_sparse_extents() {
        let dir = tempfile::tempdir().unwrap();
        let desc = dir.path().join("disk.vmdk");
        for (name, value) in [("disk-s001.vmdk", 0x41), ("disk-s002.vmdk", 0x42)] {
            let mut bytes = vec![0u8; 6 * 512];
            bytes[..4].copy_from_slice(b"KDMV");
            bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
            bytes[12..20].copy_from_slice(&2u64.to_le_bytes());
            bytes[20..28].copy_from_slice(&2u64.to_le_bytes());
            bytes[44..48].copy_from_slice(&4u32.to_le_bytes());
            bytes[56..64].copy_from_slice(&1u64.to_le_bytes());
            bytes[512..516].copy_from_slice(&2u32.to_le_bytes());
            bytes[1024..1028].copy_from_slice(&3u32.to_le_bytes());
            bytes[1536..2560].fill(value);
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        fs::write(&desc, "# Disk DescriptorFile\nCID=11111111\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentSparse\"\nRW 2 SPARSE \"disk-s001.vmdk\"\nRW 2 SPARSE \"disk-s002.vmdk\"\n").unwrap();
        let dst = dir.path().join("out.raw");
        assert!(matches!(
            convert_descriptor_to_raw(&desc, &dst).unwrap(),
            ConvertResult::Converted
        ));
        let raw = fs::read(dst).unwrap();
        assert_eq!(&raw[..1024], &[0x41; 1024]);
        assert_eq!(&raw[1024..], &[0x42; 1024]);
    }
}
