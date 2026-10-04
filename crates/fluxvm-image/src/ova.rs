// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OVF descriptor parsing and OVA (tar) extraction.
//!
//! Elements and attributes are matched by local name, so the `ovf:`,
//! `rasd:` and `vmw:` prefixes VMware, VirtualBox and others use all work.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

/// CIM resource types used in `VirtualHardwareSection/Item`.
const RASD_CPU: &str = "3";
const RASD_MEMORY: &str = "4";
const RASD_ETHERNET: &str = "10";
const RASD_DISK: &str = "17";

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct OvfSummary {
    pub name: String,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    /// `efi` or `bios` when the descriptor says (VMware `firmware` key).
    pub firmware: Option<String>,
    /// OS description or VMware `osType`, e.g. `ubuntu64Guest`.
    pub os: Option<String>,
    pub nics: u32,
    /// Disks in controller order; the first is the boot disk.
    pub disks: Vec<OvfDisk>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OvfDisk {
    pub id: String,
    /// File name inside the OVA (or next to the .ovf).
    pub href: String,
    pub capacity_bytes: Option<u64>,
}

fn attr<'a>(n: roxmltree::Node<'a, '_>, local: &str) -> Option<&'a str> {
    n.attributes()
        .find(|a| a.name() == local)
        .map(|a| a.value())
}

fn child_text<'a>(n: roxmltree::Node<'a, '_>, local: &str) -> Option<&'a str> {
    n.children()
        .find(|c| c.is_element() && c.tag_name().name() == local)
        .and_then(|c| c.text())
        .map(str::trim)
}

/// Bytes per unit for an OVF allocation-units string such as
/// `byte * 2^30`, `byte`, `MegaBytes`.
fn allocation_units(s: &str) -> Result<u64> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let lower = compact.to_ascii_lowercase();
    if lower.is_empty() || lower == "byte" || lower == "bytes" {
        return Ok(1);
    }
    if let Some(exp) = lower.strip_prefix("byte*2^") {
        let exp: u32 = exp
            .parse()
            .with_context(|| format!("allocation units {s:?}"))?;
        if exp > 60 {
            bail!("allocation units {s:?} out of range");
        }
        return Ok(1u64 << exp);
    }
    Ok(match lower.as_str() {
        "kilobytes" | "kb" | "kib" => 1 << 10,
        "megabytes" | "mb" | "mib" => 1 << 20,
        "gigabytes" | "gb" | "gib" => 1 << 30,
        _ => bail!("unsupported allocation units {s:?}"),
    })
}

pub fn parse_ovf(xml: &str) -> Result<OvfSummary> {
    let doc = roxmltree::Document::parse(xml).context("parsing OVF XML")?;
    let root = doc.root_element();
    let elements = || root.descendants().filter(|n| n.is_element());

    let files: Vec<(String, String)> = elements()
        .filter(|n| n.tag_name().name() == "File")
        .filter_map(|n| Some((attr(n, "id")?.to_string(), attr(n, "href")?.to_string())))
        .collect();

    let mut disks = Vec::new();
    for d in elements().filter(|n| n.tag_name().name() == "Disk") {
        let id = attr(d, "diskId").context("OVF Disk without diskId")?;
        let file_ref = attr(d, "fileRef").context("OVF Disk without fileRef")?;
        let href = files
            .iter()
            .find(|(fid, _)| fid == file_ref)
            .map(|(_, h)| h.clone())
            .with_context(|| format!("OVF Disk {id} references unknown file {file_ref}"))?;
        let capacity_bytes = match attr(d, "capacity") {
            Some(c) => {
                let units = allocation_units(attr(d, "capacityAllocationUnits").unwrap_or("byte"))?;
                let n: u64 = c
                    .parse()
                    .with_context(|| format!("OVF Disk {id} capacity {c:?}"))?;
                Some(n.checked_mul(units).context("disk capacity overflows")?)
            }
            None => None,
        };
        disks.push(OvfDisk {
            id: id.to_string(),
            href,
            capacity_bytes,
        });
    }

    let mut summary = OvfSummary::default();
    let system = elements().find(|n| n.tag_name().name() == "VirtualSystem");
    if let Some(vs) = system {
        summary.name = child_text(vs, "Name")
            .or_else(|| attr(vs, "id"))
            .unwrap_or_default()
            .to_string();
    }

    let mut disk_order = Vec::new();
    for item in elements().filter(|n| {
        matches!(
            n.tag_name().name(),
            "Item" | "StorageItem" | "EthernetPortItem"
        )
    }) {
        let Some(kind) = child_text(item, "ResourceType") else {
            continue;
        };
        let quantity = child_text(item, "VirtualQuantity").and_then(|q| q.parse::<u64>().ok());
        match kind {
            RASD_CPU => summary.vcpus = quantity.and_then(|q| u32::try_from(q).ok()),
            RASD_MEMORY => {
                let units =
                    allocation_units(child_text(item, "AllocationUnits").unwrap_or("byte * 2^20"))?;
                summary.memory_mib = quantity.map(|q| q.saturating_mul(units) >> 20);
            }
            RASD_ETHERNET => summary.nics += 1,
            RASD_DISK => {
                if let Some(res) = child_text(item, "HostResource") {
                    // ovf:/disk/vmdisk1 or /disk/vmdisk1
                    if let Some(id) = res.rsplit('/').next() {
                        disk_order.push(id.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    disks.sort_by_key(|d| {
        disk_order
            .iter()
            .position(|id| *id == d.id)
            .unwrap_or(usize::MAX)
    });
    summary.disks = disks;

    for n in elements() {
        match n.tag_name().name() {
            "Config" if attr(n, "key") == Some("firmware") => {
                summary.firmware = attr(n, "value").map(str::to_ascii_lowercase);
            }
            "OperatingSystemSection" => {
                summary.os = attr(n, "osType")
                    .map(str::to_string)
                    .or_else(|| child_text(n, "Description").map(str::to_string));
            }
            _ => {}
        }
    }
    Ok(summary)
}

/// Extracts an OVA into `dir` and returns the path of its `.ovf`. Only
/// plain files with a bare name are written, so an archive can't place
/// anything outside `dir`.
pub fn extract_ova(ova: &Path, dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let file = fs::File::open(ova).with_context(|| format!("opening {}", ova.display()))?;
    let mut archive = tar::Archive::new(file);
    let mut ovf = None;
    for entry in archive.entries().context("reading OVA tar")? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.into_owned();
        let name = safe_member_name(&path)
            .with_context(|| format!("OVA member {} has an unsafe path", path.display()))?;
        let out = dir.join(&name);
        entry
            .unpack(&out)
            .with_context(|| format!("extracting {name}"))?;
        if name.to_ascii_lowercase().ends_with(".ovf") && ovf.is_none() {
            ovf = Some(out);
        }
    }
    ovf.context("OVA has no .ovf descriptor")
}

fn safe_member_name(path: &Path) -> Option<String> {
    let mut parts = path.components();
    let first = parts.next()?;
    let std::path::Component::Normal(name) = first else {
        return None;
    };
    if parts.next().is_some() {
        return None;
    }
    let name = name.to_str()?;
    (!name.is_empty() && !name.starts_with('.')).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VMWARE_OVF: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References>
    <File ovf:href="web-disk2.vmdk" ovf:id="file2" ovf:size="1024"/>
    <File ovf:href="web-disk1.vmdk" ovf:id="file1" ovf:size="2048"/>
  </References>
  <DiskSection>
    <Disk ovf:capacity="10" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk2" ovf:fileRef="file2"/>
    <Disk ovf:capacity="20" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1"/>
  </DiskSection>
  <VirtualSystem ovf:id="web01">
    <Name>web01</Name>
    <OperatingSystemSection ovf:id="94" vmw:osType="ubuntu64Guest"><Description>Ubuntu Linux (64-bit)</Description></OperatingSystemSection>
    <VirtualHardwareSection>
      <Item><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>4</rasd:VirtualQuantity></Item>
      <Item><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>8192</rasd:VirtualQuantity></Item>
      <Item><rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:ResourceType>17</rasd:ResourceType></Item>
      <Item><rasd:HostResource>ovf:/disk/vmdisk2</rasd:HostResource><rasd:ResourceType>17</rasd:ResourceType></Item>
      <Item><rasd:ResourceType>10</rasd:ResourceType></Item>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="efi"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>"#;

    #[test]
    fn parses_vmware_descriptor() {
        let s = parse_ovf(VMWARE_OVF).unwrap();
        assert_eq!(s.name, "web01");
        assert_eq!(s.vcpus, Some(4));
        assert_eq!(s.memory_mib, Some(8192));
        assert_eq!(s.nics, 1);
        assert_eq!(s.firmware.as_deref(), Some("efi"));
        assert_eq!(s.os.as_deref(), Some("ubuntu64Guest"));
        let hrefs: Vec<_> = s.disks.iter().map(|d| d.href.as_str()).collect();
        assert_eq!(
            hrefs,
            ["web-disk1.vmdk", "web-disk2.vmdk"],
            "boot disk first"
        );
        assert_eq!(s.disks[0].capacity_bytes, Some(20 << 30));
    }

    #[test]
    fn allocation_units_forms() {
        assert_eq!(allocation_units("byte").unwrap(), 1);
        assert_eq!(allocation_units("byte * 2^20").unwrap(), 1 << 20);
        assert_eq!(allocation_units("byte*2^30").unwrap(), 1 << 30);
        assert_eq!(allocation_units("MegaBytes").unwrap(), 1 << 20);
        assert!(allocation_units("byte * 2^99").is_err());
        assert!(allocation_units("furlongs").is_err());
    }

    #[test]
    fn extract_rejects_traversal_and_finds_ovf() {
        let dir = tempfile::tempdir().unwrap();
        let ova = dir.path().join("x.ova");
        let mut b = tar::Builder::new(fs::File::create(&ova).unwrap());
        for (name, body) in [
            ("vm.ovf", VMWARE_OVF.as_bytes()),
            ("web-disk1.vmdk", b"disk"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, body).unwrap();
        }
        b.finish().unwrap();
        drop(b);
        let out = dir.path().join("out");
        let ovf = extract_ova(&ova, &out).unwrap();
        assert_eq!(ovf, out.join("vm.ovf"));
        assert!(out.join("web-disk1.vmdk").exists());

        assert!(safe_member_name(Path::new("../evil")).is_none());
        assert!(safe_member_name(Path::new("/etc/passwd")).is_none());
        assert!(safe_member_name(Path::new("a/b.vmdk")).is_none());
        assert_eq!(
            safe_member_name(Path::new("disk.vmdk")).as_deref(),
            Some("disk.vmdk")
        );
    }
}
