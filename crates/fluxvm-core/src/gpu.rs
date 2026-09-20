// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//!
//! Host GPU inventory and explicit VFIO bind/release for QEMU passthrough.
//! Fabric (or an operator) calls these APIs; FluxVM never rebinds a device
//! as a side effect of `POST /v1/vms`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const PCI_DEVICES: &str = "/sys/bus/pci/devices";
const VFIO_DRIVER: &str = "vfio-pci";
const VGA_CLASS: u32 = 0x0300;
const DISPLAY_3D_CLASS: u32 = 0x0302;
const NVIDIA_VENDOR: u16 = 0x10de;
const AMD_VENDOR: u16 = 0x1002;

/// One PCI function that looks like a GPU (VGA or 3D controller).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostGpu {
    pub bdf: String,
    pub vendor_id: u16,
    pub device_id: u16,
    pub vendor: String,
    pub class_id: u32,
    pub driver: Option<String>,
    pub iommu_group: Option<u32>,
    /// Every PCI function in the same IOMMU group (sorted).
    pub iommu_members: Vec<String>,
    /// True when every group member is bound to `vfio-pci`.
    pub group_bound_to_vfio: bool,
    /// True when any process has `/dev/vfio/<group>` open.
    pub group_held: bool,
    pub numa_node: Option<u8>,
    /// Operator-supplied or previously recorded VRAM (GiB). Sysfs alone
    /// cannot report VRAM before the device is bound to the vendor driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vram_gib: Option<u32>,
    /// Driver name recorded before the last successful bind, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_driver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuBindState {
    /// BDF → driver that was unbound before binding to vfio-pci.
    #[serde(default)]
    pub previous_drivers: BTreeMap<String, String>,
    /// Optional operator-recorded VRAM (GiB) keyed by BDF.
    #[serde(default)]
    pub vram_gib: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuBindRequest {
    pub bdf: String,
    /// When set, recorded on the GPU inventory entry for placement checks.
    #[serde(default)]
    pub vram_gib: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuReleaseRequest {
    pub bdf: String,
    /// When true, unbind from vfio-pci and re-bind the recorded previous
    /// driver (or `driver_override` + probe). Default leaves vfio-pci.
    #[serde(default)]
    pub restore_driver: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuBindResult {
    pub bdf: String,
    pub iommu_group: u32,
    pub members: Vec<String>,
    pub previous_drivers: BTreeMap<String, String>,
}

fn normalize_bdf(bdf: &str) -> Result<String> {
    let bdf = bdf.trim().to_ascii_lowercase();
    if !valid_pci_bdf(&bdf) {
        bail!("invalid PCI BDF {bdf:?}");
    }
    Ok(bdf)
}

pub fn valid_pci_bdf(name: &str) -> bool {
    if name.len() != 12 || name.as_bytes()[4] != b':' || name.as_bytes()[7] != b':' {
        return false;
    }
    if name.as_bytes()[10] != b'.' {
        return false;
    }
    u16::from_str_radix(&name[0..4], 16).is_ok()
        && u8::from_str_radix(&name[5..7], 16).is_ok()
        && u8::from_str_radix(&name[8..10], 16).is_ok()
        && u8::from_str_radix(&name[11..12], 16).is_ok()
}

fn read_hex_u16(path: &Path) -> Result<u16> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let s = raw.trim().trim_start_matches("0x");
    u16::from_str_radix(s, 16).with_context(|| format!("parsing hex in {}", path.display()))
}

fn read_hex_u32(path: &Path) -> Result<u32> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let s = raw.trim().trim_start_matches("0x");
    u32::from_str_radix(s, 16).with_context(|| format!("parsing hex in {}", path.display()))
}

fn pci_driver_name(bdf: &str) -> Option<String> {
    fs::canonicalize(format!("{PCI_DEVICES}/{bdf}/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|v| v.to_string_lossy().into_owned()))
}

fn iommu_group_info(bdf: &str) -> Result<Option<(u32, Vec<String>)>> {
    let group_link = PathBuf::from(format!("{PCI_DEVICES}/{bdf}/iommu_group"));
    let group_path = match fs::canonicalize(&group_link) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("resolving IOMMU group for {bdf}")),
    };
    let group_id = group_path
        .file_name()
        .and_then(|v| v.to_str())
        .context("IOMMU group path has no numeric basename")?
        .parse::<u32>()
        .context("parsing IOMMU group id")?;
    let mut members = Vec::new();
    for entry in fs::read_dir(group_path.join("devices"))
        .with_context(|| format!("reading IOMMU group {group_id} members"))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if valid_pci_bdf(&name) {
            members.push(name.to_ascii_lowercase());
        }
    }
    members.sort();
    members.dedup();
    if !members.iter().any(|v| v == bdf) {
        bail!("IOMMU group {group_id} does not contain requested function {bdf}");
    }
    Ok(Some((group_id, members)))
}

fn group_all_vfio(members: &[String]) -> bool {
    !members.is_empty() && members.iter().all(|m| pci_driver_name(m).as_deref() == Some(VFIO_DRIVER))
}

/// True when any process has an open fd pointing at `/dev/vfio/<group>`.
pub fn vfio_group_held(group_id: u32) -> bool {
    let target = format!("/dev/vfio/{group_id}");
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    return true;
                }
            }
        }
    }
    false
}

fn vendor_label(vendor_id: u16) -> String {
    match vendor_id {
        NVIDIA_VENDOR => "nvidia".into(),
        AMD_VENDOR => "amd".into(),
        other => format!("0x{other:04x}"),
    }
}

fn numa_node(bdf: &str) -> Option<u8> {
    let raw = fs::read_to_string(format!("{PCI_DEVICES}/{bdf}/numa_node")).ok()?;
    let n: i32 = raw.trim().parse().ok()?;
    if n < 0 {
        None
    } else {
        Some(n as u8)
    }
}

fn is_gpu_class(class_id: u32) -> bool {
    let class = class_id >> 8;
    class == VGA_CLASS || class == DISPLAY_3D_CLASS
}

pub fn load_bind_state(state_dir: &Path) -> GpuBindState {
    let path = state_dir.join("gpu-bind-state.json");
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => GpuBindState::default(),
    }
}

pub fn save_bind_state(state_dir: &Path, state: &GpuBindState) -> Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = state_dir.join("gpu-bind-state.json");
    let tmp = state_dir.join("gpu-bind-state.json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

/// Scan sysfs for VGA/3D controllers. `allocated_bdfs` are BDFs already
/// claimed by running or stopped VMs (`CreateVmRequest.vfio_devices`).
pub fn list_host_gpus(state_dir: &Path, allocated_bdfs: &HashSet<String>) -> Result<Vec<HostGpu>> {
    let bind_state = load_bind_state(state_dir);
    let mut out = Vec::new();
    let entries = match fs::read_dir(PCI_DEVICES) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).context("reading /sys/bus/pci/devices"),
    };
    for entry in entries {
        let entry = entry?;
        let bdf = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if !valid_pci_bdf(&bdf) {
            continue;
        }
        let class_path = entry.path().join("class");
        let class_id = match read_hex_u32(&class_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !is_gpu_class(class_id) {
            continue;
        }
        let vendor_id = read_hex_u16(&entry.path().join("vendor"))?;
        let device_id = read_hex_u16(&entry.path().join("device"))?;
        let (iommu_group, iommu_members) = match iommu_group_info(&bdf)? {
            Some((g, m)) => (Some(g), m),
            None => (None, vec![bdf.clone()]),
        };
        let group_bound_to_vfio = group_all_vfio(&iommu_members);
        let group_held = iommu_group
            .map(vfio_group_held)
            .unwrap_or(false)
            || iommu_members.iter().any(|m| allocated_bdfs.contains(m));
        out.push(HostGpu {
            bdf: bdf.clone(),
            vendor_id,
            device_id,
            vendor: vendor_label(vendor_id),
            class_id,
            driver: pci_driver_name(&bdf),
            iommu_group,
            iommu_members,
            group_bound_to_vfio,
            group_held,
            numa_node: numa_node(&bdf),
            vram_gib: bind_state.vram_gib.get(&bdf).copied(),
            previous_driver: bind_state.previous_drivers.get(&bdf).cloned(),
        });
    }
    out.sort_by(|a, b| a.bdf.cmp(&b.bdf));
    Ok(out)
}

fn unbind_driver(bdf: &str, driver: &str) -> Result<()> {
    let path = format!("/sys/bus/pci/drivers/{driver}/unbind");
    fs::write(&path, bdf).with_context(|| format!("unbinding {bdf} from {driver}"))
}

fn bind_vfio(bdf: &str) -> Result<()> {
    let vendor = read_hex_u16(&PathBuf::from(format!("{PCI_DEVICES}/{bdf}/vendor")))?;
    let device = read_hex_u16(&PathBuf::from(format!("{PCI_DEVICES}/{bdf}/device")))?;
    // Prefer driver_override + bind so we do not permanently enlarge new_id.
    let override_path = format!("{PCI_DEVICES}/{bdf}/driver_override");
    if Path::new(&override_path).exists() {
        fs::write(&override_path, VFIO_DRIVER)
            .with_context(|| format!("setting driver_override on {bdf}"))?;
        let bind_path = format!("/sys/bus/pci/drivers/{VFIO_DRIVER}/bind");
        match fs::write(&bind_path, bdf) {
            Ok(()) => {}
            Err(_) => {
                // Fall back to new_id if bind failed (driver not yet aware).
                let new_id = format!("{vendor:04x} {device:04x}");
                fs::write("/sys/bus/pci/drivers/vfio-pci/new_id", &new_id)
                    .with_context(|| format!("vfio-pci new_id for {bdf}"))?;
            }
        }
    } else {
        let new_id = format!("{vendor:04x} {device:04x}");
        fs::write("/sys/bus/pci/drivers/vfio-pci/new_id", &new_id)
            .with_context(|| format!("vfio-pci new_id for {bdf}"))?;
    }
    if pci_driver_name(bdf).as_deref() != Some(VFIO_DRIVER) {
        bail!("failed to bind {bdf} to vfio-pci (driver={:?})", pci_driver_name(bdf));
    }
    Ok(())
}

fn restore_driver(bdf: &str, previous: Option<&str>) -> Result<()> {
    if pci_driver_name(bdf).as_deref() == Some(VFIO_DRIVER) {
        unbind_driver(bdf, VFIO_DRIVER)?;
    }
    let override_path = format!("{PCI_DEVICES}/{bdf}/driver_override");
    if Path::new(&override_path).exists() {
        // Empty string clears the override on modern kernels.
        let _ = fs::write(&override_path, "");
        if let Some(driver) = previous {
            if !driver.is_empty() && driver != VFIO_DRIVER {
                let _ = fs::write(&override_path, driver);
                let bind_path = format!("/sys/bus/pci/drivers/{driver}/bind");
                let _ = fs::write(&bind_path, bdf);
            }
        }
        // Trigger a reprobe.
        let _ = fs::write(format!("{PCI_DEVICES}/{bdf}/driver_override"), "");
        let _ = fs::write("/sys/bus/pci/drivers_probe", bdf);
    }
    Ok(())
}

/// Bind every function in the GPU's IOMMU group to vfio-pci.
/// Refuses a missing IOMMU group, a held group, or a partially free group.
pub fn bind_gpu_group(
    state_dir: &Path,
    req: &GpuBindRequest,
    allocated_bdfs: &HashSet<String>,
) -> Result<GpuBindResult> {
    let bdf = normalize_bdf(&req.bdf)?;
    let (group_id, members) = iommu_group_info(&bdf)?
        .with_context(|| format!("PCI device {bdf} has no IOMMU group; enable IOMMU first"))?;

    if vfio_group_held(group_id) {
        bail!("IOMMU group {group_id} is held (/dev/vfio/{group_id} is open)");
    }
    for m in &members {
        if allocated_bdfs.contains(m) {
            bail!("IOMMU group {group_id} member {m} is allocated to a VM");
        }
    }

    let mut previous = BTreeMap::new();
    for m in &members {
        let current = pci_driver_name(m);
        if current.as_deref() == Some(VFIO_DRIVER) {
            continue;
        }
        if let Some(ref driver) = current {
            previous.insert(m.clone(), driver.clone());
            unbind_driver(m, driver)?;
        }
        bind_vfio(m)?;
    }

    if !group_all_vfio(&members) {
        bail!(
            "IOMMU group {group_id} is split after bind; not every member is on vfio-pci"
        );
    }

    let mut state = load_bind_state(state_dir);
    for (m, d) in &previous {
        state.previous_drivers.insert(m.clone(), d.clone());
    }
    if let Some(vram) = req.vram_gib {
        state.vram_gib.insert(bdf.clone(), vram);
    }
    save_bind_state(state_dir, &state)?;

    Ok(GpuBindResult {
        bdf,
        iommu_group: group_id,
        members,
        previous_drivers: previous,
    })
}

/// Mark a GPU free after QEMU has released the VFIO group fd.
/// By default the device stays on vfio-pci. Pass `restore_driver: true`
/// to put the previous host driver back.
pub fn release_gpu_group(
    state_dir: &Path,
    req: &GpuReleaseRequest,
    allocated_bdfs: &HashSet<String>,
) -> Result<HostGpu> {
    let bdf = normalize_bdf(&req.bdf)?;
    let (group_id, members) = iommu_group_info(&bdf)?
        .with_context(|| format!("PCI device {bdf} has no IOMMU group"))?;

    if vfio_group_held(group_id) {
        bail!(
            "IOMMU group {group_id} is still held; stop/delete the QEMU VM before release"
        );
    }
    for m in &members {
        if allocated_bdfs.contains(m) {
            bail!("IOMMU group {group_id} member {m} is still listed on a VM");
        }
    }

    let mut state = load_bind_state(state_dir);
    if req.restore_driver {
        for m in &members {
            let prev = state.previous_drivers.get(m).cloned();
            restore_driver(m, prev.as_deref())?;
            state.previous_drivers.remove(m);
        }
        save_bind_state(state_dir, &state)?;
    }

    let gpus = list_host_gpus(state_dir, allocated_bdfs)?;
    gpus.into_iter()
        .find(|g| g.bdf == bdf)
        .with_context(|| format!("GPU {bdf} not found after release"))
}

/// IOMMU / driver preflight checks for a host that will run GPU VMs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuPreflight {
    pub iommu_enabled: bool,
    pub vfio_pci_loaded: bool,
    pub gpu_count: usize,
    pub issues: Vec<String>,
}

pub fn gpu_preflight(state_dir: &Path) -> Result<GpuPreflight> {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let iommu_enabled = cmdline.contains("intel_iommu=on")
        || cmdline.contains("amd_iommu=on")
        || Path::new("/sys/kernel/iommu_groups").exists();
    let vfio_pci_loaded = Path::new("/sys/bus/pci/drivers/vfio-pci").exists();
    let gpus = list_host_gpus(state_dir, &HashSet::new())?;
    let mut issues = Vec::new();
    if !iommu_enabled {
        issues.push("IOMMU does not appear enabled".into());
    }
    if !vfio_pci_loaded {
        issues.push("vfio-pci driver is not loaded".into());
    }
    for g in &gpus {
        if g.iommu_group.is_none() {
            issues.push(format!("{} has no IOMMU group", g.bdf));
        }
        if g.iommu_members.len() > 1 && !g.group_bound_to_vfio {
            let foreign: Vec<_> = g
                .iommu_members
                .iter()
                .filter(|m| m.as_str() != g.bdf)
                .cloned()
                .collect();
            if !foreign.is_empty() {
                issues.push(format!(
                    "{} shares IOMMU group with {:?}; bind the whole group or isolate ACS",
                    g.bdf, foreign
                ));
            }
        }
    }
    Ok(GpuPreflight {
        iommu_enabled,
        vfio_pci_loaded,
        gpu_count: gpus.len(),
        issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_bdf_accepts_standard_form() {
        assert!(valid_pci_bdf("0000:01:00.0"));
        assert!(valid_pci_bdf("0000:ff:1f.7"));
        assert!(!valid_pci_bdf("01:00.0"));
        assert!(!valid_pci_bdf("0000:01:00.g"));
        assert!(!valid_pci_bdf("../etc/passwd"));
    }

    #[test]
    fn bind_state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = GpuBindState::default();
        state
            .previous_drivers
            .insert("0000:01:00.0".into(), "nvidia".into());
        state.vram_gib.insert("0000:01:00.0".into(), 24);
        save_bind_state(dir.path(), &state).unwrap();
        let loaded = load_bind_state(dir.path());
        assert_eq!(
            loaded.previous_drivers.get("0000:01:00.0").map(String::as_str),
            Some("nvidia")
        );
        assert_eq!(loaded.vram_gib.get("0000:01:00.0"), Some(&24));
    }

    #[test]
    fn vendor_label_nvidia_amd() {
        assert_eq!(vendor_label(NVIDIA_VENDOR), "nvidia");
        assert_eq!(vendor_label(AMD_VENDOR), "amd");
    }
}
