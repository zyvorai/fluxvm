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
    !members.is_empty()
        && members
            .iter()
            .all(|m| pci_driver_name(m).as_deref() == Some(VFIO_DRIVER))
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
            if let Ok(link) = fs::read_link(fd.path())
                && link.to_string_lossy() == target
            {
                return true;
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
    if n < 0 { None } else { Some(n as u8) }
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
        let group_held = iommu_group.map(vfio_group_held).unwrap_or(false)
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
        bail!(
            "failed to bind {bdf} to vfio-pci (driver={:?})",
            pci_driver_name(bdf)
        );
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
        if let Some(driver) = previous
            && !driver.is_empty()
            && driver != VFIO_DRIVER
        {
            let _ = fs::write(&override_path, driver);
            let bind_path = format!("/sys/bus/pci/drivers/{driver}/bind");
            let _ = fs::write(&bind_path, bdf);
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
        bail!("IOMMU group {group_id} is split after bind; not every member is on vfio-pci");
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
    let (group_id, members) =
        iommu_group_info(&bdf)?.with_context(|| format!("PCI device {bdf} has no IOMMU group"))?;

    if vfio_group_held(group_id) {
        bail!("IOMMU group {group_id} is still held; stop/delete the QEMU VM before release");
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

/// Most GPUs one sandbox may ask for.
pub const MAX_SANDBOX_GPUS: usize = 8;

/// Fewer free GPUs than a sandbox asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuShortage {
    pub requested: usize,
    pub free: usize,
}

impl std::fmt::Display for GpuShortage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} GPU(s) requested but only {} free (a free GPU is bound to vfio-pci and not in use)",
            self.requested, self.free
        )
    }
}

impl std::error::Error for GpuShortage {}

/// A GPU another VM or process is not using and that is ready for passthrough: its whole IOMMU
/// group is bound to `vfio-pci` and nothing holds the group.
fn is_free(g: &HostGpu) -> bool {
    g.group_bound_to_vfio && !g.group_held && g.iommu_group.is_some()
}

/// Choose `n` free GPUs from `inventory`, never one in `exclude`. Deterministic: the same
/// inventory gives the same answer.
///
/// A request that fits on one NUMA node gets it, on the node with the fewest free GPUs that
/// still fits (best fit, so a big request is not starved by small ones scattering across nodes).
/// Otherwise GPUs are taken in NUMA-node then address order. The result is sorted by address.
pub fn pick_free_gpus(
    inventory: &[HostGpu],
    n: usize,
    exclude: &HashSet<String>,
) -> std::result::Result<Vec<String>, GpuShortage> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut free: Vec<&HostGpu> = inventory
        .iter()
        .filter(|g| is_free(g) && !exclude.contains(&g.bdf.to_ascii_lowercase()))
        .collect();
    free.sort_by(|a, b| {
        (a.numa_node.unwrap_or(u8::MAX), &a.bdf).cmp(&(b.numa_node.unwrap_or(u8::MAX), &b.bdf))
    });
    if free.len() < n {
        return Err(GpuShortage {
            requested: n,
            free: free.len(),
        });
    }
    let mut by_node: BTreeMap<u8, Vec<&HostGpu>> = BTreeMap::new();
    for g in &free {
        by_node
            .entry(g.numa_node.unwrap_or(u8::MAX))
            .or_default()
            .push(g);
    }
    let best_node = by_node
        .iter()
        .filter(|(_, gpus)| gpus.len() >= n)
        .min_by_key(|(node, gpus)| (gpus.len(), **node));
    let chosen: Vec<&HostGpu> = match best_node {
        Some((_, gpus)) => gpus.iter().take(n).copied().collect(),
        None => free.iter().take(n).copied().collect(),
    };
    let mut out: Vec<String> = chosen.iter().map(|g| g.bdf.clone()).collect();
    out.sort();
    Ok(out)
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
            loaded
                .previous_drivers
                .get("0000:01:00.0")
                .map(String::as_str),
            Some("nvidia")
        );
        assert_eq!(loaded.vram_gib.get("0000:01:00.0"), Some(&24));
    }

    #[test]
    fn vendor_label_nvidia_amd() {
        assert_eq!(vendor_label(NVIDIA_VENDOR), "nvidia");
        assert_eq!(vendor_label(AMD_VENDOR), "amd");
    }

    fn gpu(bdf: &str, numa: Option<u8>, bound: bool, held: bool) -> HostGpu {
        HostGpu {
            bdf: bdf.into(),
            vendor_id: NVIDIA_VENDOR,
            device_id: 0x2330,
            vendor: "NVIDIA".into(),
            class_id: DISPLAY_3D_CLASS,
            driver: Some("vfio-pci".into()),
            iommu_group: Some(7),
            iommu_members: vec![bdf.into()],
            group_bound_to_vfio: bound,
            group_held: held,
            numa_node: numa,
            vram_gib: None,
            previous_driver: None,
        }
    }

    fn free_gpu(bdf: &str, numa: u8) -> HostGpu {
        gpu(bdf, Some(numa), true, false)
    }

    fn none() -> HashSet<String> {
        HashSet::new()
    }

    #[test]
    fn picks_the_lowest_addresses_and_is_deterministic() {
        let inv = [
            free_gpu("0000:81:00.0", 0),
            free_gpu("0000:41:00.0", 0),
            free_gpu("0000:c1:00.0", 0),
        ];
        assert_eq!(
            pick_free_gpus(&inv, 2, &none()).unwrap(),
            ["0000:41:00.0", "0000:81:00.0"]
        );
        assert_eq!(
            pick_free_gpus(&inv, 2, &none()),
            pick_free_gpus(&inv, 2, &none())
        );
        assert!(pick_free_gpus(&inv, 0, &none()).unwrap().is_empty());
    }

    #[test]
    fn skips_gpus_that_are_held_unbound_or_have_no_iommu_group() {
        let mut nogroup = free_gpu("0000:10:00.0", 0);
        nogroup.iommu_group = None;
        let inv = [
            gpu("0000:01:00.0", Some(0), true, true),   // in use
            gpu("0000:02:00.0", Some(0), false, false), // still on the host driver
            nogroup,
            free_gpu("0000:03:00.0", 0),
        ];
        assert_eq!(pick_free_gpus(&inv, 1, &none()).unwrap(), ["0000:03:00.0"]);
        assert_eq!(
            pick_free_gpus(&inv, 2, &none()),
            Err(GpuShortage {
                requested: 2,
                free: 1
            })
        );
    }

    #[test]
    fn never_returns_an_excluded_address_whatever_its_case() {
        let inv = [free_gpu("0000:aa:00.0", 0), free_gpu("0000:bb:00.0", 0)];
        let exclude: HashSet<String> = ["0000:aa:00.0".to_string()].into();
        assert_eq!(pick_free_gpus(&inv, 1, &exclude).unwrap(), ["0000:bb:00.0"]);
        let upper = [free_gpu("0000:AA:00.0", 0), free_gpu("0000:bb:00.0", 0)];
        assert_eq!(
            pick_free_gpus(&upper, 1, &exclude).unwrap(),
            ["0000:bb:00.0"]
        );
    }

    #[test]
    fn a_request_that_fits_one_numa_node_gets_the_tightest_one() {
        // node 0 has 3 free, node 1 has 2 free: a request for 2 takes node 1, leaving node 0 whole.
        let inv = [
            free_gpu("0000:01:00.0", 0),
            free_gpu("0000:02:00.0", 0),
            free_gpu("0000:03:00.0", 0),
            free_gpu("0000:81:00.0", 1),
            free_gpu("0000:82:00.0", 1),
        ];
        assert_eq!(
            pick_free_gpus(&inv, 2, &none()).unwrap(),
            ["0000:81:00.0", "0000:82:00.0"]
        );
        assert_eq!(
            pick_free_gpus(&inv, 3, &none()).unwrap(),
            ["0000:01:00.0", "0000:02:00.0", "0000:03:00.0"]
        );
        // Too big for either node: span nodes, lowest node first.
        assert_eq!(
            pick_free_gpus(&inv, 4, &none()).unwrap(),
            [
                "0000:01:00.0",
                "0000:02:00.0",
                "0000:03:00.0",
                "0000:81:00.0"
            ]
        );
    }

    #[test]
    fn a_gpu_with_unknown_numa_is_still_usable() {
        let inv = [gpu("0000:01:00.0", None, true, false)];
        assert_eq!(pick_free_gpus(&inv, 1, &none()).unwrap(), ["0000:01:00.0"]);
    }

    /// Many random allocate and release steps against 4 GPUs: nothing is ever handed out twice and
    /// the count of free GPUs always agrees with what is outstanding.
    #[test]
    fn random_allocation_never_double_assigns() {
        let all = [
            "0000:01:00.0",
            "0000:02:00.0",
            "0000:81:00.0",
            "0000:82:00.0",
        ];
        let numa = [0u8, 0, 1, 1];
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |m: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % m
        };
        let mut leases: Vec<Vec<String>> = Vec::new();
        for _ in 0..5000 {
            let held: HashSet<String> = leases.iter().flatten().cloned().collect();
            if next(3) != 0 || leases.is_empty() {
                let want = 1 + next(3) as usize;
                let inv: Vec<HostGpu> = all
                    .iter()
                    .zip(numa)
                    .map(|(b, n)| gpu(b, Some(n), true, held.contains(*b)))
                    .collect();
                let free = all.len() - held.len();
                match pick_free_gpus(&inv, want, &none()) {
                    Ok(got) => {
                        assert_eq!(got.len(), want);
                        assert!(want <= free);
                        assert!(
                            got.iter().all(|g| !held.contains(g)),
                            "handed out a held GPU: {got:?}"
                        );
                        let unique: HashSet<&String> = got.iter().collect();
                        assert_eq!(unique.len(), got.len());
                        leases.push(got);
                    }
                    Err(short) => {
                        assert!(want > free);
                        assert_eq!(
                            short,
                            GpuShortage {
                                requested: want,
                                free
                            }
                        );
                    }
                }
            } else {
                let i = next(leases.len() as u64) as usize;
                leases.swap_remove(i);
            }
        }
    }
}
