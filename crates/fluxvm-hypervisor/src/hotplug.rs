// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! H4 / P3: CPU and disk hotplug for the in-tree KVM engine.
//!
//! CPU hotplug follows the Cloud Hypervisor model: reserve `max_cpus` at
//! create time, then `KVM_CREATE_VCPU` for additional ids while the VM is
//! paused (control path). Disk hotplug validates a host image and returns a
//! slot plan the VMM attaches as another virtio-blk MMIO window.

use crate::error::{FluxError, Result};
use crate::kvm::KvmVm;
use std::path::{Path, PathBuf};

/// Default hotplug headroom when the caller does not set `max_cpus`.
pub const DEFAULT_MAX_CPUS: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuHotplugPlan {
    pub current: u8,
    pub max: u8,
    pub add: u8,
    pub next_id: u8,
}

/// Validate a CPU hotplug request against current / max counts.
pub fn plan_add_vcpu(current: u8, max: u8, add: u8) -> Result<CpuHotplugPlan> {
    if add == 0 {
        return Err(FluxError::Unsupported("add_vcpus must be >= 1".into()));
    }
    if max == 0 || max < current {
        return Err(FluxError::Unsupported(
            "max_cpus must be >= current vCPU count".into(),
        ));
    }
    let next = current
        .checked_add(add)
        .ok_or_else(|| FluxError::Unsupported("vCPU count overflow".into()))?;
    if next > max {
        return Err(FluxError::Unsupported(format!(
            "adding {add} vCPU(s) to {current} would exceed max_cpus={max}"
        )));
    }
    Ok(CpuHotplugPlan {
        current,
        max,
        add,
        next_id: current,
    })
}

/// Create the next vCPU id on an existing KVM VM (caller owns threading).
pub fn add_vcpu(kvm: &mut KvmVm, id: u8) -> Result<()> {
    let current = kvm.num_cpus() as u8;
    if id != current {
        return Err(FluxError::Unsupported(format!(
            "vCPU ids must be contiguous: next expected {current}, got {id}"
        )));
    }
    kvm.create_vcpu(id as i32)?;
    Ok(())
}

/// Remove is not supported for in-tree KVM (CH also rejects shrink in many
/// builds); keep an explicit error rather than a silent no-op.
pub fn remove_vcpu(_id: u8) -> Result<()> {
    Err(FluxError::Unsupported(
        "CPU hot-unplug is not supported by the in-tree KVM engine (SoT=cloud-hypervisor)".into(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskHotplugPlan {
    pub path: PathBuf,
    pub read_only: bool,
}

/// Validate a host disk image for virtio-blk hotplug.
pub fn hotplug_disk(path: &str) -> Result<DiskHotplugPlan> {
    hotplug_disk_path(Path::new(path), false)
}

pub fn hotplug_disk_path(path: &Path, read_only: bool) -> Result<DiskHotplugPlan> {
    if path.as_os_str().is_empty() {
        return Err(FluxError::Unsupported("hotplug disk path is empty".into()));
    }
    let meta = std::fs::metadata(path).map_err(|e| {
        FluxError::Unsupported(format!(
            "hotplug disk {}: {e}",
            path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(FluxError::Unsupported(format!(
            "hotplug disk {} is not a regular file",
            path.display()
        )));
    }
    if meta.len() == 0 {
        return Err(FluxError::Unsupported(format!(
            "hotplug disk {} is empty",
            path.display()
        )));
    }
    Ok(DiskHotplugPlan {
        path: path.to_path_buf(),
        read_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn plans_cpu_hotplug_within_max() {
        let p = plan_add_vcpu(2, 8, 2).unwrap();
        assert_eq!(p.next_id, 2);
        assert_eq!(p.add, 2);
    }

    #[test]
    fn rejects_cpu_over_max() {
        assert!(plan_add_vcpu(7, 8, 2).is_err());
        assert!(plan_add_vcpu(1, 8, 0).is_err());
    }

    #[test]
    fn remove_vcpu_is_explicit_unsupported() {
        assert!(remove_vcpu(1).is_err());
    }

    #[test]
    fn hotplug_disk_requires_nonempty_file() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "disk").unwrap();
        let plan = hotplug_disk(f.path().to_str().unwrap()).unwrap();
        assert_eq!(plan.path, f.path());
        assert!(hotplug_disk("/no/such/disk.img").is_err());
        assert!(hotplug_disk("").is_err());
    }
}
