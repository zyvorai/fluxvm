// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! H4 / P3: live migration state export/import for the in-tree KVM engine.
//!
//! Directory bundle (Cloud Hypervisor–shaped pause/save/restore):
//! ```text
//! <dir>/
//!   vmstate   # FLUXKVM1 (see kvm_snap)
//!   mem       # guest RAM dump
//!   meta.json # optional BootConfig / SnapshotSpec companion
//! ```
//! Pre-copy over the network stays a control-plane concern (Sentinel / API
//! receivers); this module is the VMM-local pause → serialize → restore path.

use crate::devices::virtio_mmio::VirtioState;
use crate::error::{FluxError, Result};
use crate::kvm::KvmVm;
use crate::kvm_snap::{self, CpuSnapshot};
use crate::memory::GuestMemory;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const VMSTATE_NAME: &str = "vmstate";
pub const MEM_NAME: &str = "mem";
pub const META_NAME: &str = "meta.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationMeta {
    pub format: String,
    pub version: u32,
    #[serde(default)]
    pub note: String,
}

impl Default for MigrationMeta {
    fn default() -> Self {
        Self {
            format: "fluxvm-kvm-migration".into(),
            version: 1,
            note: "FLUXKVM1 pause/export bundle".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MigrationBundle {
    pub dir: PathBuf,
    pub vmstate: PathBuf,
    pub mem: PathBuf,
    pub meta: PathBuf,
}

impl MigrationBundle {
    pub fn at(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            vmstate: dir.join(VMSTATE_NAME),
            mem: dir.join(MEM_NAME),
            meta: dir.join(META_NAME),
        }
    }

    pub fn validate_import(&self) -> Result<()> {
        if !self.vmstate.is_file() {
            return Err(FluxError::Unsupported(format!(
                "migration import missing {}",
                self.vmstate.display()
            )));
        }
        if !self.mem.is_file() {
            return Err(FluxError::Unsupported(format!(
                "migration import missing {}",
                self.mem.display()
            )));
        }
        if !kvm_snap::is_flux_kvm_vmstate(&self.vmstate) {
            return Err(FluxError::Unsupported(
                "migration import vmstate is not FLUXKVM1".into(),
            ));
        }
        Ok(())
    }
}

/// Pause-compatible export: write FLUXKVM1 vmstate + guest RAM into `dir`.
/// Caller must ensure vCPUs are not mid-`KVM_RUN` (control path pauses first).
pub fn export_state(
    kvm: &KvmVm,
    mem: &GuestMemory,
    virtio: &[VirtioState],
    dir: &Path,
) -> Result<MigrationBundle> {
    fs::create_dir_all(dir).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let bundle = MigrationBundle::at(dir);
    kvm_snap::dump(kvm, mem, &bundle.vmstate, &bundle.mem, virtio)?;
    let meta = MigrationMeta::default();
    let bytes = serde_json::to_vec_pretty(&meta)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    fs::write(&bundle.meta, bytes).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    Ok(bundle)
}

/// Validate an on-disk bundle and load the CPU snapshot (mem path returned for
/// the restore caller to map).
pub fn import_state(dir: &Path) -> Result<(CpuSnapshot, PathBuf, MigrationBundle)> {
    let bundle = MigrationBundle::at(dir);
    bundle.validate_import()?;
    let cpu = kvm_snap::load_cpu(&bundle.vmstate)?;
    Ok((cpu, bundle.mem.clone(), bundle))
}

/// Compatibility wrappers matching the historical free-function names.
pub fn export_state_path(path: &Path) -> Result<()> {
    if path.exists() && path.is_file() {
        return Err(FluxError::Unsupported(
            "migration export expects a directory path (vmstate+mem bundle)".into(),
        ));
    }
    // Directory must be prepared by a caller that holds KvmVm — without a VM
    // handle we can only validate the path shape.
    fs::create_dir_all(path).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    Ok(())
}

pub fn import_state_path(path: &Path) -> Result<()> {
    MigrationBundle::at(path).validate_import()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn import_rejects_empty_dir() {
        let d = tempdir().unwrap();
        let err = import_state_path(d.path()).unwrap_err();
        assert!(format!("{err}").contains("missing") || format!("{err}").contains("migration"));
    }

    #[test]
    fn export_path_creates_dir() {
        let d = tempdir().unwrap();
        let dest = d.path().join("mig");
        export_state_path(&dest).unwrap();
        assert!(dest.is_dir());
    }

    #[test]
    fn meta_round_trip() {
        let m = MigrationMeta::default();
        let v = serde_json::to_vec(&m).unwrap();
        let back: MigrationMeta = serde_json::from_slice(&v).unwrap();
        assert_eq!(back.format, "fluxvm-kvm-migration");
        assert_eq!(back.version, 1);
    }
}
