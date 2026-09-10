// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Lab-only in-tree KVM memory + vCPU snapshot format (`FLUXKVM1`).
//!
//! Not Firecracker-compatible. Device (virtio) live state is not captured —
//! restore re-attaches disks/TAP from boot config and reloads guest RAM +
//! GPRs/sregs. Suitable for warm-pool density experiments, not FC parity.

use crate::error::{FluxError, Result};
use crate::kvm::{KvmRegs, KvmSregs, KvmVm};
use crate::memory::GuestMemory;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"FLUXKVM1";
pub const VERSION: u32 = 1;

/// Cross-thread snapshot request handled inside the vCPU run loop.
pub struct SnapCmd {
    pub vmstate: std::path::PathBuf,
    pub mem: std::path::PathBuf,
    pub reply: std::sync::mpsc::SyncSender<std::result::Result<(), String>>,
}

pub fn is_flux_kvm_vmstate(path: &Path) -> bool {
    let mut buf = [0u8; 8];
    match File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => &buf == MAGIC,
        Err(_) => false,
    }
}

pub fn dump(kvm: &KvmVm, mem: &GuestMemory, vmstate: &Path, mem_path: &Path) -> Result<()> {
    if let Some(parent) = mem_path.parent() {
        fs::create_dir_all(parent).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    }
    if let Some(parent) = vmstate.parent() {
        fs::create_dir_all(parent).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    }
    fs::write(mem_path, mem.as_slice()).map_err(|e| FluxError::Hypervisor(e.to_string()))?;

    // Snapshot/restore is BSP-only (vCPU 0); extending to N vCPUs is
    // separate, out-of-scope follow-up work (see fluxvm-hypervisor SMP plan).
    let regs = kvm.get_regs(0)?;
    let sregs = kvm.get_sregs(0)?;
    let mut f = File::create(vmstate).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(MAGIC)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(&VERSION.to_le_bytes())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(&(mem.len() as u64).to_le_bytes())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    // SAFETY: KvmRegs / KvmSregs are #[repr(C)] POD ioctl mirrors.
    unsafe {
        let regs_bytes = std::slice::from_raw_parts(
            (&regs as *const KvmRegs) as *const u8,
            std::mem::size_of::<KvmRegs>(),
        );
        let sregs_bytes = std::slice::from_raw_parts(
            (&sregs as *const KvmSregs) as *const u8,
            std::mem::size_of::<KvmSregs>(),
        );
        f.write_all(regs_bytes)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.write_all(sregs_bytes)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    }
    f.sync_all()
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    Ok(())
}

#[derive(Clone)]
pub struct CpuSnapshot {
    pub mem_len: u64,
    pub regs: KvmRegs,
    pub sregs: KvmSregs,
}

pub fn load_cpu(vmstate: &Path) -> Result<CpuSnapshot> {
    let mut f = File::open(vmstate).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    if &magic != MAGIC {
        return Err(FluxError::Hypervisor(
            "not a FluxVM in-tree KVM vmstate (expected FLUXKVM1)".into(),
        ));
    }
    let mut ver = [0u8; 4];
    f.read_exact(&mut ver)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let version = u32::from_le_bytes(ver);
    if version != VERSION {
        return Err(FluxError::Hypervisor(format!(
            "unsupported KVM vmstate version {version}"
        )));
    }
    let mut lenb = [0u8; 8];
    f.read_exact(&mut lenb)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let mem_len = u64::from_le_bytes(lenb);
    let mut regs = unsafe { std::mem::zeroed::<KvmRegs>() };
    let mut sregs = unsafe { std::mem::zeroed::<KvmSregs>() };
    unsafe {
        let regs_bytes = std::slice::from_raw_parts_mut(
            (&mut regs as *mut KvmRegs) as *mut u8,
            std::mem::size_of::<KvmRegs>(),
        );
        let sregs_bytes = std::slice::from_raw_parts_mut(
            (&mut sregs as *mut KvmSregs) as *mut u8,
            std::mem::size_of::<KvmSregs>(),
        );
        f.read_exact(regs_bytes)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.read_exact(sregs_bytes)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    }
    Ok(CpuSnapshot {
        mem_len,
        regs,
        sregs,
    })
}

pub fn load_memory_into(mem: &mut GuestMemory, mem_path: &Path) -> Result<()> {
    let data = fs::read(mem_path).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    if data.len() > mem.len() {
        return Err(FluxError::Hypervisor(format!(
            "snapshot mem {} bytes exceeds guest RAM {}",
            data.len(),
            mem.len()
        )));
    }
    mem.as_slice_mut()[..data.len()].copy_from_slice(&data);
    if data.len() < mem.len() {
        mem.as_slice_mut()[data.len()..].fill(0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_non_flux_magic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.vmstate");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"NOTFLUX1").unwrap();
        assert!(!is_flux_kvm_vmstate(&p));
        assert!(load_cpu(&p).is_err());
    }

    #[test]
    fn roundtrip_header_magic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok.vmstate");
        let mut f = File::create(&p).unwrap();
        f.write_all(MAGIC).unwrap();
        f.write_all(&VERSION.to_le_bytes()).unwrap();
        f.write_all(&4096u64.to_le_bytes()).unwrap();
        let regs = unsafe { std::mem::zeroed::<KvmRegs>() };
        let sregs = unsafe { std::mem::zeroed::<KvmSregs>() };
        unsafe {
            f.write_all(std::slice::from_raw_parts(
                (&regs as *const KvmRegs) as *const u8,
                std::mem::size_of::<KvmRegs>(),
            ))
            .unwrap();
            f.write_all(std::slice::from_raw_parts(
                (&sregs as *const KvmSregs) as *const u8,
                std::mem::size_of::<KvmSregs>(),
            ))
            .unwrap();
        }
        assert!(is_flux_kvm_vmstate(&p));
        let cpu = load_cpu(&p).unwrap();
        assert_eq!(cpu.mem_len, 4096);
    }
}
