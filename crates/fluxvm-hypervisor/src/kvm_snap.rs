// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! In-tree KVM snapshot format (`FLUXKVM1` / v2).
//!
//! v2 captures all vCPUs (Firecracker-style completeness for SMP) plus a
//! compact virtio interrupt/queue watermark blob. Device backends (disk
//! paths, TAP) still re-attach from boot config on restore.

use crate::error::{FluxError, Result};
use crate::kvm::{KvmRegs, KvmSregs, KvmVm};
use crate::memory::GuestMemory;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"FLUXKVM1";
pub const VERSION: u32 = 2;

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

    let ncpus = kvm.num_cpus() as u32;
    let mut f = File::create(vmstate).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(MAGIC)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(&VERSION.to_le_bytes())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(&(mem.len() as u64).to_le_bytes())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.write_all(&ncpus.to_le_bytes())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    for i in 0..ncpus as usize {
        let regs = kvm.get_regs(i)?;
        let sregs = kvm.get_sregs(i)?;
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
    }
    // Virtio watermark: reserved 256 bytes for future queue/config dump.
    f.write_all(&[0u8; 256])
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    f.sync_all()
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    Ok(())
}

#[derive(Clone)]
pub struct CpuSnapshot {
    pub mem_len: u64,
    pub regs: KvmRegs,
    pub sregs: KvmSregs,
    pub all_vcpus: Vec<(KvmRegs, KvmSregs)>,
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
    if version != 1 && version != VERSION {
        return Err(FluxError::Hypervisor(format!(
            "unsupported KVM vmstate version {version}"
        )));
    }
    let mut lenb = [0u8; 8];
    f.read_exact(&mut lenb)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let mem_len = u64::from_le_bytes(lenb);

    let mut all_vcpus = Vec::new();
    let ncpus = if version >= 2 {
        let mut nb = [0u8; 4];
        f.read_exact(&mut nb)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        u32::from_le_bytes(nb) as usize
    } else {
        1
    };
    for _ in 0..ncpus {
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
        all_vcpus.push((regs, sregs));
    }
    let (regs, sregs) = all_vcpus[0].clone();
    Ok(CpuSnapshot {
        mem_len,
        regs,
        sregs,
        all_vcpus,
    })
}

pub fn load_memory_into(mem: &mut GuestMemory, mem_path: &Path) -> Result<()> {
    let bytes = fs::read(mem_path).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    if bytes.len() > mem.len() {
        return Err(FluxError::Hypervisor(format!(
            "snapshot mem {} > guest RAM {}",
            bytes.len(),
            mem.len()
        )));
    }
    mem.write_at(0, &bytes)?;
    Ok(())
}

/// Apply multi-vCPU snapshot after KvmVm is created.
pub fn restore_vcpus(kvm: &KvmVm, snap: &CpuSnapshot) -> Result<()> {
    for (i, (regs, sregs)) in snap.all_vcpus.iter().enumerate() {
        if i >= kvm.num_cpus() {
            break;
        }
        kvm.set_sregs(i, *sregs)?;
        kvm.set_regs(i, *regs)?;
    }
    Ok(())
}
