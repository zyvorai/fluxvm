// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! In-tree KVM snapshot format (`FLUXKVM1` / v2–v3).
//!
//! - **v2**: all vCPUs + 256-byte reserved virtio watermark (zeros).
//! - **v3**: all vCPUs + packed virtio device live-state (queue rings /
//!   status / features) so restore can reattach backends without cold
//!   re-init of queue pointers. Disk/TAP paths still come from boot config.

use crate::devices::virtio_mmio::{QueueState, VirtioState};
use crate::error::{FluxError, Result};
use crate::kvm::{KvmRegs, KvmSregs, KvmVm};
use crate::memory::GuestMemory;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"FLUXKVM1";
pub const VERSION: u32 = 3;
const V2_WATERMARK: usize = 256;

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

fn write_virtio_v3(f: &mut File, devices: &[VirtioState]) -> Result<()> {
    let ndev = devices.len() as u32;
    f.write_all(&ndev.to_le_bytes())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    for st in devices {
        f.write_all(&st.device_id.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.write_all(&st.features.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.write_all(&st.driver_features.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.write_all(&st.status.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.write_all(&st.interrupt_status.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        f.write_all(&st.num_queues.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        let nq = st.num_queues.min(4) as usize;
        for q in st.queues.iter().take(nq) {
            f.write_all(&q.num.to_le_bytes())
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            f.write_all(&q.ready.to_le_bytes())
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            f.write_all(&q.desc.to_le_bytes())
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            f.write_all(&q.avail.to_le_bytes())
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            f.write_all(&q.used.to_le_bytes())
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            f.write_all(&q.last_avail.to_le_bytes())
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        }
    }
    Ok(())
}

fn read_virtio_v3(f: &mut File) -> Result<Vec<VirtioState>> {
    let mut nb = [0u8; 4];
    f.read_exact(&mut nb)
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let ndev = u32::from_le_bytes(nb) as usize;
    let mut out = Vec::with_capacity(ndev);
    for _ in 0..ndev {
        let mut st = VirtioState::default();
        let mut u32b = [0u8; 4];
        let mut u64b = [0u8; 8];
        let mut u16b = [0u8; 2];
        f.read_exact(&mut u32b)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        st.device_id = u32::from_le_bytes(u32b);
        f.read_exact(&mut u64b)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        st.features = u64::from_le_bytes(u64b);
        f.read_exact(&mut u64b)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        st.driver_features = u64::from_le_bytes(u64b);
        f.read_exact(&mut u32b)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        st.status = u32::from_le_bytes(u32b);
        f.read_exact(&mut u32b)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        st.interrupt_status = u32::from_le_bytes(u32b);
        f.read_exact(&mut u32b)
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        st.num_queues = u32::from_le_bytes(u32b).min(4);
        for i in 0..st.num_queues as usize {
            let mut q = QueueState::default();
            f.read_exact(&mut u32b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            q.num = u32::from_le_bytes(u32b);
            f.read_exact(&mut u32b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            q.ready = u32::from_le_bytes(u32b);
            f.read_exact(&mut u64b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            q.desc = u64::from_le_bytes(u64b);
            f.read_exact(&mut u64b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            q.avail = u64::from_le_bytes(u64b);
            f.read_exact(&mut u64b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            q.used = u64::from_le_bytes(u64b);
            f.read_exact(&mut u16b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            q.last_avail = u16::from_le_bytes(u16b);
            st.queues[i] = q;
        }
        out.push(st);
    }
    Ok(out)
}

pub fn dump(
    kvm: &KvmVm,
    mem: &GuestMemory,
    vmstate: &Path,
    mem_path: &Path,
    virtio: &[VirtioState],
) -> Result<()> {
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
    write_virtio_v3(&mut f, virtio)?;
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
    /// Virtio device live-state from FLUXKVM1 v3 (empty for v1/v2).
    pub virtio: Vec<VirtioState>,
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
    if version != 1 && version != 2 && version != VERSION {
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
    let virtio = if version >= 3 {
        read_virtio_v3(&mut f)?
    } else {
        // v2 reserved watermark — discard.
        let mut pad = [0u8; V2_WATERMARK];
        let _ = f.read_exact(&mut pad);
        Vec::new()
    };
    let (regs, sregs) = all_vcpus[0].clone();
    Ok(CpuSnapshot {
        mem_len,
        regs,
        sregs,
        all_vcpus,
        virtio,
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

/// Overlay packed virtio live-state onto live device backends (matched by
/// `device_id`). Backends (disk path, TAP) stay from boot config.
pub fn restore_virtio(targets: &[&std::sync::Arc<crate::devices::virtio_mmio::VirtioMmio>], snap: &[VirtioState]) {
    for packed in snap {
        for target in targets {
            let Ok(mut live) = target.state.lock() else {
                continue;
            };
            if live.device_id != packed.device_id {
                continue;
            }
            live.features = packed.features;
            live.driver_features = packed.driver_features;
            live.status = packed.status;
            live.interrupt_status = packed.interrupt_status;
            live.num_queues = packed.num_queues;
            let nq = packed.num_queues.min(4) as usize;
            for i in 0..nq {
                live.queues[i] = packed.queues[i].clone();
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio_mmio::{VIRTIO_ID_BLOCK, VIRTIO_ID_NET};

    #[test]
    fn virtio_v3_round_trip_bytes() {
        let mut net = VirtioState::default();
        net.device_id = VIRTIO_ID_NET;
        net.status = 0xf;
        net.queues[0].desc = 0x1000;
        net.queues[0].avail = 0x2000;
        net.queues[0].used = 0x3000;
        net.queues[0].last_avail = 7;
        net.queues[0].ready = 1;
        net.queues[0].num = 256;
        let mut blk = VirtioState::default();
        blk.device_id = VIRTIO_ID_BLOCK;
        blk.num_queues = 1;
        blk.queues[0].desc = 0x4000;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.vmstate");
        {
            let mut f = File::create(&path).unwrap();
            write_virtio_v3(&mut f, &[net.clone(), blk.clone()]).unwrap();
        }
        let mut f = File::open(&path).unwrap();
        let got = read_virtio_v3(&mut f).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].device_id, VIRTIO_ID_NET);
        assert_eq!(got[0].queues[0].last_avail, 7);
        assert_eq!(got[0].queues[0].desc, 0x1000);
        assert_eq!(got[1].device_id, VIRTIO_ID_BLOCK);
        assert_eq!(got[1].queues[0].desc, 0x4000);
    }
}
