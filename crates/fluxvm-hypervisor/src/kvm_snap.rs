// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! In-tree KVM snapshot format (`FLUXKVM1` / v2–v5).
//!
//! - **v2**: all vCPUs + 256-byte reserved virtio watermark (zeros).
//! - **v3**: all vCPUs + packed virtio device live-state (queue rings /
//!   status / features) so restore can reattach backends without cold
//!   re-init of queue pointers. Disk/TAP paths still come from boot config.
//! - **v4**: v3 plus one `KVM_MP_STATE` u32 per vCPU, so restored APs come
//!   back runnable (or still waiting for SIPI) exactly as they were.
//! - **v5**: v4 plus tagged, length-prefixed full-fidelity state (see
//!   [`crate::kvm_state`]): per-vCPU XSAVE/XCRS/MSRs/LAPIC/events/debug regs/TSC
//!   kHz and VM-wide clock/PIC/IOAPIC/PIT. v2-v4 restores are register-only
//!   and log a warning.

use crate::devices::virtio_mmio::{QueueState, VirtioState};
use crate::error::{FluxError, Result};
use crate::kvm::{KvmRegs, KvmSregs, KvmVm};
use crate::kvm_state::{self, VcpuState, VmState};
use crate::memory::GuestMemory;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"FLUXKVM1";
pub const VERSION: u32 = 5;
const V2_WATERMARK: usize = 256;
const MAX_SNAPSHOT_VCPUS: usize = 256;
const MAX_SNAPSHOT_DEVICES: usize = 64;
const MAX_VIRTIO_QUEUES: u32 = crate::devices::virtio_mmio::MAX_QUEUES as u32;

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
    if devices.len() > MAX_SNAPSHOT_DEVICES
        || devices.iter().any(|d| d.num_queues > MAX_VIRTIO_QUEUES)
    {
        return Err(FluxError::Hypervisor(
            "snapshot virtio device or queue count exceeds limit".into(),
        ));
    }
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
        let nq = st.num_queues as usize;
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
    if ndev > MAX_SNAPSHOT_DEVICES {
        return Err(FluxError::Hypervisor(format!(
            "snapshot has too many virtio devices: {ndev}"
        )));
    }
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
        st.num_queues = u32::from_le_bytes(u32b);
        if st.num_queues > MAX_VIRTIO_QUEUES {
            return Err(FluxError::Hypervisor(format!(
                "snapshot has too many virtio queues: {}",
                st.num_queues
            )));
        }
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
    if ncpus == 0 || ncpus as usize > MAX_SNAPSHOT_VCPUS {
        return Err(FluxError::Hypervisor(format!(
            "unsupported snapshot vCPU count: {ncpus}"
        )));
    }
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
    for i in 0..ncpus as usize {
        f.write_all(&kvm.get_mp_state(i)?.to_le_bytes())
            .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    }
    // v5: full-fidelity vCPU and VM state (the vCPUs are parked by now).
    let (vcpu_states, vm_state) = kvm_state::capture(kvm)?;
    kvm_state::write_sections(&mut f, &vcpu_states, &vm_state)
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
    /// Virtio device live-state from FLUXKVM1 v3 (empty for v1/v2).
    pub virtio: Vec<VirtioState>,
    /// Per-vCPU `KVM_MP_STATE` from v4; empty for older snapshots (which
    /// only ever held one vCPU).
    pub mp_states: Vec<u32>,
    /// On-disk format version.
    pub version: u32,
    /// Per-vCPU full-fidelity state from v5; entries are incomplete
    /// (`!is_complete()`) for older snapshots.
    pub vcpu_states: Vec<VcpuState>,
    /// VM-wide clock/irqchip/PIT state from v5; `None` for older snapshots.
    pub vm_state: Option<VmState>,
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
    if !(1..=VERSION).contains(&version) {
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
    if ncpus == 0 || ncpus > MAX_SNAPSHOT_VCPUS {
        return Err(FluxError::Hypervisor(format!(
            "invalid snapshot vCPU count: {ncpus}"
        )));
    }
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
        if version == 2 {
            f.read_exact(&mut pad)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
        }
        Vec::new()
    };
    let mut mp_states = Vec::new();
    if version >= 4 {
        for _ in 0..ncpus {
            let mut b = [0u8; 4];
            f.read_exact(&mut b)
                .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
            mp_states.push(u32::from_le_bytes(b));
        }
    }
    let (vcpu_states, vm_state) = if version >= 5 {
        let (v, vm) = kvm_state::read_sections(&mut f, ncpus)?;
        (v, Some(vm))
    } else {
        (vec![VcpuState::default(); ncpus], None)
    };
    let (regs, sregs) = all_vcpus[0].clone();
    Ok(CpuSnapshot {
        mem_len,
        regs,
        sregs,
        all_vcpus,
        virtio,
        mp_states,
        version,
        vcpu_states,
        vm_state,
    })
}

pub fn load_memory_into(mem: &mut GuestMemory, mem_path: &Path) -> Result<()> {
    let file = File::open(mem_path).map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    let actual = file
        .metadata()
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?
        .len();
    if actual != mem.len() as u64 {
        return Err(FluxError::Hypervisor(format!(
            "snapshot RAM size {} does not match guest RAM {}",
            actual,
            mem.len()
        )));
    }
    let mut reader = std::io::BufReader::new(file);
    reader
        .read_exact(mem.as_slice_mut())
        .map_err(|e| FluxError::Hypervisor(e.to_string()))?;
    Ok(())
}

/// Apply multi-vCPU snapshot after KvmVm is created.
pub fn restore_vcpus(kvm: &KvmVm, snap: &CpuSnapshot) -> Result<()> {
    if snap.all_vcpus.len() != kvm.num_cpus() {
        return Err(FluxError::Hypervisor(format!(
            "snapshot has {} vCPUs, VM has {}",
            snap.all_vcpus.len(),
            kvm.num_cpus()
        )));
    }
    let full = snap.version >= 5
        && snap.vcpu_states.len() == snap.all_vcpus.len()
        && snap.vcpu_states.iter().all(VcpuState::is_complete)
        && snap.vm_state.as_ref().map_or(false, VmState::is_complete);
    if !full {
        eprintln!(
            "[kvm] vmstate v{} has no full-fidelity state: restoring registers only \
             (LAPIC, MSRs, FPU, clock, irqchip and PIT start fresh)",
            snap.version
        );
    }
    // VM-wide clock/PIC/IOAPIC/PIT first, then each vCPU (Firecracker's order).
    if full {
        if let Some(vm) = &snap.vm_state {
            kvm_state::apply_vm(kvm, vm)?;
        }
    }
    for (i, (regs, sregs)) in snap.all_vcpus.iter().enumerate() {
        kvm.set_sregs(i, *sregs)?;
        kvm.set_regs(i, *regs)?;
        if full {
            kvm_state::apply_vcpu(kvm, i, &snap.vcpu_states[i])?;
        }
    }
    // APs are created UNINITIALIZED; put each back in the state it had when
    // the snapshot was taken (a booted AP must be RUNNABLE or it never runs).
    for (i, state) in snap.mp_states.iter().enumerate().skip(1) {
        kvm.set_mp_state(i, *state)?;
    }
    Ok(())
}

/// Overlay packed virtio live-state onto live device backends (matched by
/// `device_id`). Backends (disk path, TAP) stay from boot config.
///
/// vhost-net holds no state of its own across a restore: the restored
/// queue rings and `last_avail` are what it is programmed from, so the caller
/// (`vm.rs`, once the queue service exists) re-binds it with
/// `QueueService::rebind_vhost_after_restore` rather than waiting for a guest
/// notify that an idle RX queue may never send.
pub fn restore_virtio(
    targets: &[&std::sync::Arc<crate::devices::virtio_mmio::VirtioMmio>],
    snap: &[VirtioState],
) {
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
            let nq = packed.num_queues.min(MAX_VIRTIO_QUEUES) as usize;
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

    fn snapshot_header(version: u32, ncpus: u32) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend_from_slice(&4096u64.to_le_bytes());
        bytes.extend_from_slice(&ncpus.to_le_bytes());
        bytes
    }

    /// A pre-v5 file (registers, empty virtio list, one MP state) must keep
    /// loading, with no full-fidelity state, so old snapshots still restore.
    #[test]
    fn v4_file_still_loads_without_full_state() {
        let mut bytes = snapshot_header(4, 1);
        bytes.extend(vec![
            0u8;
            std::mem::size_of::<KvmRegs>()
                + std::mem::size_of::<KvmSregs>()
        ]);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // virtio device count
        bytes.extend_from_slice(&0u32.to_le_bytes()); // MP state of vCPU 0
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v4.vmstate");
        fs::write(&path, bytes).unwrap();
        let cpu = load_cpu(&path).unwrap();
        assert_eq!(cpu.version, 4);
        assert_eq!(cpu.mp_states, vec![0]);
        assert!(cpu.vm_state.is_none());
        assert!(!cpu.vcpu_states[0].is_complete());
    }

    /// A v5 header with no sections at all loads but is not restorable
    /// (preflight rejects it), rather than silently restoring half a guest.
    #[test]
    fn v5_file_without_sections_loads_as_incomplete() {
        let mut bytes = snapshot_header(5, 1);
        bytes.extend(vec![
            0u8;
            std::mem::size_of::<KvmRegs>()
                + std::mem::size_of::<KvmSregs>()
        ]);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v5.vmstate");
        fs::write(&path, bytes).unwrap();
        let cpu = load_cpu(&path).unwrap();
        assert_eq!(cpu.version, 5);
        assert!(!cpu.vcpu_states[0].is_complete());
        assert!(!cpu.vm_state.unwrap().is_complete());
    }

    #[test]
    fn rejects_zero_and_excessive_vcpu_counts_before_reading_registers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vmstate");
        for count in [0, MAX_SNAPSHOT_VCPUS as u32 + 1, u32::MAX] {
            fs::write(&path, snapshot_header(VERSION, count)).unwrap();
            assert!(format!("{}", load_cpu(&path).err().unwrap()).contains("vCPU count"));
        }
    }

    #[test]
    fn rejects_oversized_virtio_count_and_queue_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("virtio");
        fs::write(&path, (MAX_SNAPSHOT_DEVICES as u32 + 1).to_le_bytes()).unwrap();
        assert!(format!(
            "{}",
            read_virtio_v3(&mut File::open(&path).unwrap())
                .err()
                .unwrap()
        )
        .contains("devices"));

        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&VIRTIO_ID_NET.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8 + 8 + 4 + 4]);
        bytes.extend_from_slice(&(MAX_VIRTIO_QUEUES + 1).to_le_bytes());
        fs::write(&path, bytes).unwrap();
        assert!(format!(
            "{}",
            read_virtio_v3(&mut File::open(&path).unwrap())
                .err()
                .unwrap()
        )
        .contains("queues"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_truncated_ram_without_mutating_guest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mem");
        fs::write(&path, [0x5au8; 2048]).unwrap();
        let mut mem = GuestMemory::allocate(4096).unwrap();
        mem.write_at(0, &[0xa5]).unwrap();
        assert!(
            format!("{}", load_memory_into(&mut mem, &path).err().unwrap())
                .contains("does not match")
        );
        assert_eq!(mem.as_slice()[0], 0xa5);
    }

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
