// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Full-fidelity KVM state for `FLUXKVM1` v5 snapshots.
//!
//! v2-v4 snapshots carried only general and special registers (plus MP
//! state), so a restored guest resumed with a fresh LAPIC, no FPU/XSAVE state,
//! default MSRs (TSC, kvm-clock, syscall, EFER...), a reset PIC/IOAPIC/PIT and
//! a new KVM clock. v5 appends tagged, length-prefixed sections that hold what
//! Firecracker and Cloud Hypervisor save:
//!
//! - per vCPU: XSAVE, XCRS, MSRs, LAPIC, VCPU_EVENTS, DEBUGREGS, TSC kHz;
//! - per VM: KVM clock, IRQCHIP (PIC master/slave, IOAPIC) and PIT2.
//!
//! Sections are `[tag u32][len u32][payload]`, little endian, running to the
//! end of the file. Unknown tags are skipped, every length is bounds-checked,
//! and duplicate sections are rejected. Blobs that KVM defines as fixed-size
//! structs are stored raw and validated by length; only the MSR list is
//! structured.

use crate::error::{FluxError, Result};
use crate::ffi;
use crate::kvm::KvmVm;
use std::io::{Read, Write};
use std::os::raw::c_void;

const TAG_XSAVE: u32 = 0x01;
const TAG_XCRS: u32 = 0x02;
const TAG_MSRS: u32 = 0x03;
const TAG_LAPIC: u32 = 0x04;
const TAG_EVENTS: u32 = 0x05;
const TAG_DEBUGREGS: u32 = 0x06;
const TAG_TSC_KHZ: u32 = 0x07;
const TAG_CLOCK: u32 = 0x10;
const TAG_IRQCHIP: u32 = 0x11;
const TAG_PIT2: u32 = 0x12;

const XSAVE_MIN: usize = 4096;
const XCRS_LEN: usize = 392;
const EVENTS_LEN: usize = 64;
const DEBUGREGS_LEN: usize = 128;
const LAPIC_LEN: usize = 1024;
const CLOCK_LEN: usize = 48;
const IRQCHIP_LEN: usize = 520;
const PIT2_LEN: usize = 112;
const MAX_SECTION_BYTES: usize = 1 << 20;
const MAX_MSRS: usize = 4096;
const MSR_ENTRY_LEN: usize = 16;
/// PIC master, PIC slave, IOAPIC.
const IRQCHIP_IDS: [u32; 3] = [0, 1, 2];

/// Everything KVM keeps per vCPU beyond regs/sregs/MP state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VcpuState {
    pub xsave: Vec<u8>,
    pub xcrs: Vec<u8>,
    pub msrs: Vec<(u32, u64)>,
    pub lapic: Vec<u8>,
    pub events: Vec<u8>,
    pub debugregs: Vec<u8>,
    /// 0 when the host could not report it.
    pub tsc_khz: u32,
}

impl VcpuState {
    /// The pieces a restore cannot do without.
    pub fn is_complete(&self) -> bool {
        self.xsave.len() >= XSAVE_MIN && self.lapic.len() == LAPIC_LEN && !self.msrs.is_empty()
    }
}

/// VM-wide interrupt-controller, timer and clock state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmState {
    pub clock: Vec<u8>,
    /// One raw `struct kvm_irqchip` per entry of [`IRQCHIP_IDS`].
    pub irqchips: Vec<Vec<u8>>,
    pub pit2: Vec<u8>,
}

impl VmState {
    pub fn is_complete(&self) -> bool {
        self.clock.len() == CLOCK_LEN
            && self.irqchips.len() == IRQCHIP_IDS.len()
            && self.irqchips.iter().all(|c| c.len() == IRQCHIP_LEN)
            && self.pit2.len() == PIT2_LEN
    }
}

fn hv(msg: impl Into<String>) -> FluxError {
    FluxError::Hypervisor(msg.into())
}

fn ioctl(fd: i32, req: std::os::raw::c_ulong, arg: *mut c_void, what: &str) -> Result<i32> {
    let rc = unsafe { ffi::flux_ioctl(fd, req, arg) };
    if rc < 0 {
        return Err(hv(format!("{what} failed (errno {})", unsafe {
            ffi::flux_errno()
        })));
    }
    Ok(rc)
}

// ---------------------------------------------------------------- capture

fn get_blob(fd: i32, req: std::os::raw::c_ulong, len: usize, what: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    ioctl(fd, req, buf.as_mut_ptr() as *mut c_void, what)?;
    Ok(buf)
}

/// Indices KVM saves/restores (`KVM_GET_MSR_INDEX_LIST`).
fn msr_index_list(kvm: &KvmVm) -> Result<Vec<u32>> {
    // First call with nmsrs = 0 fails with E2BIG and reports the count.
    let mut probe = [0u32; 1];
    unsafe {
        ffi::flux_ioctl(
            kvm.kvm_fd,
            ffi::KVM_GET_MSR_INDEX_LIST,
            probe.as_mut_ptr() as *mut c_void,
        );
    }
    let n = probe[0] as usize;
    if n == 0 || n > MAX_MSRS {
        return Err(hv(format!("KVM reports {n} MSRs to save")));
    }
    let mut buf = vec![0u32; 1 + n];
    buf[0] = n as u32;
    ioctl(
        kvm.kvm_fd,
        ffi::KVM_GET_MSR_INDEX_LIST,
        buf.as_mut_ptr() as *mut c_void,
        "KVM_GET_MSR_INDEX_LIST",
    )?;
    let got = (buf[0] as usize).min(n);
    Ok(buf[1..1 + got].to_vec())
}

/// `KVM_GET_MSRS` stops at the first MSR it cannot read and returns how many
/// it did read, so skip the failing one and continue with the rest.
fn read_msrs(vcpu_fd: i32, indices: &[u32]) -> Result<Vec<(u32, u64)>> {
    let mut out = Vec::with_capacity(indices.len());
    let mut rest = indices;
    while !rest.is_empty() {
        let mut buf = vec![0u8; 8 + MSR_ENTRY_LEN * rest.len()];
        buf[..4].copy_from_slice(&(rest.len() as u32).to_le_bytes());
        for (i, idx) in rest.iter().enumerate() {
            let o = 8 + i * MSR_ENTRY_LEN;
            buf[o..o + 4].copy_from_slice(&idx.to_le_bytes());
        }
        let done = ioctl(
            vcpu_fd,
            ffi::KVM_GET_MSRS,
            buf.as_mut_ptr() as *mut c_void,
            "KVM_GET_MSRS",
        )? as usize;
        for i in 0..done.min(rest.len()) {
            let o = 8 + i * MSR_ENTRY_LEN;
            let idx = u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
            let data = u64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap());
            out.push((idx, data));
        }
        rest = &rest[(done + 1).min(rest.len())..];
    }
    Ok(out)
}

/// Same skip-and-continue rule for `KVM_SET_MSRS`; returns how many were
/// rejected (read-only or unsupported on this host).
fn write_msrs(vcpu_fd: i32, msrs: &[(u32, u64)]) -> Result<usize> {
    let mut skipped = 0;
    let mut rest = msrs;
    while !rest.is_empty() {
        let mut buf = vec![0u8; 8 + MSR_ENTRY_LEN * rest.len()];
        buf[..4].copy_from_slice(&(rest.len() as u32).to_le_bytes());
        for (i, (idx, data)) in rest.iter().enumerate() {
            let o = 8 + i * MSR_ENTRY_LEN;
            buf[o..o + 4].copy_from_slice(&idx.to_le_bytes());
            buf[o + 8..o + 16].copy_from_slice(&data.to_le_bytes());
        }
        let done = ioctl(
            vcpu_fd,
            ffi::KVM_SET_MSRS,
            buf.as_mut_ptr() as *mut c_void,
            "KVM_SET_MSRS",
        )? as usize;
        if done < rest.len() {
            skipped += 1;
        }
        rest = &rest[(done + 1).min(rest.len())..];
    }
    Ok(skipped)
}

fn xsave_len(kvm: &KvmVm) -> (usize, bool) {
    let n = unsafe {
        ffi::flux_ioctl(
            kvm.vm_fd,
            ffi::KVM_CHECK_EXTENSION,
            ffi::KVM_CAP_XSAVE2 as *mut c_void,
        )
    };
    if n > XSAVE_MIN as i32 {
        (n as usize, true)
    } else {
        (XSAVE_MIN, false)
    }
}

/// Capture one vCPU. The vCPU must be out of `KVM_RUN` (paused).
pub fn capture_vcpu(kvm: &KvmVm, idx: usize, msr_list: &[u32]) -> Result<VcpuState> {
    let fd = kvm.vcpus[idx].fd;
    let (xlen, xsave2) = xsave_len(kvm);
    let xsave = get_blob(
        fd,
        if xsave2 {
            ffi::KVM_GET_XSAVE2
        } else {
            ffi::KVM_GET_XSAVE
        },
        xlen,
        "KVM_GET_XSAVE",
    )?;
    let tsc_khz = unsafe { ffi::flux_ioctl(fd, ffi::KVM_GET_TSC_KHZ, std::ptr::null_mut()) };
    Ok(VcpuState {
        xsave,
        xcrs: get_blob(fd, ffi::KVM_GET_XCRS, XCRS_LEN, "KVM_GET_XCRS")?,
        msrs: read_msrs(fd, msr_list)?,
        lapic: get_blob(fd, ffi::KVM_GET_LAPIC, LAPIC_LEN, "KVM_GET_LAPIC")?,
        events: get_blob(
            fd,
            ffi::KVM_GET_VCPU_EVENTS,
            EVENTS_LEN,
            "KVM_GET_VCPU_EVENTS",
        )?,
        debugregs: get_blob(
            fd,
            ffi::KVM_GET_DEBUGREGS,
            DEBUGREGS_LEN,
            "KVM_GET_DEBUGREGS",
        )?,
        tsc_khz: tsc_khz.max(0) as u32,
    })
}

pub fn capture_vm(kvm: &KvmVm) -> Result<VmState> {
    let clock = get_blob(kvm.vm_fd, ffi::KVM_GET_CLOCK, CLOCK_LEN, "KVM_GET_CLOCK")?;
    let mut irqchips = Vec::new();
    for id in IRQCHIP_IDS {
        let mut buf = vec![0u8; IRQCHIP_LEN];
        buf[..4].copy_from_slice(&id.to_le_bytes());
        ioctl(
            kvm.vm_fd,
            ffi::KVM_GET_IRQCHIP,
            buf.as_mut_ptr() as *mut c_void,
            "KVM_GET_IRQCHIP",
        )?;
        irqchips.push(buf);
    }
    let pit2 = get_blob(kvm.vm_fd, ffi::KVM_GET_PIT2, PIT2_LEN, "KVM_GET_PIT2")?;
    Ok(VmState {
        clock,
        irqchips,
        pit2,
    })
}

/// Capture every vCPU plus the VM-wide state.
pub fn capture(kvm: &KvmVm) -> Result<(Vec<VcpuState>, VmState)> {
    let msr_list = msr_index_list(kvm)?;
    let mut vcpus = Vec::with_capacity(kvm.num_cpus());
    for i in 0..kvm.num_cpus() {
        vcpus.push(capture_vcpu(kvm, i, &msr_list)?);
    }
    Ok((vcpus, capture_vm(kvm)?))
}

// ---------------------------------------------------------------- restore

fn set_blob(fd: i32, req: std::os::raw::c_ulong, data: &[u8], what: &str) -> Result<()> {
    let mut buf = data.to_vec();
    ioctl(fd, req, buf.as_mut_ptr() as *mut c_void, what)?;
    Ok(())
}

/// VM-wide state first (Firecracker's order), then each vCPU.
pub fn apply_vm(kvm: &KvmVm, vm: &VmState) -> Result<()> {
    // `struct kvm_clock_data { u64 clock; u32 flags; ... }`. With
    // KVM_CLOCK_REALTIME (4) set, KVM advances the guest clock by the wall time
    // between save and restore: a snapshot restored hours later would hand the
    // guest a multi-hour monotonic jump (soft-lockup and RCU stall warnings).
    // Clear REALTIME and HOST_TSC (8) so the guest resumes from the instant it
    // was paused, like a VM that was merely stopped; wall-clock catch-up is the
    // guest's NTP/agent job.
    let mut clock = vm.clock.clone();
    let flags = u32::from_le_bytes(clock[8..12].try_into().unwrap()) & !(4 | 8);
    clock[8..12].copy_from_slice(&flags.to_le_bytes());
    set_blob(kvm.vm_fd, ffi::KVM_SET_CLOCK, &clock, "KVM_SET_CLOCK")?;
    for chip in &vm.irqchips {
        set_blob(kvm.vm_fd, ffi::KVM_SET_IRQCHIP, chip, "KVM_SET_IRQCHIP")?;
    }
    set_blob(kvm.vm_fd, ffi::KVM_SET_PIT2, &vm.pit2, "KVM_SET_PIT2")
}

/// Apply one vCPU's state. Call after `set_sregs`/`set_regs`. The TSC
/// frequency is set right before the MSRs so the TSC MSR write is scaled.
pub fn apply_vcpu(kvm: &KvmVm, idx: usize, st: &VcpuState) -> Result<()> {
    let fd = kvm.vcpus[idx].fd;
    set_blob(fd, ffi::KVM_SET_XSAVE, &st.xsave, "KVM_SET_XSAVE")?;
    set_blob(fd, ffi::KVM_SET_XCRS, &st.xcrs, "KVM_SET_XCRS")?;
    set_blob(fd, ffi::KVM_SET_LAPIC, &st.lapic, "KVM_SET_LAPIC")?;
    if st.tsc_khz != 0 {
        // Best effort: an unscalable host keeps its own frequency.
        unsafe {
            ffi::flux_ioctl(fd, ffi::KVM_SET_TSC_KHZ, st.tsc_khz as usize as *mut c_void);
        }
    }
    let skipped = write_msrs(fd, &st.msrs)?;
    if skipped > 0 {
        eprintln!(
            "[kvm] vcpu{idx}: {skipped} MSR(s) rejected on restore (read-only or unsupported here)"
        );
    }
    set_blob(
        fd,
        ffi::KVM_SET_VCPU_EVENTS,
        &st.events,
        "KVM_SET_VCPU_EVENTS",
    )?;
    set_blob(
        fd,
        ffi::KVM_SET_DEBUGREGS,
        &st.debugregs,
        "KVM_SET_DEBUGREGS",
    )?;
    // Last step, matching Firecracker's restore order: tell KVM this vCPU's
    // clock just had a long involuntary pause. See the constant's doc comment
    // in ffi.rs for why this specifically matters for multi-vCPU restores.
    // Best-effort -- e.g. EINVAL when the guest never enabled kvm-clock.
    if unsafe { ffi::flux_ioctl(fd, ffi::KVM_KVMCLOCK_CTRL, std::ptr::null_mut()) } < 0 {
        eprintln!(
            "[kvm] vcpu{idx}: KVM_KVMCLOCK_CTRL failed (errno {}); guest clock may be off by the pause duration",
            unsafe { ffi::flux_errno() }
        );
    }
    Ok(())
}

// ------------------------------------------------------------------ codec

fn put_section<W: Write>(w: &mut W, tag: u32, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&tag.to_le_bytes())?;
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(payload)
}

fn with_idx(idx: usize, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.extend_from_slice(&(idx as u32).to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// Append the v5 sections for `vcpus` and `vm`.
pub fn write_sections<W: Write>(
    w: &mut W,
    vcpus: &[VcpuState],
    vm: &VmState,
) -> std::io::Result<()> {
    for (i, v) in vcpus.iter().enumerate() {
        put_section(w, TAG_XSAVE, &with_idx(i, &v.xsave))?;
        put_section(w, TAG_XCRS, &with_idx(i, &v.xcrs))?;
        let mut m = Vec::with_capacity(8 + v.msrs.len() * 12);
        m.extend_from_slice(&(i as u32).to_le_bytes());
        m.extend_from_slice(&(v.msrs.len() as u32).to_le_bytes());
        for (idx, data) in &v.msrs {
            m.extend_from_slice(&idx.to_le_bytes());
            m.extend_from_slice(&data.to_le_bytes());
        }
        put_section(w, TAG_MSRS, &m)?;
        put_section(w, TAG_LAPIC, &with_idx(i, &v.lapic))?;
        put_section(w, TAG_EVENTS, &with_idx(i, &v.events))?;
        put_section(w, TAG_DEBUGREGS, &with_idx(i, &v.debugregs))?;
        put_section(w, TAG_TSC_KHZ, &with_idx(i, &v.tsc_khz.to_le_bytes()))?;
    }
    put_section(w, TAG_CLOCK, &vm.clock)?;
    for c in &vm.irqchips {
        put_section(w, TAG_IRQCHIP, c)?;
    }
    put_section(w, TAG_PIT2, &vm.pit2)
}

fn corrupt(msg: impl Into<String>) -> FluxError {
    hv(format!("corrupt KVM vmstate state section: {}", msg.into()))
}

fn take_idx(payload: &[u8], ncpus: usize) -> Result<(usize, &[u8])> {
    if payload.len() < 4 {
        return Err(corrupt("section shorter than its vCPU index"));
    }
    let idx = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
    if idx >= ncpus {
        return Err(corrupt(format!("vCPU index {idx} >= {ncpus}")));
    }
    Ok((idx, &payload[4..]))
}

fn exact(data: &[u8], want: usize, what: &str) -> Result<Vec<u8>> {
    if data.len() != want {
        return Err(corrupt(format!(
            "{what} is {} bytes, expected {want}",
            data.len()
        )));
    }
    Ok(data.to_vec())
}

fn set_once<T: Default + PartialEq>(slot: &mut T, val: T, what: &str) -> Result<()> {
    if *slot != T::default() {
        return Err(corrupt(format!("duplicate {what} section")));
    }
    *slot = val;
    Ok(())
}

/// Read v5 sections to end of file for a snapshot with `ncpus` vCPUs.
/// Returns empty per-vCPU states if the file has no sections at all.
pub fn read_sections<R: Read>(r: &mut R, ncpus: usize) -> Result<(Vec<VcpuState>, VmState)> {
    let mut vcpus = vec![VcpuState::default(); ncpus];
    let mut vm = VmState::default();
    let max_records = ncpus * 8 + 16;
    for _ in 0..max_records {
        let mut hdr = [0u8; 8];
        let n = r.read(&mut hdr[..1]).map_err(|e| hv(e.to_string()))?;
        if n == 0 {
            return Ok((vcpus, vm));
        }
        r.read_exact(&mut hdr[1..])
            .map_err(|_| corrupt("truncated section header"))?;
        let tag = u32::from_le_bytes(hdr[..4].try_into().unwrap());
        let len = u32::from_le_bytes(hdr[4..].try_into().unwrap()) as usize;
        if len > MAX_SECTION_BYTES {
            return Err(corrupt(format!("section {tag:#x} claims {len} bytes")));
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload)
            .map_err(|_| corrupt(format!("section {tag:#x} truncated")))?;
        match tag {
            TAG_XSAVE => {
                let (i, d) = take_idx(&payload, ncpus)?;
                if d.len() < XSAVE_MIN {
                    return Err(corrupt("XSAVE area smaller than 4096 bytes"));
                }
                set_once(&mut vcpus[i].xsave, d.to_vec(), "XSAVE")?;
            }
            TAG_XCRS => {
                let (i, d) = take_idx(&payload, ncpus)?;
                set_once(&mut vcpus[i].xcrs, exact(d, XCRS_LEN, "XCRS")?, "XCRS")?;
            }
            TAG_MSRS => {
                let (i, d) = take_idx(&payload, ncpus)?;
                if d.len() < 4 {
                    return Err(corrupt("MSR section shorter than its count"));
                }
                let count = u32::from_le_bytes(d[..4].try_into().unwrap()) as usize;
                if count > MAX_MSRS || d.len() != 4 + count * 12 {
                    return Err(corrupt(format!(
                        "MSR count {count} does not match its size"
                    )));
                }
                let msrs = (0..count)
                    .map(|k| {
                        let o = 4 + k * 12;
                        (
                            u32::from_le_bytes(d[o..o + 4].try_into().unwrap()),
                            u64::from_le_bytes(d[o + 4..o + 12].try_into().unwrap()),
                        )
                    })
                    .collect::<Vec<_>>();
                set_once(&mut vcpus[i].msrs, msrs, "MSRS")?;
            }
            TAG_LAPIC => {
                let (i, d) = take_idx(&payload, ncpus)?;
                set_once(&mut vcpus[i].lapic, exact(d, LAPIC_LEN, "LAPIC")?, "LAPIC")?;
            }
            TAG_EVENTS => {
                let (i, d) = take_idx(&payload, ncpus)?;
                set_once(
                    &mut vcpus[i].events,
                    exact(d, EVENTS_LEN, "EVENTS")?,
                    "EVENTS",
                )?;
            }
            TAG_DEBUGREGS => {
                let (i, d) = take_idx(&payload, ncpus)?;
                set_once(
                    &mut vcpus[i].debugregs,
                    exact(d, DEBUGREGS_LEN, "DEBUGREGS")?,
                    "DEBUGREGS",
                )?;
            }
            TAG_TSC_KHZ => {
                let (i, d) = take_idx(&payload, ncpus)?;
                let khz = u32::from_le_bytes(exact(d, 4, "TSC kHz")?.try_into().unwrap());
                set_once(&mut vcpus[i].tsc_khz, khz, "TSC kHz")?;
            }
            TAG_CLOCK => set_once(&mut vm.clock, exact(&payload, CLOCK_LEN, "CLOCK")?, "CLOCK")?,
            TAG_IRQCHIP => {
                let chip = exact(&payload, IRQCHIP_LEN, "IRQCHIP")?;
                let id = u32::from_le_bytes(chip[..4].try_into().unwrap());
                if !IRQCHIP_IDS.contains(&id) {
                    return Err(corrupt(format!("unknown irqchip id {id}")));
                }
                if vm
                    .irqchips
                    .iter()
                    .any(|c| u32::from_le_bytes(c[..4].try_into().unwrap()) == id)
                {
                    return Err(corrupt(format!("duplicate IRQCHIP {id} section")));
                }
                vm.irqchips.push(chip);
            }
            TAG_PIT2 => set_once(&mut vm.pit2, exact(&payload, PIT2_LEN, "PIT2")?, "PIT2")?,
            _ => {} // unknown tag from a newer writer: skipped
        }
    }
    Err(corrupt("too many sections"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real KVM: capture a fresh 2-vCPU VM, apply it back, capture again.
    /// Skips (does not fail) where /dev/kvm is unusable, e.g. CI without KVM.
    #[cfg(target_os = "linux")]
    #[test]
    fn capture_and_apply_round_trip_on_real_kvm() {
        let usable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
        if !usable {
            eprintln!("skipping: /dev/kvm not usable");
            return;
        }
        let mem = crate::memory::GuestMemory::allocate(16 << 20).unwrap();
        let Ok(kvm) = KvmVm::create(&mem, 2) else {
            eprintln!("skipping: KvmVm::create failed");
            return;
        };
        let (v, vm) = capture(&kvm).unwrap();
        assert_eq!(v.len(), 2);
        assert!(
            v.iter().all(VcpuState::is_complete),
            "vCPU state incomplete"
        );
        assert!(vm.is_complete(), "VM state incomplete");
        assert!(v[0].msrs.len() > 10, "expected a real MSR list");
        apply_vm(&kvm, &vm).unwrap();
        for (i, st) in v.iter().enumerate() {
            apply_vcpu(&kvm, i, st).unwrap();
        }
        let (v2, _) = capture(&kvm).unwrap();
        assert_eq!(v2[0].xcrs, v[0].xcrs);
        assert_eq!(v2[0].debugregs, v[0].debugregs);
    }

    fn sample_vcpu(seed: u8) -> VcpuState {
        VcpuState {
            xsave: vec![seed; XSAVE_MIN],
            xcrs: vec![seed.wrapping_add(1); XCRS_LEN],
            msrs: vec![
                (0x10, 0x1234_5678_9abc),
                (0xc000_0080, 0xd01),
                (0x4b56_4d01, 7),
            ],
            lapic: vec![seed.wrapping_add(2); LAPIC_LEN],
            events: vec![seed.wrapping_add(3); EVENTS_LEN],
            debugregs: vec![seed.wrapping_add(4); DEBUGREGS_LEN],
            tsc_khz: 2_899_999,
        }
    }

    fn sample_vm() -> VmState {
        VmState {
            clock: vec![9; CLOCK_LEN],
            irqchips: IRQCHIP_IDS
                .iter()
                .map(|id| {
                    let mut c = vec![0x5a; IRQCHIP_LEN];
                    c[..4].copy_from_slice(&id.to_le_bytes());
                    c
                })
                .collect(),
            pit2: vec![3; PIT2_LEN],
        }
    }

    fn encode(vcpus: &[VcpuState], vm: &VmState) -> Vec<u8> {
        let mut b = Vec::new();
        write_sections(&mut b, vcpus, vm).unwrap();
        b
    }

    #[test]
    fn sections_round_trip() {
        let vcpus = vec![sample_vcpu(1), sample_vcpu(2)];
        let vm = sample_vm();
        let bytes = encode(&vcpus, &vm);
        let (got_v, got_vm) = read_sections(&mut bytes.as_slice(), 2).unwrap();
        assert_eq!(got_v, vcpus);
        assert_eq!(got_vm, vm);
        assert!(got_v.iter().all(VcpuState::is_complete));
        assert!(got_vm.is_complete());
    }

    #[test]
    fn empty_tail_means_no_state() {
        let (v, vm) = read_sections(&mut &[][..], 3).unwrap();
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|s| !s.is_complete()));
        assert!(!vm.is_complete());
    }

    #[test]
    fn unknown_tags_are_skipped() {
        let mut bytes = Vec::new();
        put_section(&mut bytes, 0xdead, &[1, 2, 3, 4, 5]).unwrap();
        bytes.extend(encode(&[sample_vcpu(1)], &sample_vm()));
        put_section(&mut bytes, 0xbeef, &[]).unwrap();
        let (v, vm) = read_sections(&mut bytes.as_slice(), 1).unwrap();
        assert!(v[0].is_complete() && vm.is_complete());
    }

    #[test]
    fn truncated_and_oversized_sections_are_rejected() {
        let bytes = encode(&[sample_vcpu(1)], &sample_vm());
        for cut in [3, 7, 20, bytes.len() - 5] {
            let e = read_sections(&mut &bytes[..cut], 1).unwrap_err();
            assert!(format!("{e}").contains("corrupt"), "cut {cut}: {e}");
        }
        let mut huge = Vec::new();
        huge.extend_from_slice(&TAG_XSAVE.to_le_bytes());
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            format!("{}", read_sections(&mut huge.as_slice(), 1).unwrap_err()).contains("claims")
        );
    }

    #[test]
    fn bad_indices_lengths_duplicates_and_counts_are_rejected() {
        let mut bad_idx = Vec::new();
        put_section(&mut bad_idx, TAG_LAPIC, &with_idx(5, &[0; LAPIC_LEN])).unwrap();
        assert!(read_sections(&mut bad_idx.as_slice(), 2).is_err());

        let mut bad_len = Vec::new();
        put_section(&mut bad_len, TAG_LAPIC, &with_idx(0, &[0; 100])).unwrap();
        assert!(read_sections(&mut bad_len.as_slice(), 1).is_err());

        let mut dup = Vec::new();
        for _ in 0..2 {
            put_section(&mut dup, TAG_LAPIC, &with_idx(0, &[1; LAPIC_LEN])).unwrap();
        }
        assert!(
            format!("{}", read_sections(&mut dup.as_slice(), 1).unwrap_err()).contains("duplicate")
        );

        let mut bad_msrs = Vec::new();
        let mut p = 0u32.to_le_bytes().to_vec();
        p.extend_from_slice(&1000u32.to_le_bytes());
        put_section(&mut bad_msrs, TAG_MSRS, &p).unwrap();
        assert!(read_sections(&mut bad_msrs.as_slice(), 1).is_err());

        let mut bad_chip = Vec::new();
        let mut c = vec![0u8; IRQCHIP_LEN];
        c[..4].copy_from_slice(&9u32.to_le_bytes());
        put_section(&mut bad_chip, TAG_IRQCHIP, &c).unwrap();
        assert!(format!(
            "{}",
            read_sections(&mut bad_chip.as_slice(), 1).unwrap_err()
        )
        .contains("irqchip"));
    }

    #[test]
    fn missing_pieces_are_reported_incomplete() {
        let mut v = sample_vcpu(1);
        v.msrs.clear();
        assert!(!v.is_complete());
        let mut vm = sample_vm();
        vm.irqchips.pop();
        assert!(!vm.is_complete());
    }
}
