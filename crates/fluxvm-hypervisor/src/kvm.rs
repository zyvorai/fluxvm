// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use crate::ffi;
use crate::memory::{self, GuestMemory};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct KvmUserspaceMemoryRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// Raw host CPUID, used only to backfill leaves KVM_GET_SUPPORTED_CPUID
/// zeroes out (e.g. leaf 0x15) despite the host actually supporting them.
#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)] // __cpuid_count's unsafe-ness varies by rustc version
fn host_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let r = unsafe { std::arch::x86_64::__cpuid_count(leaf, subleaf) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// This hypervisor only ever runs on x86_64 (raw KVM ioctls, x86 CPUID) --
/// this fallback exists solely so the crate still type-checks when built
/// for local tooling on a non-x86_64 host (e.g. macOS/arm64 dev machine).
#[cfg(not(target_arch = "x86_64"))]
fn host_cpuid(_leaf: u32, _subleaf: u32) -> (u32, u32, u32, u32) {
    (0, 0, 0, 0)
}

/// One vCPU's KVM file descriptor and its mmap'd `kvm_run` page. Each
/// vCPU's `run` page is a disjoint mmap region, so concurrent `&self`
/// access to *different* indices from different vCPU threads is sound —
/// there is no shared mutable state between vCPUs here, only per-vCPU
/// raw-pointer access that was already unsafe before this struct existed.
pub struct VcpuHandle {
    pub fd: i32,
    pub run: *mut u8,
}

pub struct KvmVm {
    pub kvm_fd: i32,
    pub vm_fd: i32,
    pub vcpus: Vec<VcpuHandle>,
    pub run_size: usize,
    tsc_deadline_supported: bool,
}

unsafe impl Send for KvmVm {}
unsafe impl Sync for KvmVm {}

impl KvmVm {
    pub fn create(mem: &GuestMemory, num_cpus: u8) -> Result<Self> {
        unsafe {
            let path = b"/dev/kvm\0";
            let kvm_fd = ffi::open(path.as_ptr() as *const c_char, ffi::O_RDWR);
            if kvm_fd < 0 {
                return Err(FluxError::Hypervisor("open /dev/kvm failed".into()));
            }
            let ver = ffi::flux_ioctl(kvm_fd, ffi::KVM_GET_API_VERSION, std::ptr::null_mut());
            if ver != 12 {
                return Err(FluxError::Hypervisor(format!("KVM API {ver}, want 12")));
            }
            let vm_fd = ffi::flux_ioctl(kvm_fd, ffi::KVM_CREATE_VM, std::ptr::null_mut());
            if vm_fd < 0 {
                return Err(FluxError::Hypervisor("KVM_CREATE_VM failed".into()));
            }
            let mut region = KvmUserspaceMemoryRegion {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: mem.len() as u64,
                userspace_addr: mem.host_ptr() as u64,
            };
            if ffi::flux_ioctl(
                vm_fd,
                ffi::KVM_SET_USER_MEMORY_REGION,
                &mut region as *mut _ as *mut c_void,
            ) < 0
            {
                return Err(FluxError::Hypervisor("KVM_SET_USER_MEMORY_REGION".into()));
            }
            // Intel VT-x quirk: with an in-kernel irqchip, KVM needs a
            // three-page TSS region in guest phys that does not overlap
            // RAM/MMIO. Firecracker / cloud-hypervisor both call this
            // before CREATE_IRQCHIP; omitting it on this host (Xeon
            // E-2336) left the guest hanging inside late initcalls
            // (init_zbud) while the same kernel booted under FC/CH.
            if ffi::flux_ioctl(
                vm_fd,
                ffi::KVM_SET_TSS_ADDR,
                memory::KVM_TSS_ADDRESS as *mut c_void,
            ) < 0
            {
                return Err(FluxError::Hypervisor("KVM_SET_TSS_ADDR".into()));
            }
            // Real in-kernel LAPIC/IOAPIC/PIC. This is what makes real SMP
            // possible without any userspace INIT-SIPI emulation below: a
            // freshly created non-BSP vCPU on a VM with an irqchip starts
            // KVM_MP_STATE_UNINITIALIZED and blocks in KVM_RUN until KVM's
            // own in-kernel LAPIC delivers the guest's real SIPI. A silent
            // failure here previously produced an indefinite, undiagnosable
            // hang (the exact failure class chased for hours before this
            // fix) -- it's now a real error instead of `let _ =`.
            if ffi::flux_ioctl(vm_fd, ffi::KVM_CREATE_IRQCHIP, std::ptr::null_mut()) < 0 {
                return Err(FluxError::Hypervisor("KVM_CREATE_IRQCHIP".into()));
            }
            // KVM_GET_SUPPORTED_CPUID unconditionally clears CPUID.01H:
            // ECX[24] (TSC_DEADLINE) regardless of whether the host CPU
            // and in-kernel irqchip actually support it -- this capability
            // check is the real source of truth (same technique crosvm
            // uses). Without it the guest falls back to legacy
            // periodic-mode LAPIC timer reprogramming via LVTT/TMICT,
            // which live tracing showed stalling permanently after an
            // initial burst of ticks. TSC-deadline mode uses a single
            // WRMSR per timer event instead, sidestepping that path
            // entirely.
            let tsc_deadline_supported = ffi::flux_ioctl(
                kvm_fd,
                ffi::KVM_CHECK_EXTENSION,
                ffi::KVM_CAP_TSC_DEADLINE_TIMER as *mut c_void,
            ) > 0;
            eprintln!("[kvm] TSC-deadline timer supported: {tsc_deadline_supported}");
            // In-kernel PIT so the guest can calibrate timers / get IRQ0.
            #[repr(C)]
            struct KvmPitConfig {
                flags: u32,
                pad: [u32; 15],
            }
            let mut pit = KvmPitConfig {
                flags: 0,
                pad: [0; 15],
            };
            if ffi::flux_ioctl(
                vm_fd,
                ffi::KVM_CREATE_PIT2,
                &mut pit as *mut _ as *mut c_void,
            ) < 0
            {
                eprintln!(
                    "[kvm] KVM_CREATE_PIT2 optional failed (errno {})",
                    ffi::flux_errno()
                );
            } else {
                eprintln!("[kvm] PIT2 created");
            }

            let mmap_size =
                ffi::flux_ioctl(kvm_fd, ffi::KVM_GET_VCPU_MMAP_SIZE, std::ptr::null_mut());
            if mmap_size <= 0 {
                return Err(FluxError::Hypervisor("KVM_GET_VCPU_MMAP_SIZE".into()));
            }

            let mut vcpus = Vec::with_capacity(num_cpus as usize);
            for id in 0..num_cpus as i32 {
                // KVM_CREATE_VCPU's arg is the vCPU id, which for x86 is
                // also its initial APIC id -- must match the id
                // mptable::write_mptable already writes per-processor
                // entry (mptable.rs's `local_apic_id: i`).
                let vcpu_fd = ffi::flux_ioctl(vm_fd, ffi::KVM_CREATE_VCPU, id as *mut c_void);
                if vcpu_fd < 0 {
                    return Err(FluxError::Hypervisor(format!("KVM_CREATE_VCPU id={id}")));
                }
                let run = ffi::mmap(
                    std::ptr::null_mut(),
                    mmap_size as usize,
                    ffi::PROT_READ | ffi::PROT_WRITE,
                    ffi::MAP_SHARED,
                    vcpu_fd,
                    0,
                );
                if run as usize == ffi::MAP_FAILED {
                    return Err(FluxError::Hypervisor("mmap kvm_run".into()));
                }
                if id != 0 {
                    // A freshly created vCPU defaults to
                    // KVM_MP_STATE_RUNNABLE, not "wait for SIPI" -- left
                    // alone it would immediately execute whatever garbage
                    // sits at the reset vector (no RIP/sregs are ever set
                    // for APs) instead of blocking for the guest's real
                    // INIT-SIPI-SIPI. This is what made the AP thread
                    // block forever in a single KVM_RUN with zero vmexits
                    // (a tight, exit-free decode loop over unmapped/zero
                    // memory) while the BSP spun waiting for it to check
                    // in -- exactly the original hang symptom, just with
                    // the real vCPU now silently running junk instead of
                    // not existing at all.
                    let mut mp_state = ffi::KVM_MP_STATE_UNINITIALIZED;
                    if ffi::flux_ioctl(
                        vcpu_fd,
                        ffi::KVM_SET_MP_STATE,
                        &mut mp_state as *mut _ as *mut c_void,
                    ) < 0
                    {
                        return Err(FluxError::Hypervisor(format!("KVM_SET_MP_STATE id={id}")));
                    }
                }
                vcpus.push(VcpuHandle {
                    fd: vcpu_fd,
                    run: run as *mut u8,
                });
            }

            let this = Self {
                kvm_fd,
                vm_fd,
                vcpus,
                run_size: mmap_size as usize,
                tsc_deadline_supported,
            };
            for id in 0..num_cpus as usize {
                this.setup_cpuid(id)?;
                // Firecracker / cloud-hypervisor per-vCPU boot triad.
                this.setup_boot_msrs(id)?;
                this.setup_fpu(id)?;
                this.set_lint(id)?;
            }
            Ok(this)
        }
    }

    pub fn num_cpus(&self) -> usize {
        self.vcpus.len()
    }

    /// Firecracker `create_boot_msr_entries` / CH `boot_msr_entries` — exact
    /// 11-entry list, applied on every vCPU before first `KVM_RUN`.
    fn setup_boot_msrs(&self, idx: usize) -> Result<()> {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct KvmMsrEntry {
            index: u32,
            reserved: u32,
            data: u64,
        }
        #[repr(C)]
        struct KvmMsrs {
            nmsrs: u32,
            pad: u32,
            entries: [KvmMsrEntry; 11],
        }
        // Indices from arch/x86/include/asm/msr-index.h (same as FC/CH).
        let entries = [
            KvmMsrEntry {
                index: 0x0000_0174, // MSR_IA32_SYSENTER_CS
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0x0000_0175, // MSR_IA32_SYSENTER_ESP
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0x0000_0176, // MSR_IA32_SYSENTER_EIP
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0xc000_0081, // MSR_STAR
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0xc000_0083, // MSR_CSTAR
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0xc000_0102, // MSR_KERNEL_GS_BASE
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0xc000_0084, // MSR_SYSCALL_MASK
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0xc000_0082, // MSR_LSTAR
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0x0000_0010, // MSR_IA32_TSC
                reserved: 0,
                data: 0,
            },
            KvmMsrEntry {
                index: 0x0000_01a0, // MSR_IA32_MISC_ENABLE
                reserved: 0,
                data: 0x1, // FAST_STRING
            },
            KvmMsrEntry {
                index: 0x0000_02ff, // MSR_MTRRdefType
                reserved: 0,
                data: (1 << 11) | 0x6, // enable + write-back
            },
        ];
        let mut msrs = KvmMsrs {
            nmsrs: entries.len() as u32,
            pad: 0,
            entries,
        };
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_MSRS,
                &mut msrs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor(format!("KVM_SET_MSRS vcpu{idx}")));
        }
        Ok(())
    }

    /// Firecracker / CH `setup_fpu`: fcw=0x37f, mxcsr=0x1f80.
    fn setup_fpu(&self, idx: usize) -> Result<()> {
        // linux/kvm.h `struct kvm_fpu` (same fields Firecracker writes).
        #[repr(C)]
        struct KvmFpu {
            fpr: [[u8; 16]; 8],
            fcw: u16,
            fsw: u16,
            ftwx: u8,
            pad1: u8,
            last_opcode: u16,
            last_ip: u64,
            last_dp: u64,
            xmm: [[u8; 16]; 16],
            mxcsr: u32,
            pad2: u32,
        }
        let mut fpu = unsafe { std::mem::zeroed::<KvmFpu>() };
        fpu.fcw = 0x37f;
        fpu.mxcsr = 0x1f80;
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_FPU,
                &mut fpu as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor(format!("KVM_SET_FPU vcpu{idx}")));
        }
        Ok(())
    }

    /// Firecracker / CH `set_lint`: LVT0=EXTINT, LVT1=NMI.
    fn set_lint(&self, idx: usize) -> Result<()> {
        const APIC_LVT0: usize = 0x350;
        const APIC_LVT1: usize = 0x360;
        const APIC_MODE_EXTINT: u32 = 0x7;
        const APIC_MODE_NMI: u32 = 0x4;
        let mut regs = [0u8; 0x400];
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_GET_LAPIC,
                regs.as_mut_ptr() as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor(format!("KVM_GET_LAPIC vcpu{idx}")));
        }
        let patch = |regs: &mut [u8], off: usize, mode: u32| {
            let mut v = u32::from_le_bytes(regs[off..off + 4].try_into().unwrap());
            v = (v & !0x700) | (mode << 8);
            regs[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        patch(&mut regs, APIC_LVT0, APIC_MODE_EXTINT);
        patch(&mut regs, APIC_LVT1, APIC_MODE_NMI);
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_LAPIC,
                regs.as_mut_ptr() as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor(format!("KVM_SET_LAPIC vcpu{idx}")));
        }
        Ok(())
    }

    /// Firecracker `register_irq` — bind an eventfd to a GSI via `KVM_IRQFD`.
    pub fn register_irqfd(&self, eventfd: i32, gsi: u32) -> Result<()> {
        #[repr(C)]
        struct KvmIrqfd {
            fd: u32,
            gsi: u32,
            flags: u32,
            resamplefd: u32,
            pad: [u8; 16],
        }
        let mut irqfd = KvmIrqfd {
            fd: eventfd as u32,
            gsi,
            flags: 0,
            resamplefd: 0,
            pad: [0; 16],
        };
        if unsafe {
            ffi::flux_ioctl(
                self.vm_fd,
                ffi::KVM_IRQFD,
                &mut irqfd as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor(format!(
                "KVM_IRQFD gsi={gsi} fd={eventfd}"
            )));
        }
        eprintln!("[kvm] irqfd gsi={gsi} fd={eventfd}");
        Ok(())
    }

    /// Expose host-supported CPUID leaves to the guest, patched with this
    /// vCPU's own initial APIC id (leaf 1, EBX[31:24]). Without the base
    /// CPUID setup, Linux hits #UD on the first `cpuid` (empty IDT →
    /// triple fault → SHUTDOWN). Without the per-vCPU APIC id patch, every
    /// vCPU would report the same (BSP's) APIC id, and the guest's real
    /// INIT-SIPI addressing (by APIC id, done entirely in-kernel by KVM's
    /// LAPIC model) would never reach the intended AP.
    fn setup_cpuid(&self, idx: usize) -> Result<()> {
        const MAX: usize = 256;
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Entry {
            function: u32,
            index: u32,
            flags: u32,
            eax: u32,
            ebx: u32,
            ecx: u32,
            edx: u32,
            padding: [u32; 3],
        }
        #[repr(C)]
        struct Header {
            nent: u32,
            padding: u32,
        }
        let entry_size = std::mem::size_of::<Entry>();
        let mut buf = vec![0u8; std::mem::size_of::<Header>() + MAX * entry_size];
        let apic_id = idx as u32;
        unsafe {
            let hdr = buf.as_mut_ptr() as *mut Header;
            (*hdr).nent = MAX as u32;
            if ffi::flux_ioctl(
                self.kvm_fd,
                ffi::KVM_GET_SUPPORTED_CPUID,
                buf.as_mut_ptr() as *mut c_void,
            ) < 0
            {
                return Err(FluxError::Hypervisor("KVM_GET_SUPPORTED_CPUID".into()));
            }
            let nent = (*hdr).nent as usize;
            let entries = (buf.as_mut_ptr().add(std::mem::size_of::<Header>())) as *mut Entry;
            for i in 0..nent {
                let e = &mut *entries.add(i);
                if e.function == 0 && e.index == 0 {
                    // A guest's CPUID leaf reader may refuse to query leaf
                    // 0x15 at all if leaf 0's reported max-standard-
                    // function is lower than that (matches crosvm).
                    e.eax = e.eax.max(0x15);
                }
                if e.function == 1 {
                    e.ebx = (e.ebx & 0x00ff_ffff) | (apic_id << 24);
                    // "Hypervisor present" -- always true here, and some
                    // guest-kernel paravirt/topology decisions gate on it
                    // (matches crosvm, which sets this unconditionally).
                    e.ecx |= 1 << 31;
                    if self.tsc_deadline_supported {
                        e.ecx |= 1 << 24;
                    }
                }
                // KVM_GET_SUPPORTED_CPUID always zeroes leaf 0x15 (TSC /
                // "core crystal clock" ratio) even when the host CPU
                // reports it -- confirmed live: this host's raw CPUID.15H
                // is {eax=2,ebx=242,ecx=24000000}, but the KVM-reported
                // "supported" leaf comes back all zero. Without it, Linux
                // can't derive tsc_khz from CPUID and falls back to the
                // legacy PIT/APIC-timer calibration dance
                // (calibrate_APIC_clock), which is what was actually
                // hanging boot (confirmed live: LAPIC periodic-timer
                // interrupts stop arriving partway through calibration,
                // stalling the boot/AP-checkin wait loops that depend on
                // jiffies). The guest's TSC isn't scaled by us (no
                // KVM_SET_TSC_KHZ), so it runs 1:1 with the host TSC and
                // the host's own leaf 0x15 values are valid to hand
                // through directly.
                if e.function == 0x15 && e.eax == 0 && e.ebx == 0 && e.ecx == 0 {
                    let (heax, hebx, hecx, _) = host_cpuid(0x15, 0);
                    if heax != 0 && hebx != 0 && hecx != 0 {
                        e.eax = heax;
                        e.ebx = hebx;
                        e.ecx = hecx;
                    }
                }
            }
            if ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_CPUID2,
                buf.as_mut_ptr() as *mut c_void,
            ) < 0
            {
                return Err(FluxError::Hypervisor("KVM_SET_CPUID2".into()));
            }
            eprintln!("[kvm] vcpu{idx} CPUID leaves={nent} apic_id={apic_id}");
        }
        Ok(())
    }

    /// BSP-only. APs must never go through this: their RIP/CS/segment
    /// state is set entirely by KVM's in-kernel LAPIC when the guest's own
    /// INIT-SIPI-SIPI sequence actually arrives -- writing real register
    /// state here for an AP would race (and likely conflict with) that.
    pub fn setup_long_mode(
        &self,
        mem: &mut GuestMemory,
        rip: u64,
        rsp: u64,
        cr3: u64,
        rsi: u64,
    ) -> Result<()> {
        let idx = 0;
        const GDT: u64 = 0xB000;
        const TSS: u64 = 0xC000;
        mem.write_at(TSS, &[0u8; 128])?;
        // null, code64, data32, tss64 (16-byte descriptor)
        let mut gdt = [0u8; 40];
        gdt[8..16].copy_from_slice(&0x00af_9b00_0000_ffffu64.to_le_bytes());
        gdt[16..24].copy_from_slice(&0x00cf_9300_0000_ffffu64.to_le_bytes());
        let tss_limit = 103u64;
        let tss_low = (tss_limit & 0xffff)
            | ((TSS & 0xff_ffff) << 16)
            | (0x9u64 << 40) // available 64-bit TSS
            | (1u64 << 47) // present
            | (((TSS >> 24) & 0xff) << 56);
        let tss_high = TSS >> 32;
        gdt[24..32].copy_from_slice(&tss_low.to_le_bytes());
        gdt[32..40].copy_from_slice(&tss_high.to_le_bytes());
        mem.write_at(GDT, &gdt)?;

        let mut sregs = unsafe { std::mem::zeroed::<KvmSregs>() };
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_GET_SREGS,
                &mut sregs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_GET_SREGS".into()));
        }

        let code = KvmSegment {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x08,
            type_: 11,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let data = KvmSegment {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x10,
            type_: 3,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        sregs.cs = code;
        sregs.ds = data;
        sregs.es = data;
        sregs.fs = data;
        sregs.gs = data;
        sregs.ss = data;
        sregs.ldt = data;
        sregs.ldt.unusable = 1;
        sregs.ldt.present = 0;
        sregs.ldt.selector = 0;
        sregs.tr = KvmSegment {
            base: TSS,
            limit: 103,
            selector: 0x18,
            type_: 11, // busy 64-bit TSS
            present: 1,
            dpl: 0,
            db: 0,
            s: 0,
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        sregs.gdt.base = GDT;
        sregs.gdt.limit = 40 - 1;
        sregs.idt.base = 0;
        sregs.idt.limit = 0;
        sregs.cr0 = 0x8005_0033; // PE MP ET NE WP PG
        sregs.cr3 = cr3;
        sregs.cr4 = 0x20; // PAE
        sregs.efer = 0x500; // LME | LMA
                            // BSP local APIC enabled at the default MMIO address.
        sregs.apic_base = 0xfee0_0000 | (1 << 11) | (1 << 8); // enable + BSP

        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_SREGS,
                &mut sregs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_SREGS".into()));
        }

        let mut regs = unsafe { std::mem::zeroed::<KvmRegs>() };
        regs.rip = rip;
        regs.rsp = rsp;
        regs.rsi = rsi;
        regs.rflags = 0x2;
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_REGS,
                &mut regs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_REGS".into()));
        }
        Ok(())
    }

    /// BSP-only, PVH boot entry. Sets up the *minimum* the PVH spec
    /// requires -- 32-bit protected mode, paging off, a flat code/data
    /// GDT, RIP at the kernel's PVH entry point, RBX pointing at the
    /// `hvm_start_info` structure (the PVH ABI's calling convention) --
    /// and leaves everything else (page tables, the 32-to-64-bit
    /// transition, per-cpu/GDT reload) to the kernel's own
    /// startup_32/startup_64 code, exactly as a real PVH-aware hypervisor
    /// (Xen, and this is also how cloud-hypervisor does it) would.
    ///
    /// This exists because our own hand-built identity page tables +
    /// direct-to-long-mode jump (`setup_long_mode`) substitutes our
    /// from-scratch setup for a large piece of what the kernel would
    /// otherwise do itself on real hardware -- any subtle gap there is a
    /// bug class PVH boot sidesteps entirely by letting the kernel do it.
    pub fn setup_pvh_entry(&self, mem: &mut GuestMemory, rip: u64, rbx: u64) -> Result<()> {
        let idx = 0;
        const GDT: u64 = 0xB000;
        const TSS: u64 = 0xC000;
        mem.write_at(TSS, &[0u8; 128])?;
        // null, code32, data32 -- flat, 4 GiB, matching the well-known
        // reference GDT bytes documented for the Linux boot protocol's
        // own 32-bit entry (Documentation/arch/x86/boot.rst) -- plus a
        // real 32-bit TSS descriptor. Unlike LDTR, VMX's guest-state
        // entry checks give TR no "unusable" exception: it must always
        // be a valid, PRESENT, busy (type 11) descriptor, even though
        // nothing ever actually task-switches into it. Omitting this
        // (marking TR unusable, matching how LDT is handled) is exactly
        // what caused KVM_EXIT_FAIL_ENTRY / EXIT_REASON_INVALID_STATE
        // (basic reason 33) on the very first vmentry -- confirmed live.
        let mut gdt = [0u8; 32];
        gdt[8..16].copy_from_slice(&0x00cf_9b00_0000_ffffu64.to_le_bytes());
        gdt[16..24].copy_from_slice(&0x00cf_9300_0000_ffffu64.to_le_bytes());
        let tss_limit = 103u64;
        let tss_desc = (tss_limit & 0xffff)
            | ((TSS & 0xff_ffff) << 16)
            | (0xbu64 << 40) // busy 32-bit TSS
            | (1u64 << 47) // present
            | (((TSS >> 24) & 0xff) << 56);
        gdt[24..32].copy_from_slice(&tss_desc.to_le_bytes());
        mem.write_at(GDT, &gdt)?;

        let mut sregs = unsafe { std::mem::zeroed::<KvmSregs>() };
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_GET_SREGS,
                &mut sregs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_GET_SREGS".into()));
        }

        let code = KvmSegment {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x08,
            type_: 0xb, // execute + read
            present: 1,
            dpl: 0,
            db: 1, // 32-bit
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let data = KvmSegment {
            base: 0,
            limit: 0xffff_ffff,
            selector: 0x10,
            type_: 0x3, // read + write
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        sregs.cs = code;
        sregs.ds = data;
        sregs.es = data;
        sregs.fs = data;
        sregs.gs = data;
        sregs.ss = data;
        sregs.ldt = data;
        sregs.ldt.unusable = 1;
        sregs.ldt.present = 0;
        sregs.ldt.selector = 0;
        sregs.tr = KvmSegment {
            base: TSS,
            limit: 103,
            selector: 0x18,
            type_: 0xb, // busy 32-bit TSS
            present: 1,
            dpl: 0,
            db: 0,
            s: 0,
            l: 0,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        sregs.gdt.base = GDT;
        sregs.gdt.limit = 32 - 1;
        sregs.idt.base = 0;
        sregs.idt.limit = 0;
        // Protected mode only -- no paging (PG), no PAE, no long mode.
        // The kernel's own startup_32 builds its own page tables and
        // makes the jump to long mode itself.
        sregs.cr0 = 0x1; // PE
        sregs.cr3 = 0;
        sregs.cr4 = 0;
        sregs.efer = 0;
        sregs.apic_base = 0xfee0_0000 | (1 << 11) | (1 << 8); // enable + BSP

        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_SREGS,
                &mut sregs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_SREGS".into()));
        }

        let mut regs = unsafe { std::mem::zeroed::<KvmRegs>() };
        regs.rip = rip;
        // Per the PVH boot spec, EBX holds a pointer to the
        // hvm_start_info structure at entry.
        regs.rbx = rbx;
        regs.rflags = 0x2;
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_REGS,
                &mut regs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_REGS".into()));
        }
        Ok(())
    }

    /// Assert or deassert a GSI on the in-kernel irqchip (IOAPIC).
    pub fn set_irq_line(&self, gsi: u32, level: bool) -> Result<()> {
        #[repr(C)]
        struct KvmIrqLevel {
            irq: u32,
            level: u32,
        }
        let mut irq = KvmIrqLevel {
            irq: gsi,
            level: u32::from(level),
        };
        if unsafe {
            ffi::flux_ioctl(
                self.vm_fd,
                ffi::KVM_IRQ_LINE,
                &mut irq as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor(format!(
                "KVM_IRQ_LINE gsi={gsi} level={level}"
            )));
        }
        Ok(())
    }

    /// Edge pulse used after virtio used-ring updates.
    pub fn pulse_irq(&self, gsi: u32) -> Result<()> {
        self.set_irq_line(gsi, true)?;
        self.set_irq_line(gsi, false)
    }

    pub fn get_regs(&self, idx: usize) -> Result<KvmRegs> {
        let mut regs = unsafe { std::mem::zeroed::<KvmRegs>() };
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_GET_REGS,
                &mut regs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_GET_REGS".into()));
        }
        Ok(regs)
    }

    pub fn set_regs(&self, idx: usize, mut regs: KvmRegs) -> Result<()> {
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_REGS,
                &mut regs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_REGS".into()));
        }
        Ok(())
    }

    pub fn get_sregs(&self, idx: usize) -> Result<KvmSregs> {
        let mut sregs = unsafe { std::mem::zeroed::<KvmSregs>() };
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_GET_SREGS,
                &mut sregs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_GET_SREGS".into()));
        }
        Ok(sregs)
    }

    pub fn set_sregs(&self, idx: usize, mut sregs: KvmSregs) -> Result<()> {
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_SREGS,
                &mut sregs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_SREGS".into()));
        }
        Ok(())
    }

    pub fn run_once(&self, idx: usize) -> Result<u32> {
        let r = unsafe { ffi::flux_ioctl(self.vcpus[idx].fd, ffi::KVM_RUN, std::ptr::null_mut()) };
        if r < 0 {
            let errno = unsafe { ffi::flux_errno() };
            // A signal delivered to force a stuck/looping vCPU out of
            // KVM_RUN (the gdbstub's break-in mechanism: set
            // immediate_exit then signal this thread) surfaces as EINTR.
            // Treat it the same as KVM_EXIT_INTR -- "nothing to handle,
            // just re-check state and loop" -- rather than a fatal error.
            if errno == ffi::EINTR {
                return Ok(ffi::KVM_EXIT_INTR);
            }
            return Err(FluxError::Hypervisor(format!("KVM_RUN errno {errno}")));
        }
        Ok(self.exit_reason(idx))
    }

    pub fn exit_reason(&self, idx: usize) -> u32 {
        unsafe { std::ptr::read_unaligned(self.vcpus[idx].run.add(8) as *const u32) }
    }

    /// Force the next (or currently in-flight) KVM_RUN on this vCPU to
    /// return immediately without entering/continuing guest execution.
    /// Combined with a signal sent to the vCPU's OS thread (needed to
    /// break out of a KVM_RUN already in progress), this is the standard
    /// technique for an external "pause"/gdbstub break-in.
    pub fn request_immediate_exit(&self, idx: usize, on: bool) {
        unsafe {
            std::ptr::write_volatile(self.vcpus[idx].run.add(1), on as u8);
        }
    }

    /// Enable trapping of the guest's own `int3` (software breakpoint)
    /// execution to `KVM_EXIT_DEBUG` instead of letting it reach the
    /// guest's IDT. The gdbstub still has to patch the `0xCC` byte into
    /// guest memory itself (`KVM_GUESTDBG_USE_SW_BP` only controls how
    /// KVM *reports* an int3 that already happened, not where one is).
    pub fn enable_guest_debug(&self, idx: usize) -> Result<()> {
        #[repr(C)]
        struct KvmGuestDebug {
            control: u32,
            pad: u32,
            debugreg: [u64; 8],
        }
        let mut dbg = KvmGuestDebug {
            control: ffi::KVM_GUESTDBG_ENABLE | ffi::KVM_GUESTDBG_USE_SW_BP,
            pad: 0,
            debugreg: [0; 8],
        };
        if unsafe {
            ffi::flux_ioctl(
                self.vcpus[idx].fd,
                ffi::KVM_SET_GUEST_DEBUG,
                &mut dbg as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_GUEST_DEBUG".into()));
        }
        Ok(())
    }

    pub fn io_info(&self, idx: usize) -> (u8, u8, u16, u32, u32) {
        // direction, size, port, count, data_offset
        unsafe {
            let run = self.vcpus[idx].run;
            let d = std::ptr::read_unaligned(run.add(32) as *const u8);
            let sz = std::ptr::read_unaligned(run.add(33) as *const u8);
            let port = std::ptr::read_unaligned(run.add(34) as *const u16);
            let count = std::ptr::read_unaligned(run.add(36) as *const u32);
            let off = std::ptr::read_unaligned(run.add(40) as *const u32);
            (d, sz, port, count, off)
        }
    }

    pub fn io_data(&self, idx: usize, off: u32, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.vcpus[idx].run.add(off as usize), len) }
    }

    pub fn set_io_data(&self, idx: usize, off: u32, data: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.vcpus[idx].run.add(off as usize),
                data.len(),
            );
        }
    }

    pub fn mmio_info(&self, idx: usize) -> (u64, Vec<u8>, u32, bool) {
        unsafe {
            let run = self.vcpus[idx].run;
            let phys = std::ptr::read_unaligned(run.add(32) as *const u64);
            let len = std::ptr::read_unaligned(run.add(48) as *const u32);
            let is_write = std::ptr::read_unaligned(run.add(52) as *const u8) != 0;
            let mut data = vec![0u8; len as usize];
            std::ptr::copy_nonoverlapping(run.add(40), data.as_mut_ptr(), len as usize);
            (phys, data, len, is_write)
        }
    }

    pub fn mmio_set_data(&self, idx: usize, data: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.vcpus[idx].run.add(40),
                data.len().min(8),
            );
        }
    }
}

impl Drop for KvmVm {
    fn drop(&mut self) {
        unsafe {
            for vcpu in &self.vcpus {
                if !vcpu.run.is_null() {
                    ffi::munmap(vcpu.run as *mut c_void, self.run_size);
                }
                if vcpu.fd >= 0 {
                    ffi::close(vcpu.fd);
                }
            }
            if self.vm_fd >= 0 {
                ffi::close(self.vm_fd);
            }
            if self.kvm_fd >= 0 {
                ffi::close(self.kvm_fd);
            }
        }
    }
}
