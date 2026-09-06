// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use crate::ffi;
use crate::memory::GuestMemory;
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

pub struct KvmVm {
    pub kvm_fd: i32,
    pub vm_fd: i32,
    pub vcpu_fd: i32,
    pub run: *mut u8,
    pub run_size: usize,
}

unsafe impl Send for KvmVm {}

impl KvmVm {
    pub fn create(mem: &GuestMemory) -> Result<Self> {
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
            let _ = ffi::flux_ioctl(vm_fd, ffi::KVM_CREATE_IRQCHIP, std::ptr::null_mut());

            let mmap_size =
                ffi::flux_ioctl(kvm_fd, ffi::KVM_GET_VCPU_MMAP_SIZE, std::ptr::null_mut());
            if mmap_size <= 0 {
                return Err(FluxError::Hypervisor("KVM_GET_VCPU_MMAP_SIZE".into()));
            }
            let vcpu_fd = ffi::flux_ioctl(vm_fd, ffi::KVM_CREATE_VCPU, std::ptr::null_mut());
            if vcpu_fd < 0 {
                return Err(FluxError::Hypervisor("KVM_CREATE_VCPU".into()));
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
            Ok(Self {
                kvm_fd,
                vm_fd,
                vcpu_fd,
                run: run as *mut u8,
                run_size: mmap_size as usize,
            })
        }
    }

    pub fn setup_long_mode(
        &mut self,
        mem: &mut GuestMemory,
        rip: u64,
        rsp: u64,
        cr3: u64,
    ) -> Result<()> {
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
                self.vcpu_fd,
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

        if unsafe {
            ffi::flux_ioctl(
                self.vcpu_fd,
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
        regs.rflags = 0x2;
        if unsafe {
            ffi::flux_ioctl(
                self.vcpu_fd,
                ffi::KVM_SET_REGS,
                &mut regs as *mut _ as *mut c_void,
            )
        } < 0
        {
            return Err(FluxError::Hypervisor("KVM_SET_REGS".into()));
        }
        Ok(())
    }

    pub fn run_once(&mut self) -> Result<u32> {
        let r = unsafe { ffi::flux_ioctl(self.vcpu_fd, ffi::KVM_RUN, std::ptr::null_mut()) };
        if r < 0 {
            return Err(FluxError::Hypervisor(format!("KVM_RUN errno {}", unsafe {
                ffi::flux_errno()
            })));
        }
        Ok(self.exit_reason())
    }

    pub fn exit_reason(&self) -> u32 {
        unsafe { std::ptr::read_unaligned(self.run.add(8) as *const u32) }
    }

    pub fn io_info(&self) -> (u8, u8, u16, u32, u32) {
        // direction, size, port, count, data_offset
        unsafe {
            let d = std::ptr::read_unaligned(self.run.add(32) as *const u8);
            let sz = std::ptr::read_unaligned(self.run.add(33) as *const u8);
            let port = std::ptr::read_unaligned(self.run.add(34) as *const u16);
            let count = std::ptr::read_unaligned(self.run.add(36) as *const u32);
            let off = std::ptr::read_unaligned(self.run.add(40) as *const u32);
            (d, sz, port, count, off)
        }
    }

    pub fn io_data(&self, off: u32, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.run.add(off as usize), len) }
    }

    pub fn io_data_mut(&mut self, off: u32, len: usize) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.run.add(off as usize), len) }
    }

    pub fn mmio_info(&self) -> (u64, Vec<u8>, u32, bool) {
        unsafe {
            let phys = std::ptr::read_unaligned(self.run.add(32) as *const u64);
            let len = std::ptr::read_unaligned(self.run.add(48) as *const u32);
            let is_write = std::ptr::read_unaligned(self.run.add(52) as *const u8) != 0;
            let mut data = vec![0u8; len as usize];
            std::ptr::copy_nonoverlapping(self.run.add(40), data.as_mut_ptr(), len as usize);
            (phys, data, len, is_write)
        }
    }

    pub fn mmio_set_data(&mut self, data: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.run.add(40), data.len().min(8));
        }
    }
}

impl Drop for KvmVm {
    fn drop(&mut self) {
        unsafe {
            if !self.run.is_null() {
                ffi::munmap(self.run as *mut c_void, self.run_size);
            }
            if self.vcpu_fd >= 0 {
                ffi::close(self.vcpu_fd);
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
