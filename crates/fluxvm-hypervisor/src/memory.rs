// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use crate::ffi;
use std::os::raw::c_void;
use std::ptr::NonNull;

pub const MMIO_WINDOW: u64 = 0xFEB0_0000;
pub const KERNEL_LOAD_ADDR: u64 = 0x0020_0000;
/// Linux zero-page / boot_params GPA (also Firecracker `ZERO_PAGE_START`).
pub const BOOT_PARAMS_ADDR: u64 = 0x0000_7000;
pub const INITRD_ADDR: u64 = 0x0400_0000;
pub const GUEST_STACK: u64 = 0x0080_0000;

// ---- x86_64 guest layout (match Firecracker / cloud-hypervisor) ----
/// `hvm_start_info` for PVH (`Firecracker::PVH_INFO_START`).
pub const PVH_INFO_START: u64 = 0x6000;
/// PVH module list (`Firecracker::MODLIST_START`).
pub const MODLIST_START: u64 = 0x6040;
/// PVH memmap table (`Firecracker::MEMMAP_START`); overlaps zero-page GPA
/// because the two boot paths are mutually exclusive.
pub const MEMMAP_START: u64 = 0x7000;
/// Start of high usable RAM.
pub const HIMEM_START: u64 = 0x0010_0000;
/// EBDA-ish system-data window start (MP table, etc.).
pub const SYSTEM_MEM_START: u64 = 0x0009_fc00;
/// RSDP placeholder address; system reserved runs `[SYSTEM_MEM_START, RSDP_ADDR)`.
pub const RSDP_ADDR: u64 = 0x000e_0000;
pub const SYSTEM_MEM_SIZE: u64 = RSDP_ADDR - SYSTEM_MEM_START;
pub const IOAPIC_ADDR: u64 = 0xfec0_0000;
/// PCIe ECAM window reserved in e820/memmap (Firecracker layout).
pub const PCI_MMCONFIG_SIZE: u64 = 256 << 20;
pub const PCI_MMCONFIG_START: u64 = IOAPIC_ADDR - PCI_MMCONFIG_SIZE;
/// Three-page Intel VT-x quirk region (`Firecracker::KVM_TSS_ADDRESS`).
/// Must sit outside guest RAM / MMIO slots; required with in-kernel irqchip.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

pub struct GuestMemory {
    ptr: NonNull<u8>,
    len: usize,
}

unsafe impl Send for GuestMemory {}
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    pub fn allocate(len: usize) -> Result<Self> {
        if len == 0 || len % 4096 != 0 {
            return Err(FluxError::Memory(
                "size must be non-zero and 4 KiB aligned".into(),
            ));
        }
        let dense = std::env::var("FLUXVM_KVM_LOCK_MEM").ok().as_deref() == Some("1");
        let mut flags = ffi::MAP_SHARED | ffi::MAP_ANONYMOUS;
        if dense {
            flags |= ffi::MAP_POPULATE;
        } else {
            flags |= ffi::MAP_NORESERVE;
        }
        let p = unsafe {
            ffi::mmap(
                std::ptr::null_mut(),
                len,
                ffi::PROT_READ | ffi::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if p as usize == ffi::MAP_FAILED {
            return Err(FluxError::Memory("mmap guest ram failed".into()));
        }
        if dense {
            let _ = unsafe { ffi::mlock(p as *const c_void, len) };
        }
        Ok(Self {
            ptr: NonNull::new(p as *mut u8).unwrap(),
            len,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn host_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    pub fn write_at(&mut self, gpa: u64, data: &[u8]) -> Result<()> {
        let start = gpa as usize;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| FluxError::Memory("GPA overflow".into()))?;
        if end > self.len {
            return Err(FluxError::Memory(format!(
                "write GPA {gpa:#x}+{} past RAM {}",
                data.len(),
                self.len
            )));
        }
        self.as_slice_mut()[start..end].copy_from_slice(data);
        Ok(())
    }

    pub fn read_at(&self, gpa: u64, buf: &mut [u8]) -> Result<()> {
        let start = gpa as usize;
        let end = start + buf.len();
        if end > self.len {
            return Err(FluxError::Memory(format!(
                "read GPA {gpa:#x}+{} past RAM {}",
                buf.len(),
                self.len
            )));
        }
        buf.copy_from_slice(&self.as_slice()[start..end]);
        Ok(())
    }

    pub fn read_u16(&self, gpa: u64) -> Result<u16> {
        let mut b = [0u8; 2];
        self.read_at(gpa, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    pub fn write_u16(&mut self, gpa: u64, v: u16) -> Result<()> {
        self.write_at(gpa, &v.to_le_bytes())
    }
}

impl Drop for GuestMemory {
    fn drop(&mut self) {
        unsafe {
            ffi::munmap(self.ptr.as_ptr() as *mut c_void, self.len);
        }
    }
}

impl Clone for GuestMemory {
    fn clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            len: self.len,
        }
    }
}
