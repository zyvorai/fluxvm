// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use crate::ffi;
use std::os::raw::c_void;
use std::ptr::NonNull;

pub const MMIO_WINDOW: u64 = 0xFEB0_0000;
pub const KERNEL_LOAD_ADDR: u64 = 0x0020_0000;
pub const BOOT_PARAMS_ADDR: u64 = 0x0000_7000;
pub const INITRD_ADDR: u64 = 0x0400_0000;
pub const GUEST_STACK: u64 = 0x0080_0000;

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
        let p = unsafe {
            ffi::mmap(
                std::ptr::null_mut(),
                len,
                ffi::PROT_READ | ffi::PROT_WRITE,
                ffi::MAP_SHARED | ffi::MAP_ANONYMOUS | ffi::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if p as usize == ffi::MAP_FAILED {
            return Err(FluxError::Memory("mmap guest ram failed".into()));
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
