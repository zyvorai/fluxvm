// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use std::os::raw::{c_char, c_int, c_ulong, c_void};

#[cfg(not(fluxvm_no_host_c))]
extern "C" {
    pub fn flux_ioctl(fd: c_int, req: c_ulong, arg: *mut c_void) -> c_int;
    pub fn flux_tap_open(name: *const c_char) -> c_int;
    pub fn flux_if_up(name: *const c_char) -> c_int;
    pub fn flux_if_addr(name: *const c_char, addr_be: u32, mask_be: u32) -> c_int;
    pub fn flux_errno() -> c_int;

    pub fn open(path: *const c_char, flags: c_int) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        off: i64,
    ) -> *mut c_void;
    pub fn munmap(addr: *mut c_void, len: usize) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    pub fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
}

#[cfg(fluxvm_no_host_c)]
mod stubs {
    use super::*;
    pub unsafe fn flux_ioctl(_: c_int, _: c_ulong, _: *mut c_void) -> c_int {
        -1
    }
    pub unsafe fn flux_tap_open(_: *const c_char) -> c_int {
        -1
    }
    pub unsafe fn flux_if_up(_: *const c_char) -> c_int {
        -1
    }
    pub unsafe fn flux_if_addr(_: *const c_char, _: u32, _: u32) -> c_int {
        -1
    }
    pub unsafe fn flux_errno() -> c_int {
        38
    } // ENOSYS
    pub unsafe fn open(_: *const c_char, _: c_int) -> c_int {
        -1
    }
    pub unsafe fn close(_: c_int) -> c_int {
        -1
    }
    pub unsafe fn mmap(
        _: *mut c_void,
        _: usize,
        _: c_int,
        _: c_int,
        _: c_int,
        _: i64,
    ) -> *mut c_void {
        MAP_FAILED as *mut c_void
    }
    pub unsafe fn munmap(_: *mut c_void, _: usize) -> c_int {
        -1
    }
    pub unsafe fn read(_: c_int, _: *mut c_void, _: usize) -> isize {
        -1
    }
    pub unsafe fn write(_: c_int, _: *const c_void, _: usize) -> isize {
        -1
    }
}

#[cfg(fluxvm_no_host_c)]
pub use stubs::*;

pub const O_RDWR: c_int = 2;
pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const MAP_SHARED: c_int = 0x01;
pub const MAP_ANONYMOUS: c_int = 0x20;
pub const MAP_NORESERVE: c_int = 0x4000;
pub const MAP_FAILED: usize = !0;

pub const KVM_GET_API_VERSION: c_ulong = 0xae00;
pub const KVM_CREATE_VM: c_ulong = 0xae01;
pub const KVM_GET_VCPU_MMAP_SIZE: c_ulong = 0xae04;
pub const KVM_CREATE_VCPU: c_ulong = 0xae41;
pub const KVM_SET_USER_MEMORY_REGION: c_ulong = 0x4020_ae46;
pub const KVM_CREATE_IRQCHIP: c_ulong = 0xae60;
pub const KVM_RUN: c_ulong = 0xae80;
pub const KVM_GET_REGS: c_ulong = 0x8090_ae81;
pub const KVM_SET_REGS: c_ulong = 0x4090_ae82;
pub const KVM_GET_SREGS: c_ulong = 0x8138_ae83;
pub const KVM_SET_SREGS: c_ulong = 0x4138_ae84;

pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTR: u32 = 10;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;

pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;
