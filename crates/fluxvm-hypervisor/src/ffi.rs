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
    pub fn mlock(addr: *const c_void, len: usize) -> c_int;
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
    pub unsafe fn mlock(_: *const c_void, _: usize) -> c_int {
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
pub const MAP_POPULATE: c_int = 0x8000;
pub const MAP_FAILED: usize = !0;

pub const KVM_GET_API_VERSION: c_ulong = 0xae00;
pub const KVM_CREATE_VM: c_ulong = 0xae01;
/// `_IO(KVMIO, 0x03)` — arg is the KVM_CAP_* id itself (not a pointer).
pub const KVM_CHECK_EXTENSION: c_ulong = 0xae03;
/// Whether the in-kernel LAPIC can accept a raw TSC-deadline WRMSR.
/// KVM_GET_SUPPORTED_CPUID unconditionally clears CPUID.01H:ECX[24]
/// (TSC_DEADLINE) even when both the host CPU and the in-kernel irqchip
/// support it -- this capability check is the correct way to know
/// whether it's actually safe to advertise to the guest (matches how
/// crosvm derives its own TSC-deadline CPUID bit).
pub const KVM_CAP_TSC_DEADLINE_TIMER: c_ulong = 72;
pub const KVM_GET_VCPU_MMAP_SIZE: c_ulong = 0xae04;
pub const KVM_CREATE_VCPU: c_ulong = 0xae41;
pub const KVM_SET_USER_MEMORY_REGION: c_ulong = 0x4020_ae46;
/// `_IO(KVMIO, 0x47)` — Intel hosts need a 3-page TSS region with irqchip.
pub const KVM_SET_TSS_ADDR: c_ulong = 0xae47;
pub const KVM_CREATE_IRQCHIP: c_ulong = 0xae60;
pub const KVM_IRQ_LINE: c_ulong = 0x4008_ae61;
/// `sizeof(struct kvm_irqfd)` == 32 — Firecracker wires COM1 via this (GSI 4).
pub const KVM_IRQFD: c_ulong = 0x4020_ae76;
/// `sizeof(struct kvm_pit_config)` == 64
pub const KVM_CREATE_PIT2: c_ulong = 0x4040_ae77;
pub const KVM_RUN: c_ulong = 0xae80;
pub const KVM_GET_REGS: c_ulong = 0x8090_ae81;
pub const KVM_SET_REGS: c_ulong = 0x4090_ae82;
pub const KVM_GET_SREGS: c_ulong = 0x8138_ae83;
pub const KVM_SET_SREGS: c_ulong = 0x4138_ae84;
/// Header-only `_IOW(KVMIO, 0x89, struct kvm_msrs)` — buffer holds `nmsrs` entries.
pub const KVM_SET_MSRS: c_ulong = 0x4008_ae89;
/// `sizeof(struct kvm_fpu)` == 416 (`_IOW(KVMIO, 0x8d, struct kvm_fpu)`).
pub const KVM_SET_FPU: c_ulong = 0x41a0_ae8d;
/// `sizeof(struct kvm_lapic_state)` == 0x400.
pub const KVM_GET_LAPIC: c_ulong = 0x8400_ae8e;
pub const KVM_SET_LAPIC: c_ulong = 0x4400_ae8f;
/// `sizeof(struct kvm_cpuid2)` header only (8); buffer must hold `nent` entries.
pub const KVM_GET_SUPPORTED_CPUID: c_ulong = 0xc008_ae05;
pub const KVM_SET_CPUID2: c_ulong = 0x4008_ae90;
/// `sizeof(struct kvm_mp_state)` == 4 (single u32).
pub const KVM_GET_MP_STATE: c_ulong = 0x8004_ae98;
pub const KVM_SET_MP_STATE: c_ulong = 0x4004_ae99;

/// A freshly created vCPU defaults to KVM_MP_STATE_RUNNABLE even without
/// an explicit RIP set — it will execute whatever garbage is at the reset
/// vector instead of waiting for the guest's real INIT-SIPI-SIPI. APs
/// must be moved to this state right after creation.
pub const KVM_MP_STATE_UNINITIALIZED: u32 = 1;

/// `_IOW(KVMIO, 0x9b, struct kvm_guest_debug)` — control(u32) + pad(u32) +
/// kvm_guest_debug_arch{debugreg[8]: u64} = 4+4+64 = 72 bytes.
pub const KVM_SET_GUEST_DEBUG: c_ulong = 0x4048_ae9b;
pub const KVM_GUESTDBG_ENABLE: u32 = 0x0000_0001;
pub const KVM_GUESTDBG_USE_SW_BP: u32 = 0x0001_0000;

pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_DEBUG: u32 = 4;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTR: u32 = 10;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;

pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;

/// Errno for a syscall interrupted by a delivered signal.
pub const EINTR: c_int = 4;
