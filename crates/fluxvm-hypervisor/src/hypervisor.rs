// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Hypervisor backend trait. `StubHv` compiles anywhere.
//! On a Linux KVM host replace it with the `kvm-ioctls` snippet in `kvm_howto`.

use crate::error::{FluxError, Result};
use crate::memory::GuestMemory;

#[derive(Debug, Clone)]
pub enum VcpuExit {
    IoOut { port: u16, data: Vec<u8> },
    IoIn { port: u16, size: u8 },
    MmioWrite { addr: u64, data: Vec<u8> },
    MmioRead { addr: u64, size: u8 },
    Halt,
    Shutdown,
    Interrupted,
    Unknown(String),
}

pub trait Hypervisor: Send {
    fn create_vm(&mut self, mem: &GuestMemory) -> Result<Box<dyn VmBackend>>;
}

pub trait VmBackend: Send {
    fn create_vcpu(&mut self, id: u8) -> Result<Box<dyn VcpuBackend>>;
    fn register_irqfd(&mut self, gsi: u32) -> Result<()>;
}

pub trait VcpuBackend: Send {
    fn set_rip(&mut self, rip: u64) -> Result<()>;
    fn run(&mut self) -> Result<VcpuExit>;
}

pub struct StubHv;

impl Hypervisor for StubHv {
    fn create_vm(&mut self, mem: &GuestMemory) -> Result<Box<dyn VmBackend>> {
        eprintln!("[hv] stub VM created, ram={} bytes", mem.len());
        Ok(Box::new(StubVm))
    }
}

struct StubVm;

impl VmBackend for StubVm {
    fn create_vcpu(&mut self, id: u8) -> Result<Box<dyn VcpuBackend>> {
        eprintln!("[hv] stub vCPU {id}");
        Ok(Box::new(StubVcpu { id, rip: 0 }))
    }

    fn register_irqfd(&mut self, gsi: u32) -> Result<()> {
        let _ = gsi;
        Ok(())
    }
}

struct StubVcpu {
    id: u8,
    rip: u64,
}

impl VcpuBackend for StubVcpu {
    fn set_rip(&mut self, rip: u64) -> Result<()> {
        self.rip = rip;
        Ok(())
    }

    fn run(&mut self) -> Result<VcpuExit> {
        eprintln!(
            "[hv] stub KVM_RUN vcpu={} rip={:#x} — no real guest execution",
            self.id, self.rip
        );
        Err(FluxError::Hypervisor(
            "stub backend cannot execute guest code; wire kvm-ioctls on a Linux KVM host".into(),
        ))
    }
}

pub mod kvm_howto {
    pub const STEPS: &str = r#"
use kvm_ioctls::{Kvm, VcpuExit};
use kvm_bindings::kvm_userspace_memory_region;

let kvm = Kvm::new()?;
let vm = kvm.create_vm()?;

let region = kvm_userspace_memory_region {
    slot: 0,
    guest_phys_addr: 0,
    memory_size: mem.len() as u64,
    userspace_addr: mem.host_ptr() as u64,
    flags: 0,
};
unsafe { vm.set_user_memory_region(region)?; }

vm.create_irq_chip()?;
vm.create_pit2(Default::default())?;

let mut vcpu = vm.create_vcpu(0)?;
let cpuid = kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)?;
vcpu.set_cpuid2(&cpuid)?;

loop {
    match vcpu.run()? {
        VcpuExit::IoOut(port, data) => bus.pio_write(port, data),
        VcpuExit::IoIn(port, data)  => bus.pio_read(port, data),
        VcpuExit::MmioWrite(addr, data) => bus.mmio_write(addr, data),
        VcpuExit::MmioRead(addr, data)  => bus.mmio_read(addr, data),
        VcpuExit::Hlt | VcpuExit::Shutdown => break,
        VcpuExit::Intr => continue,
        other => eprintln!("exit {other:?}"),
    }
}
"#;
}
