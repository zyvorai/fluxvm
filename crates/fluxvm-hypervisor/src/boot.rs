// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::config::{GuestKind, VmConfig};
use crate::error::{FluxError, Result};
use crate::memory::{self, GuestMemory};

#[derive(Debug, Clone)]
pub struct BootInfo {
    pub entry_rip: u64,
    pub boot_params_gpa: Option<u64>,
    pub notes: Vec<String>,
}

pub fn prepare(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    match cfg.guest {
        GuestKind::Linux => prepare_linux(mem, cfg),
        GuestKind::Windows => prepare_windows(mem, cfg),
    }
}

fn prepare_linux(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    let mut notes = vec![
        "Linux fast path: no BIOS, no UEFI, no PCI enumeration".into(),
        format!("cmdline: {}", cfg.cmdline),
        format!("load kernel at GPA {:#x}", memory::KERNEL_LOAD_ADDR),
        format!("boot_params at GPA {:#x}", memory::BOOT_PARAMS_ADDR),
    ];

    if let Some(path) = &cfg.kernel {
        let bytes = std::fs::read(path)?;
        if bytes.len() + memory::KERNEL_LOAD_ADDR as usize > mem.len() {
            return Err(FluxError::Boot("kernel larger than guest RAM".into()));
        }
        mem.write_at(memory::KERNEL_LOAD_ADDR, &bytes)?;
        notes.push(format!(
            "wrote {} bytes from {} (use linux-loader in production)",
            bytes.len(),
            path.display()
        ));
    } else {
        notes.push("no --kernel given; topology-only run".into());
    }

    if let Some(initrd) = &cfg.initrd {
        let bytes = std::fs::read(initrd)?;
        mem.write_at(memory::INITRD_ADDR, &bytes)?;
        notes.push(format!(
            "initrd {} bytes at {:#x}",
            bytes.len(),
            memory::INITRD_ADDR
        ));
    }

    write_linux_cmdline(mem, &cfg.cmdline)?;

    Ok(BootInfo {
        entry_rip: memory::KERNEL_LOAD_ADDR,
        boot_params_gpa: Some(memory::BOOT_PARAMS_ADDR),
        notes,
    })
}

fn write_linux_cmdline(mem: &mut GuestMemory, cmdline: &str) -> Result<()> {
    const CMDLINE_GPA: u64 = 0x0002_0000;
    let mut bytes = cmdline.as_bytes().to_vec();
    bytes.push(0);
    mem.write_at(CMDLINE_GPA, &bytes)
}

fn prepare_windows(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    let mut notes = vec![
        "Windows path: OVMF + ACPI + virtio-pci + virtio-win drivers".into(),
        "Not a Firecracker-class boot. Mirror Cloud Hypervisor.".into(),
    ];

    if let Some(path) = cfg.firmware.as_ref().or(cfg.kernel.as_ref()) {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            let gpa = 0x0100_0000u64;
            if gpa as usize + bytes.len() < mem.len() {
                mem.write_at(gpa, &bytes)?;
            }
            notes.push(format!(
                "loaded firmware {} ({} bytes)",
                path.display(),
                bytes.len()
            ));
        } else {
            notes.push(format!("firmware path {} missing", path.display()));
        }
    } else {
        notes.push("no --firmware provided (dry-run ok)".into());
    }

    notes.push(acpi_requirements().into());

    Ok(BootInfo {
        entry_rip: 0xFFFF_FFF0,
        boot_params_gpa: None,
        notes,
    })
}

pub fn acpi_requirements() -> &'static str {
    "ACPI for Windows: RSDP, XSDT, FADT, MADT (LAPIC+IOAPIC), DSDT for virtio-pci, MCFG if ECAM."
}

pub fn build_identity_page_tables(mem: &mut GuestMemory) -> Result<u64> {
    const PML4: u64 = 0x8000;
    const PDPT: u64 = 0x9000;
    let mut pml4 = [0u8; 4096];
    pml4[..8].copy_from_slice(&(PDPT | 0x3).to_le_bytes());
    mem.write_at(PML4, &pml4)?;

    const PD0: u64 = 0xA000;
    const PD3: u64 = 0xD000;
    let mut pdpt = [0u8; 4096];
    pdpt[0..8].copy_from_slice(&(PD0 | 0x3).to_le_bytes());
    pdpt[24..32].copy_from_slice(&(PD3 | 0x3).to_le_bytes());
    mem.write_at(PDPT, &pdpt)?;
    let mut pd0 = vec![0u8; 4096];
    for i in 0..512u64 {
        let e = (i << 21) | 0x83;
        pd0[(i as usize) * 8..(i as usize) * 8 + 8].copy_from_slice(&e.to_le_bytes());
    }
    mem.write_at(PD0, &pd0)?;
    let mut pd3 = vec![0u8; 4096];
    for i in 0..512u64 {
        let e = (3u64 << 30) | (i << 21) | 0x83;
        pd3[(i as usize) * 8..(i as usize) * 8 + 8].copy_from_slice(&e.to_le_bytes());
    }
    mem.write_at(PD3, &pd3)?;
    Ok(PML4)
}
