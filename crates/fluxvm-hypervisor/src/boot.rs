// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::config::{GuestKind, VmConfig};
use crate::error::{FluxError, Result};
use crate::memory::{self, GuestMemory};

#[derive(Debug, Clone)]
pub struct BootInfo {
    pub entry_rip: u64,
    /// Zero-page / boot_params GPA — Linux 64-bit boot expects this in RSI.
    pub boot_params_gpa: Option<u64>,
    pub notes: Vec<String>,
}

pub const CMDLINE_GPA: u64 = 0x0002_0000;

pub fn prepare(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    match cfg.guest {
        GuestKind::Linux => prepare_linux(mem, cfg),
        GuestKind::Windows => prepare_windows(mem, cfg),
    }
}

fn prepare_linux(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    #[cfg(target_os = "linux")]
    {
        match prepare_linux_with_loader(mem, cfg) {
            Ok(info) => return Ok(info),
            Err(e) => {
                tracing::warn!(error = %e, "linux-loader path failed; falling back to raw dump");
            }
        }
    }
    prepare_linux_raw(mem, cfg)
}

fn prepare_linux_raw(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    let mut notes = vec![
        "Linux raw dump path (no bzImage/ELF parse)".into(),
        format!("cmdline: {}", cfg.cmdline),
        format!("load kernel at GPA {:#x}", memory::KERNEL_LOAD_ADDR),
        format!("boot_params at GPA {:#x}", memory::BOOT_PARAMS_ADDR),
    ];

    let mut initrd_len = 0u32;
    if let Some(path) = &cfg.kernel {
        let bytes = std::fs::read(path)?;
        if bytes.len() + memory::KERNEL_LOAD_ADDR as usize > mem.len() {
            return Err(FluxError::Boot("kernel larger than guest RAM".into()));
        }
        mem.write_at(memory::KERNEL_LOAD_ADDR, &bytes)?;
        notes.push(format!(
            "wrote {} bytes from {} (raw; prefer linux-loader)",
            bytes.len(),
            path.display()
        ));
    } else {
        notes.push("no --kernel given; topology-only run".into());
    }

    if let Some(initrd) = &cfg.initrd {
        let bytes = std::fs::read(initrd)?;
        initrd_len = bytes.len() as u32;
        mem.write_at(memory::INITRD_ADDR, &bytes)?;
        notes.push(format!(
            "initrd {} bytes at {:#x}",
            bytes.len(),
            memory::INITRD_ADDR
        ));
    }

    write_linux_cmdline(mem, &cfg.cmdline)?;
    write_minimal_boot_params(mem, cfg, initrd_len)?;

    Ok(BootInfo {
        entry_rip: memory::KERNEL_LOAD_ADDR,
        boot_params_gpa: Some(memory::BOOT_PARAMS_ADDR),
        notes,
    })
}

#[cfg(target_os = "linux")]
fn prepare_linux_with_loader(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    use linux_loader::configurator::linux::LinuxBootConfigurator;
    use linux_loader::configurator::{BootConfigurator, BootParams};
    use linux_loader::loader::bootparam::boot_params;
    use linux_loader::loader::bzimage::BzImage;
    use linux_loader::loader::elf::Elf;
    use linux_loader::loader::{KernelLoader, KernelLoaderResult};
    use std::fs::File;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    const E820_RAM: u32 = 1;

    let path = cfg
        .kernel
        .as_ref()
        .ok_or_else(|| FluxError::Boot("no kernel path for linux-loader".into()))?;

    let mut notes = vec![
        "Linux boot via linux-loader (bzImage/ELF)".into(),
        format!("cmdline: {}", cfg.cmdline),
        format!("boot_params at GPA {:#x}", memory::BOOT_PARAMS_ADDR),
    ];

    let gm = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), mem.len())])
        .map_err(|e| FluxError::Boot(format!("GuestMemoryMmap: {e}")))?;

    let himem = GuestAddress(0x0010_0000);
    let loader_result: KernelLoaderResult = {
        let mut f = File::open(path).map_err(|e| FluxError::Boot(format!("open kernel: {e}")))?;
        match BzImage::load(&gm, None, &mut f, Some(himem)) {
            Ok(r) => {
                notes.push(format!("loaded bzImage from {}", path.display()));
                r
            }
            Err(bz_err) => {
                let mut f =
                    File::open(path).map_err(|e| FluxError::Boot(format!("open kernel: {e}")))?;
                match Elf::load(&gm, None, &mut f, Some(himem)) {
                    Ok(r) => {
                        notes.push(format!(
                            "loaded ELF vmlinux from {} (bzImage err: {bz_err})",
                            path.display()
                        ));
                        r
                    }
                    Err(elf_err) => {
                        return Err(FluxError::Boot(format!(
                            "neither bzImage ({bz_err}) nor ELF ({elf_err})"
                        )));
                    }
                }
            }
        }
    };

    // Mirror loader-populated pages into our KVM GuestMemory (skip all-zero chunks).
    copy_mmap_to_guest(&gm, mem)?;

    let mut initrd_len = 0u32;
    if let Some(initrd) = &cfg.initrd {
        let bytes = std::fs::read(initrd)?;
        initrd_len = bytes.len() as u32;
        mem.write_at(memory::INITRD_ADDR, &bytes)?;
        notes.push(format!(
            "initrd {} bytes at {:#x}",
            bytes.len(),
            memory::INITRD_ADDR
        ));
    }

    write_linux_cmdline(mem, &cfg.cmdline)?;

    let mut params = boot_params::default();
    if let Some(hdr) = loader_result.setup_header {
        params.hdr = hdr;
    }
    params.hdr.type_of_loader = 0xff;
    params.hdr.cmd_line_ptr = CMDLINE_GPA as u32;
    params.hdr.cmdline_size = (cfg.cmdline.len() as u32).saturating_add(1);
    if initrd_len > 0 {
        params.hdr.ramdisk_image = memory::INITRD_ADDR as u32;
        params.hdr.ramdisk_size = initrd_len;
    }
    params.e820_entries = 1;
    params.e820_table[0].addr = 0;
    params.e820_table[0].size = mem.len() as u64;
    params.e820_table[0].r#type = E820_RAM;

    let zero_page = GuestAddress(memory::BOOT_PARAMS_ADDR);
    let boot_cfg = BootParams::new::<boot_params>(&params, zero_page);
    LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap<()>>(&boot_cfg, &gm).map_err(|e| {
        FluxError::Boot(format!("write_bootparams: {e}"))
    })?;

    // Copy zero page into KVM guest RAM.
    let mut zero = vec![0u8; std::mem::size_of::<boot_params>()];
    gm.read(&mut zero, GuestAddress(memory::BOOT_PARAMS_ADDR))
        .map_err(|e| FluxError::Boot(format!("read zero page: {e}")))?;
    mem.write_at(memory::BOOT_PARAMS_ADDR, &zero)?;

    // 64-bit bzImage entry is kernel_load + 0x200; ELF uses kernel_load as entry.
    let entry_rip = if loader_result.setup_header.is_some() {
        loader_result.kernel_load.0 + 0x200
    } else {
        loader_result.kernel_load.0
    };
    notes.push(format!(
        "entry rip={entry_rip:#x} kernel_load={:#x} kernel_end={:#x}",
        loader_result.kernel_load.0, loader_result.kernel_end
    ));

    Ok(BootInfo {
        entry_rip,
        boot_params_gpa: Some(memory::BOOT_PARAMS_ADDR),
        notes,
    })
}

#[cfg(target_os = "linux")]
fn copy_mmap_to_guest(
    gm: &vm_memory::GuestMemoryMmap<()>,
    mem: &mut GuestMemory,
) -> Result<()> {
    use vm_memory::{Bytes, GuestAddress};
    const CHUNK: usize = 1024 * 1024;
    let total = mem.len();
    let mut offset = 0usize;
    while offset < total {
        let n = (total - offset).min(CHUNK);
        let mut buf = vec![0u8; n];
        gm.read(&mut buf, GuestAddress(offset as u64))
            .map_err(|e| FluxError::Boot(format!("gm read @ {offset:#x}: {e}")))?;
        if buf.iter().any(|&b| b != 0) {
            mem.write_at(offset as u64, &buf)?;
        }
        offset += n;
    }
    Ok(())
}

fn write_linux_cmdline(mem: &mut GuestMemory, cmdline: &str) -> Result<()> {
    let mut bytes = cmdline.as_bytes().to_vec();
    bytes.push(0);
    mem.write_at(CMDLINE_GPA, &bytes)
}

/// Minimal zero-page for the raw-dump fallback (RSI still points here).
fn write_minimal_boot_params(mem: &mut GuestMemory, cfg: &VmConfig, initrd_len: u32) -> Result<()> {
    let mut page = vec![0u8; 4096];
    // Offsets from arch/x86 bootparam.h (setup_header starts at 0x1f1):
    page[0x228..0x22c].copy_from_slice(&(CMDLINE_GPA as u32).to_le_bytes());
    page[0x238..0x23c].copy_from_slice(&((cfg.cmdline.len() as u32) + 1).to_le_bytes());
    if initrd_len > 0 {
        page[0x218..0x21c].copy_from_slice(&(memory::INITRD_ADDR as u32).to_le_bytes());
        page[0x21c..0x220].copy_from_slice(&initrd_len.to_le_bytes());
    }
    page[0x1e8] = 1; // e820_entries
    page[0x2d0..0x2d8].copy_from_slice(&0u64.to_le_bytes());
    page[0x2d8..0x2e0].copy_from_slice(&(mem.len() as u64).to_le_bytes());
    page[0x2e0..0x2e4].copy_from_slice(&1u32.to_le_bytes()); // E820_RAM
    mem.write_at(memory::BOOT_PARAMS_ADDR, &page)
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
