// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::config::{GuestKind, VmConfig};
use crate::error::{FluxError, Result};
use crate::memory::{self, GuestMemory};

#[derive(Debug, Clone)]
pub struct BootInfo {
    pub entry_rip: u64,
    /// Zero-page / boot_params GPA — Linux 64-bit direct-boot expects this
    /// in RSI. Mutually exclusive with `pvh_start_info_gpa`.
    pub boot_params_gpa: Option<u64>,
    /// `hvm_start_info` GPA for PVH boot — expected in RBX at entry.
    /// Mutually exclusive with `boot_params_gpa`. When set, the guest's
    /// own startup_32/startup_64 code does the page-table/long-mode
    /// transition itself (see `kvm::KvmVm::setup_pvh_entry`), instead of
    /// our own hand-built identity map + direct long-mode jump.
    pub pvh_start_info_gpa: Option<u64>,
    pub notes: Vec<String>,
}

pub const CMDLINE_GPA: u64 = 0x0002_0000;

/// Firecracker-style cmdline append for virtio-over-MMIO devices.
///
/// On x86_64 there is no DT discovery: the guest only probes devices listed as
/// `virtio_mmio.device=<size>@<base>:<irq>` (see Firecracker `add_virtio_device_to_cmdline`).
pub fn append_virtio_mmio_cmdline(
    cmdline: &str,
    devices: &[(u64 /* base */, u64 /* len */, u32 /* irq */)],
) -> String {
    let mut cmd = cmdline.trim().to_string();
    for &(base, len, irq) in devices {
        let already = cmd.contains(&format!("@{base:#x}:"))
            || cmd.contains(&format!("@0x{base:08x}:"))
            || cmd.contains(&format!("@0x{base:x}:"));
        if already {
            continue;
        }
        if !cmd.is_empty() {
            cmd.push(' ');
        }
        cmd.push_str(&format!("virtio_mmio.device={len:#x}@{base:#x}:{irq}"));
    }
    cmd
}

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
        pvh_start_info_gpa: None,
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
    use crate::ffi;
    use std::fs::File;
    use vm_memory::{GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

    let path = cfg
        .kernel
        .as_ref()
        .ok_or_else(|| FluxError::Boot("no kernel path for linux-loader".into()))?;

    let mut notes = vec![
        "Linux boot via linux-loader (bzImage/ELF)".into(),
        format!("cmdline: {}", cfg.cmdline),
        format!("boot_params at GPA {:#x}", memory::BOOT_PARAMS_ADDR),
    ];

    // `gm` must be a *view over our real, already-KVM-registered* guest
    // RAM (`mem`), not a separate throwaway mapping. A previous version
    // of this function loaded the kernel into a freshly allocated
    // anonymous GuestMemoryMmap and then copied 1 MiB chunks into `mem`,
    // skipping any chunk that read back as all-zero as an optimization --
    // that heuristic silently dropped real code living in the same 1 MiB
    // chunk as unrelated all-zero padding under some condition, which
    // left holes in the loaded kernel image (confirmed live via a gdbstub
    // breakpoint landing inside a real function -- asm_exc_page_fault --
    // and finding it entirely zeroed out on the guest side while the
    // on-disk vmlinux has real code there). Firecracker and
    // cloud-hypervisor never do this two-step copy: they hand
    // Elf::load/BzImage::load their real, already-registered
    // GuestMemoryMmap directly. Wrapping our existing mmap'd pointer
    // (already registered with KVM via KVM_SET_USER_MEMORY_REGION) into a
    // GuestMemoryMmap view does the same here, making the loader write
    // straight into real guest RAM with no copy step to get wrong.
    let mmap_region = unsafe {
        MmapRegion::<()>::build_raw(
            mem.host_ptr(),
            mem.len(),
            ffi::PROT_READ | ffi::PROT_WRITE,
            ffi::MAP_SHARED,
        )
    }
    .map_err(|e| FluxError::Boot(format!("MmapRegion::build_raw: {e}")))?;
    let region = GuestRegionMmap::new(mmap_region, GuestAddress(0))
        .ok_or_else(|| FluxError::Boot("GuestRegionMmap::new failed".into()))?;
    let gm = GuestMemoryMmap::<()>::from_regions(vec![region])
        .map_err(|e| FluxError::Boot(format!("GuestMemoryMmap::from_regions: {e}")))?;

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

    // Prefer PVH: the kernel's own startup_32/startup_64 code does the
    // page-table construction and 32-to-64-bit transition itself, the
    // same as on a real PVH-aware hypervisor (Xen) or cloud-hypervisor --
    // sidestepping the entire class of bug our own hand-built identity
    // page tables + direct long-mode jump (the `else` branch below) can
    // have. Only ELF kernels carry the PVH entry-point note; bzImage
    // loader results always report PvhEntryNotPresent.
    if let linux_loader::loader::elf::PvhBootCapability::PvhEntryPresent(pvh_entry) =
        loader_result.pvh_boot_cap
    {
        return configure_pvh_boot(mem, &gm, pvh_entry, initrd_len, notes, cfg);
    }

    let mut params = boot_params::default();
    if let Some(hdr) = loader_result.setup_header {
        params.hdr = hdr;
    } else {
        // ELF path: synthesize a minimal setup_header so the kernel recognizes
        // the zero page (HdrS / boot_flag).
        params.hdr.boot_flag = 0xaa55;
        params.hdr.header = 0x5372_6448; // "HdrS"
        params.hdr.version = 0x20c;
        params.hdr.kernel_alignment = 0x0100_0000;
    }
    params.hdr.type_of_loader = 0xff;
    params.hdr.cmd_line_ptr = CMDLINE_GPA as u32;
    params.hdr.cmdline_size = (cfg.cmdline.len() as u32).saturating_add(1);
    if initrd_len > 0 {
        params.hdr.ramdisk_image = memory::INITRD_ADDR as u32;
        params.hdr.ramdisk_size = initrd_len;
    }
    fill_e820(&mut params, mem.len() as u64);

    let zero_page = GuestAddress(memory::BOOT_PARAMS_ADDR);
    let boot_cfg = BootParams::new::<boot_params>(&params, zero_page);
    LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap<()>>(&boot_cfg, &gm).map_err(|e| {
        FluxError::Boot(format!("write_bootparams: {e}"))
    })?;
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
        pvh_start_info_gpa: None,
        notes,
    })
}

/// Builds the `hvm_start_info` + memory map (+ initrd module, if any) PVH
/// boot needs and writes them into real guest RAM via
/// `PvhBootConfigurator`.
///
/// Memory map layout matches Firecracker (and the same idea as
/// cloud-hypervisor): low RAM, an explicit system reserved window for the
/// MP table / EBDA range, a PCI MMCONFIG reserved window, then himem.
/// PVH struct GPAs also match FC: start_info @ 0x6000, memmap @ 0x7000.
#[cfg(target_os = "linux")]
fn configure_pvh_boot(
    mem: &mut GuestMemory,
    gm: &vm_memory::GuestMemoryMmap<()>,
    pvh_entry: vm_memory::GuestAddress,
    initrd_len: u32,
    mut notes: Vec<String>,
    cfg: &VmConfig,
) -> Result<BootInfo> {
    use linux_loader::configurator::pvh::PvhBootConfigurator;
    use linux_loader::configurator::{BootConfigurator, BootParams};
    use linux_loader::loader::elf::start_info::{
        hvm_memmap_table_entry, hvm_modlist_entry, hvm_start_info, XEN_HVM_MEMMAP_TYPE_RAM,
        XEN_HVM_MEMMAP_TYPE_RESERVED, XEN_HVM_START_MAGIC_VALUE,
    };
    use vm_memory::{Address, GuestAddress};

    let rsdp_paddr = if cfg.acpi {
        match crate::acpi::write_tables(mem, cfg.cpus) {
            Ok(a) => {
                notes.push(format!("ACPI RSDP at GPA {a:#x} (Firecracker-style)"));
                a
            }
            Err(e) => {
                notes.push(format!("ACPI write failed: {e}"));
                0
            }
        }
    } else {
        0
    };

    let mem_size = mem.len() as u64;
    let mut memmap = vec![
        hvm_memmap_table_entry {
            addr: 0,
            size: memory::SYSTEM_MEM_START,
            type_: XEN_HVM_MEMMAP_TYPE_RAM,
            reserved: 0,
        },
        hvm_memmap_table_entry {
            addr: memory::SYSTEM_MEM_START,
            size: memory::SYSTEM_MEM_SIZE,
            type_: XEN_HVM_MEMMAP_TYPE_RESERVED,
            reserved: 0,
        },
        hvm_memmap_table_entry {
            addr: memory::PCI_MMCONFIG_START,
            size: memory::PCI_MMCONFIG_SIZE,
            type_: XEN_HVM_MEMMAP_TYPE_RESERVED,
            reserved: 0,
        },
    ];
    if mem_size > memory::HIMEM_START {
        memmap.push(hvm_memmap_table_entry {
            addr: memory::HIMEM_START,
            size: mem_size - memory::HIMEM_START,
            type_: XEN_HVM_MEMMAP_TYPE_RAM,
            reserved: 0,
        });
    }

    let modules = if initrd_len > 0 {
        vec![hvm_modlist_entry {
            paddr: memory::INITRD_ADDR,
            size: initrd_len as u64,
            cmdline_paddr: 0,
            reserved: 0,
        }]
    } else {
        Vec::new()
    };

    let mut start_info = hvm_start_info {
        magic: XEN_HVM_START_MAGIC_VALUE,
        version: 1,
        cmdline_paddr: CMDLINE_GPA,
        memmap_paddr: memory::MEMMAP_START,
        memmap_entries: memmap.len() as u32,
        rsdp_paddr,
        ..Default::default()
    };
    if !modules.is_empty() {
        start_info.nr_modules = modules.len() as u32;
        start_info.modlist_paddr = memory::MODLIST_START;
    }

    let mut boot_params =
        BootParams::new::<hvm_start_info>(&start_info, GuestAddress(memory::PVH_INFO_START));
    boot_params.set_sections::<hvm_memmap_table_entry>(&memmap, GuestAddress(memory::MEMMAP_START));
    if !modules.is_empty() {
        boot_params.set_modules::<hvm_modlist_entry>(&modules, GuestAddress(memory::MODLIST_START));
    }
    PvhBootConfigurator::write_bootparams::<vm_memory::GuestMemoryMmap<()>>(&boot_params, gm)
        .map_err(|e| FluxError::Boot(format!("PVH write_bootparams: {e}")))?;
    let _ = mem; // written through `gm`, a direct view over `mem`'s backing.

    notes.push(format!(
        "PVH boot: entry={:#x} start_info={:#x} memmap_entries={} (Firecracker layout)",
        pvh_entry.raw_value(),
        memory::PVH_INFO_START,
        memmap.len()
    ));

    Ok(BootInfo {
        entry_rip: pvh_entry.raw_value(),
        boot_params_gpa: None,
        pvh_start_info_gpa: Some(memory::PVH_INFO_START),
        notes,
    })
}

#[cfg(target_os = "linux")]
fn fill_e820(params: &mut linux_loader::loader::bootparam::boot_params, mem_size: u64) {
    // Same Firecracker / cloud-hypervisor layout as configure_pvh_boot.
    const E820_RAM: u32 = 1;
    const E820_RESERVED: u32 = 2;
    params.e820_entries = 0;

    let mut push = |addr: u64, size: u64, typ: u32| {
        let i = params.e820_entries as usize;
        if i >= params.e820_table.len() || size == 0 {
            return;
        }
        params.e820_table[i].addr = addr;
        params.e820_table[i].size = size;
        params.e820_table[i].r#type = typ;
        params.e820_entries += 1;
    };

    push(0, memory::SYSTEM_MEM_START.min(mem_size), E820_RAM);
    if mem_size > memory::SYSTEM_MEM_START {
        push(
            memory::SYSTEM_MEM_START,
            memory::SYSTEM_MEM_SIZE.min(mem_size.saturating_sub(memory::SYSTEM_MEM_START)),
            E820_RESERVED,
        );
    }
    push(
        memory::PCI_MMCONFIG_START,
        memory::PCI_MMCONFIG_SIZE,
        E820_RESERVED,
    );
    if mem_size > memory::HIMEM_START {
        push(
            memory::HIMEM_START,
            mem_size - memory::HIMEM_START,
            E820_RAM,
        );
    }
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
    // Firecracker-style e820 (see fill_e820).
    let mem_size = mem.len() as u64;
    let mut entries: Vec<(u64, u64, u32)> = Vec::new();
    entries.push((0, memory::SYSTEM_MEM_START.min(mem_size), 1));
    if mem_size > memory::SYSTEM_MEM_START {
        entries.push((
            memory::SYSTEM_MEM_START,
            memory::SYSTEM_MEM_SIZE.min(mem_size.saturating_sub(memory::SYSTEM_MEM_START)),
            2,
        ));
    }
    entries.push((memory::PCI_MMCONFIG_START, memory::PCI_MMCONFIG_SIZE, 2));
    if mem_size > memory::HIMEM_START {
        entries.push((memory::HIMEM_START, mem_size - memory::HIMEM_START, 1));
    }
    page[0x1e8] = entries.len() as u8;
    for (i, (addr, size, typ)) in entries.into_iter().enumerate() {
        let off = 0x2d0 + i * 20;
        page[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        page[off + 8..off + 16].copy_from_slice(&size.to_le_bytes());
        page[off + 16..off + 20].copy_from_slice(&typ.to_le_bytes());
    }
    mem.write_at(memory::BOOT_PARAMS_ADDR, &page)
}

fn prepare_windows(mem: &mut GuestMemory, cfg: &VmConfig) -> Result<BootInfo> {
    let mut notes = vec![
        "Windows path: OVMF/CLOUDHV.fd + ACPI + virtio-pci (cloud-hypervisor SoT)".into(),
    ];

    // CH-style: write ACPI early so firmware can find RSDP.
    match crate::acpi::write_tables(mem, cfg.cpus) {
        Ok(rsdp) => notes.push(format!("ACPI RSDP at {rsdp:#x}")),
        Err(e) => notes.push(format!("ACPI write failed: {e}")),
    }

    if let Some(path) = cfg.firmware.as_ref().or(cfg.kernel.as_ref()) {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            // Load below 4GiB top like a simplified pflash image mapping.
            let gpa = 0x0100_0000u64;
            if gpa as usize + bytes.len() < mem.len() {
                mem.write_at(gpa, &bytes)?;
            }
            notes.push(format!(
                "loaded firmware {} ({} bytes) at {gpa:#x}",
                path.display(),
                bytes.len()
            ));
        } else {
            notes.push(format!("firmware path {} missing", path.display()));
        }
    } else {
        notes.push("no --firmware provided (dry-run ok)".into());
    }

    notes.push("Enable --pci for ECAM window; full virtio-pci BARs are P2 follow-up".into());
    notes.push(acpi_requirements().into());

    Ok(BootInfo {
        entry_rip: 0xFFFF_FFF0,
        boot_params_gpa: None,
        pvh_start_info_gpa: None,
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

#[cfg(test)]
mod tests {
    use super::append_virtio_mmio_cmdline;

    #[test]
    fn append_virtio_mmio_cmdline_adds_and_dedups() {
        let once = append_virtio_mmio_cmdline("console=ttyS0", &[(0xfeb0_0000, 0x200, 5)]);
        assert!(once.contains("virtio_mmio.device=0x200@0xfeb00000:5"));
        let twice = append_virtio_mmio_cmdline(&once, &[(0xfeb0_0000, 0x200, 5)]);
        assert_eq!(once, twice);
        let both = append_virtio_mmio_cmdline(
            "console=ttyS0 root=/dev/vda",
            &[(0xfeb0_0000, 0x200, 5), (0xfeb0_0200, 0x200, 6)],
        );
        assert!(both.contains("@0xfeb00000:5"));
        assert!(both.contains("@0xfeb00200:6"));
    }
}
