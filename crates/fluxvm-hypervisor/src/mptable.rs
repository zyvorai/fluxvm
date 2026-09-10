// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal Intel MP floating-pointer + config table so Linux can find the
//! local APIC / IOAPIC without ACPI (Firecracker-style bare-metal boot).

use crate::error::Result;
use crate::memory::GuestMemory;

/// Place the floating pointer in the last KB of the EBDA-ish low RAM window.
pub const MPFLOAT_GPA: u64 = 0x0009_FC00;
pub const IOAPIC_ADDR: u32 = 0xfec0_0000;
pub const LAPIC_ADDR: u32 = 0xfee0_0000;

#[repr(C, packed)]
struct MpFloatingPointer {
    signature: [u8; 4], // "_MP_"
    phys_addr: u32,
    length: u8, // paragraphs
    spec_rev: u8,
    checksum: u8,
    feature1: u8,
    feature2: u8,
    feature3: u8,
    feature4: u8,
    feature5: u8,
}

#[repr(C, packed)]
struct MpConfigTableHeader {
    signature: [u8; 4], // "PCMP"
    base_table_length: u16,
    spec_rev: u8,
    checksum: u8,
    oem_id: [u8; 8],
    product_id: [u8; 12],
    oem_table_ptr: u32,
    oem_table_size: u16,
    entry_count: u16,
    local_apic_addr: u32,
    ext_table_length: u16,
    ext_table_checksum: u8,
    reserved: u8,
}

#[repr(C, packed)]
struct MpProcessor {
    entry_type: u8, // 0
    local_apic_id: u8,
    local_apic_version: u8,
    cpu_flags: u8, // bit0=en, bit1=bsp
    cpu_signature: u32,
    feature_flags: u32,
    reserved: [u32; 2],
}

#[repr(C, packed)]
struct MpBus {
    entry_type: u8, // 1
    bus_id: u8,
    bus_type: [u8; 6],
}

#[repr(C, packed)]
struct MpIoApic {
    entry_type: u8, // 2
    id: u8,
    version: u8,
    flags: u8, // bit0=en
    addr: u32,
}

#[repr(C, packed)]
struct MpIoInterrupt {
    entry_type: u8, // 3
    interrupt_type: u8, // 0 = INT
    flags: u16,
    source_bus_id: u8,
    source_bus_irq: u8,
    dest_ioapic_id: u8,
    dest_ioapic_intin: u8,
}

#[repr(C, packed)]
struct MpLocalInterrupt {
    entry_type: u8, // 4
    interrupt_type: u8,
    flags: u16,
    source_bus_id: u8,
    source_bus_irq: u8,
    dest_lapic_id: u8,
    dest_lapic_lintin: u8,
}

fn checksum(bytes: &[u8]) -> u8 {
    let mut s: u8 = 0;
    for b in bytes {
        s = s.wrapping_add(*b);
    }
    s.wrapping_neg()
}

fn as_bytes<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((v as *const T) as *const u8, std::mem::size_of::<T>()) }
}

/// Write MP floating pointer + config table describing all `num_cpus`
/// processors (clamped to 1..=8), with `local_apic_id: i` matching the
/// initial APIC ID each real KVM vCPU is created with (see kvm.rs).
pub fn write_mptable(mem: &mut GuestMemory, num_cpus: u8) -> Result<()> {
    let cpus = num_cpus.max(1).min(8);
    let mut table: Vec<u8> = Vec::with_capacity(256);

    let header_placeholder = MpConfigTableHeader {
        signature: *b"PCMP",
        base_table_length: 0, // fill later
        spec_rev: 4,
        checksum: 0,
        oem_id: *b"ZYVOR   ",
        product_id: *b"FLUXVM      ",
        oem_table_ptr: 0,
        oem_table_size: 0,
        entry_count: 0, // fill later
        local_apic_addr: LAPIC_ADDR,
        ext_table_length: 0,
        ext_table_checksum: 0,
        reserved: 0,
    };
    table.extend_from_slice(as_bytes(&header_placeholder));

    let mut entries: u16 = 0;
    for i in 0..cpus {
        let cpu = MpProcessor {
            entry_type: 0,
            local_apic_id: i,
            local_apic_version: 0x14,
            cpu_flags: if i == 0 { 0b11 } else { 0b01 }, // enable + BSP for 0
            cpu_signature: 0x600, // generic
            feature_flags: 0x201, // FPU + APIC
            reserved: [0, 0],
        };
        table.extend_from_slice(as_bytes(&cpu));
        entries += 1;
    }

    let isa = MpBus {
        entry_type: 1,
        bus_id: 0,
        bus_type: *b"ISA   ",
    };
    table.extend_from_slice(as_bytes(&isa));
    entries += 1;

    let ioapic = MpIoApic {
        entry_type: 2,
        id: 0,
        version: 0x17,
        flags: 1,
        addr: IOAPIC_ADDR,
    };
    table.extend_from_slice(as_bytes(&ioapic));
    entries += 1;

    // Identity-map ISA IRQs 0..15 → IOAPIC pins (except IRQ2 cascade).
    for irq in 0u8..16 {
        if irq == 2 {
            continue;
        }
        let pin = if irq < 2 { irq } else { irq };
        let ent = MpIoInterrupt {
            entry_type: 3,
            interrupt_type: 0,
            flags: 0, // conforms
            source_bus_id: 0,
            source_bus_irq: irq,
            dest_ioapic_id: 0,
            dest_ioapic_intin: pin,
        };
        table.extend_from_slice(as_bytes(&ent));
        entries += 1;
    }

    // ExtINT + NMI local interrupts (Firecracker-style).
    let lint0 = MpLocalInterrupt {
        entry_type: 4,
        interrupt_type: 3, // ExtINT
        flags: 0,
        source_bus_id: 0,
        source_bus_irq: 0,
        dest_lapic_id: 0xff, // all
        dest_lapic_lintin: 0,
    };
    table.extend_from_slice(as_bytes(&lint0));
    entries += 1;
    let lint1 = MpLocalInterrupt {
        entry_type: 4,
        interrupt_type: 1, // NMI
        flags: 0,
        source_bus_id: 0,
        source_bus_irq: 0,
        dest_lapic_id: 0xff,
        dest_lapic_lintin: 1,
    };
    table.extend_from_slice(as_bytes(&lint1));
    entries += 1;

    let table_len = table.len() as u16;
    // Patch header length / entry_count / checksum.
    table[4..6].copy_from_slice(&table_len.to_le_bytes());
    table[34..36].copy_from_slice(&entries.to_le_bytes());
    table[7] = 0;
    table[7] = checksum(&table);

    // Config table sits just after the floating pointer (16 bytes).
    let cfg_gpa = MPFLOAT_GPA + 16;
    mem.write_at(cfg_gpa, &table)?;

    let mut fp = MpFloatingPointer {
        signature: *b"_MP_",
        phys_addr: cfg_gpa as u32,
        length: 1,
        spec_rev: 4,
        checksum: 0,
        feature1: 0,
        feature2: 0,
        feature3: 0,
        feature4: 0,
        feature5: 0,
    };
    let mut fp_bytes = as_bytes(&fp).to_vec();
    fp.checksum = checksum(&fp_bytes);
    fp_bytes = as_bytes(&fp).to_vec();
    mem.write_at(MPFLOAT_GPA, &fp_bytes)?;
    Ok(())
}
