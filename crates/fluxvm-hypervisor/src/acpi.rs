// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal Firecracker-style ACPI tables for PVH Linux guests.
//! Writes RSDP @ RSDP_ADDR and XSDT/FADT/MADT into SYSTEM_MEM.

use crate::error::Result;
use crate::memory::{self, GuestMemory};
use crate::mptable::{IOAPIC_ADDR, LAPIC_ADDR};

fn checksum(buf: &[u8]) -> u8 {
    let mut s: u8 = 0;
    for b in buf {
        s = s.wrapping_add(*b);
    }
    (!s).wrapping_add(1)
}

fn write_header(buf: &mut [u8], sig: &[u8; 4], len: u32, rev: u8) {
    buf[0..4].copy_from_slice(sig);
    buf[4..8].copy_from_slice(&len.to_le_bytes());
    buf[8] = rev;
    buf[9] = 0; // checksum filled later
    buf[10..16].copy_from_slice(b"FLUXVM");
    buf[16..24].copy_from_slice(b"FLUXVM  ");
    buf[24..28].copy_from_slice(&1u32.to_le_bytes());
    buf[28..32].copy_from_slice(b"FLVM");
    buf[32..36].copy_from_slice(&1u32.to_le_bytes());
}

/// Install RSDP + XSDT + FADT + MADT. Returns RSDP GPA for PVH `rsdp_paddr`.
pub fn write_tables(mem: &mut GuestMemory, num_cpus: u8) -> Result<u64> {
    // Layout inside [SYSTEM_MEM_START, RSDP_ADDR):
    //   0x9fc00 MP table (existing)
    //   0xa0000 FADT
    //   0xa1000 MADT
    //   0xa2000 XSDT
    // RSDP at 0xe0000
    const FADT: u64 = 0xa_0000;
    const MADT: u64 = 0xa_1000;
    const XSDT: u64 = 0xa_2000;
    let rsdp = memory::RSDP_ADDR;

    // ---- FADT (FACP) — include PM1a blocks so the interpreter can start.
    // Addresses sit in the reserved system window (unused PIO-like placeholders
    // matching Firecracker's "tables present" contract; full AML is P2).
    let mut fadt = vec![0u8; 276];
    write_header(&mut fadt, b"FACP", 276, 5);
    // pm1a_evt_blk @ 0x1000, len 4; pm1a_cnt_blk @ 0x1004, len 2 (legacy).
    fadt[56..60].copy_from_slice(&0x1000u32.to_le_bytes());
    fadt[64..68].copy_from_slice(&0x1004u32.to_le_bytes());
    fadt[88] = 4; // pm1_evt_len
    fadt[89] = 2; // pm1_cnt_len
    fadt[40..44].copy_from_slice(&1u32.to_le_bytes()); // preferred_pm_profile
    fadt[109] = 1 << 0; // RESET_REG_SUP
    fadt[9] = checksum(&fadt);
    mem.write_at(FADT, &fadt)?;

    // ---- MADT ----
    let madt_len = 44u32 + 8 * num_cpus as u32 + 12;
    let mut madt = vec![0u8; madt_len as usize];
    write_header(&mut madt, b"APIC", madt_len, 3);
    madt[36..40].copy_from_slice(&LAPIC_ADDR.to_le_bytes());
    madt[40..44].copy_from_slice(&1u32.to_le_bytes()); // PCAT_COMPAT
    let mut off = 44usize;
    for i in 0..num_cpus {
        madt[off] = 0; // Local APIC
        madt[off + 1] = 8;
        madt[off + 2] = i; // ACPI processor id
        madt[off + 3] = i; // APIC id
        madt[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes()); // enabled
        off += 8;
    }
    madt[off] = 1; // IO APIC
    madt[off + 1] = 12;
    madt[off + 2] = 0; // IOAPIC id
    madt[off + 3] = 0;
    madt[off + 4..off + 8].copy_from_slice(&IOAPIC_ADDR.to_le_bytes());
    madt[off + 8..off + 12].copy_from_slice(&0u32.to_le_bytes()); // GSI base
    madt[9] = checksum(&madt);
    mem.write_at(MADT, &madt)?;

    // ---- XSDT ----
    let xsdt_len = 36 + 8 * 2;
    let mut xsdt = vec![0u8; xsdt_len];
    write_header(&mut xsdt, b"XSDT", xsdt_len as u32, 1);
    xsdt[36..44].copy_from_slice(&FADT.to_le_bytes());
    xsdt[44..52].copy_from_slice(&MADT.to_le_bytes());
    xsdt[9] = checksum(&xsdt);
    mem.write_at(XSDT, &xsdt)?;

    // ---- RSDP (ACPI 2.0, 36 bytes) ----
    let mut rsdp_buf = vec![0u8; 36];
    rsdp_buf[0..8].copy_from_slice(b"RSD PTR ");
    rsdp_buf[9..15].copy_from_slice(b"FLUXVM");
    rsdp_buf[15] = 2; // revision
    rsdp_buf[16..20].copy_from_slice(&0u32.to_le_bytes()); // rsdt (unused)
    rsdp_buf[20..24].copy_from_slice(&36u32.to_le_bytes());
    rsdp_buf[24..32].copy_from_slice(&XSDT.to_le_bytes());
    rsdp_buf[8] = checksum(&rsdp_buf[0..20]);
    rsdp_buf[32] = checksum(&rsdp_buf);
    mem.write_at(rsdp, &rsdp_buf)?;

    Ok(rsdp)
}
