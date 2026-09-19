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

/// Install RSDP + XSDT + FADT + MADT (+ MCFG for ECAM). Returns RSDP GPA.
pub fn write_tables(mem: &mut GuestMemory, num_cpus: u8) -> Result<u64> {
    // Layout inside [SYSTEM_MEM_START, RSDP_ADDR):
    //   0x9fc00 MP table (existing)
    //   0xa0000 FADT
    //   0xa1000 MADT
    //   0xa2000 XSDT
    //   0xa3000 MCFG (H2 — points at PCI_MMCONFIG_START)
    // RSDP at 0xe0000
    const FADT: u64 = 0xa_0000;
    const MADT: u64 = 0xa_1000;
    const XSDT: u64 = 0xa_2000;
    const MCFG: u64 = 0xa_3000;
    const DSDT_GPA: u64 = 0xa_4000;
    let rsdp = memory::RSDP_ADDR;

    let dsdt = dsdt_table();
    mem.write_at(DSDT_GPA, &dsdt)?;

    // ---- FADT (FACP) — PM1a blocks plus DSDT and the I/O reset register.
    let mut fadt = vec![0u8; 276];
    write_header(&mut fadt, b"FACP", 276, 5);
    fadt[40..44].copy_from_slice(&(DSDT_GPA as u32).to_le_bytes());
    fadt[45] = 1; // preferred_pm_profile = desktop
                  // pm1a_evt_blk @ 0x1000, len 4; pm1a_cnt_blk @ 0x1004, len 2 (legacy).
    fadt[56..60].copy_from_slice(&0x1000u32.to_le_bytes());
    fadt[64..68].copy_from_slice(&0x1004u32.to_le_bytes());
    fadt[88] = 4; // pm1_evt_len
    fadt[89] = 2; // pm1_cnt_len
                  // Flags bit 10 = RESET_REG_SUP.
    fadt[112..116].copy_from_slice(&(1u32 << 10).to_le_bytes());
    // RESET_REG: System I/O, 8-bit, port 0xCF9, value 0x06 (ACPI reset).
    fadt[116] = 1; // SystemIO
    fadt[117] = 8; // bit width
    fadt[118] = 0;
    fadt[119] = 1; // byte access
    fadt[120..128].copy_from_slice(&0xCF9u64.to_le_bytes());
    fadt[128] = 0x06;
    fadt[140..148].copy_from_slice(&DSDT_GPA.to_le_bytes()); // X_DSDT
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

    // ---- MCFG (H2) — ECAM base for segment 0, buses 0–0 ----
    // struct: header(36) + reserved(8) + allocation(16) = 60
    let mut mcfg = vec![0u8; 60];
    write_header(&mut mcfg, b"MCFG", 60, 1);
    // allocation @ 44: base_addr(8), segment(2), start_bus(1), end_bus(1), reserved(4)
    mcfg[44..52].copy_from_slice(&memory::PCI_MMCONFIG_START.to_le_bytes());
    mcfg[52..54].copy_from_slice(&0u16.to_le_bytes()); // segment
    mcfg[54] = 0; // start bus
    mcfg[55] = 0; // end bus
    mcfg[9] = checksum(&mcfg);
    mem.write_at(MCFG, &mcfg)?;

    // ---- XSDT (FADT + MADT + MCFG) ----
    let xsdt_len = 36 + 8 * 3;
    let mut xsdt = vec![0u8; xsdt_len];
    write_header(&mut xsdt, b"XSDT", xsdt_len as u32, 1);
    xsdt[36..44].copy_from_slice(&FADT.to_le_bytes());
    xsdt[44..52].copy_from_slice(&MADT.to_le_bytes());
    xsdt[52..60].copy_from_slice(&MCFG.to_le_bytes());
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

/// True when a guest write to port `0xCF9` is the ACPI reset value from FADT.
pub fn is_acpi_reset(port: u16, data: &[u8]) -> bool {
    port == 0xCF9 && data.first().is_some_and(|b| *b & 0x04 != 0)
}

/// DSDT with `\_SB.PCI0` (`PNP0A08` / `PNP0A03`) and a `_CRS` covering the
/// ECAM window plus the virtio BAR0 MMIO window.
pub fn dsdt_table() -> Vec<u8> {
    let aml = dsdt_aml();
    let len = (36 + aml.len()) as u32;
    let mut table = vec![0u8; len as usize];
    write_header(&mut table, b"DSDT", len, 2);
    table[36..].copy_from_slice(&aml);
    table[9] = checksum(&table);
    table
}

fn name_seg(seg: &str) -> [u8; 4] {
    let mut out = [b'_'; 4];
    for (i, b) in seg.bytes().take(4).enumerate() {
        out[i] = b;
    }
    out
}

fn eisa_id(id: &str) -> u32 {
    let b = id.as_bytes();
    let d1 = (b[0] - 0x40) as u32;
    let d2 = (b[1] - 0x40) as u32;
    let d3 = (b[2] - 0x40) as u32;
    let prod = u32::from_str_radix(&id[3..7], 16).unwrap_or(0);
    (d1 << 26) | (d2 << 21) | (d3 << 16) | (prod & 0xffff)
}

fn encode_pkg_len(len: usize) -> Vec<u8> {
    if len < 0x40 {
        vec![len as u8]
    } else if len < 0x1000 {
        vec![((len & 0x0F) as u8) | 0x40, (len >> 4) as u8]
    } else {
        vec![
            ((len & 0x0F) as u8) | 0x80,
            ((len >> 4) & 0xFF) as u8,
            ((len >> 12) & 0xFF) as u8,
        ]
    }
}

fn push_pkg(op: &[u8], name: &[u8], body: &[u8]) -> Vec<u8> {
    let payload = name.len() + body.len();
    let mut width = 1usize;
    loop {
        let enc = encode_pkg_len(width + payload);
        if enc.len() == width {
            let mut out = Vec::with_capacity(op.len() + enc.len() + payload);
            out.extend_from_slice(op);
            out.extend(enc);
            out.extend_from_slice(name);
            out.extend_from_slice(body);
            return out;
        }
        width = enc.len();
    }
}

fn memory32_fixed(base: u32, length: u32) -> Vec<u8> {
    let mut d = vec![0x86, 0x09, 0x00, 0x01];
    d.extend_from_slice(&base.to_le_bytes());
    d.extend_from_slice(&length.to_le_bytes());
    d
}

fn dsdt_aml() -> Vec<u8> {
    let mut crs_bytes = memory32_fixed(memory::PCI_MMCONFIG_START as u32, 0x0010_0000);
    crs_bytes.extend(memory32_fixed(memory::MMIO_WINDOW as u32, 0x1000));
    crs_bytes.extend_from_slice(&[0x79, 0x00]); // end tag

    let mut crs = vec![
        0x11,
        (1 + 2 + crs_bytes.len()) as u8,
        0x0A,
        crs_bytes.len() as u8,
    ];
    crs.extend(crs_bytes);

    let mut dev_body = Vec::new();
    for (name, id) in [("_HID", "PNP0A08"), ("_CID", "PNP0A03")] {
        dev_body.push(0x08);
        dev_body.extend(name_seg(name));
        dev_body.push(0x0C);
        dev_body.extend(eisa_id(id).to_le_bytes());
    }
    dev_body.push(0x08);
    dev_body.extend(name_seg("_UID"));
    dev_body.push(0x00); // Zero
    dev_body.push(0x08);
    dev_body.extend(name_seg("_STA"));
    dev_body.extend([0x0A, 0x0F]);
    dev_body.push(0x08);
    dev_body.extend(name_seg("_CRS"));
    dev_body.extend(crs);

    let device = push_pkg(&[0x5B, 0x82], &name_seg("PCI0"), &dev_body);
    let mut sb_name = vec![0x5C];
    sb_name.extend(name_seg("_SB_"));
    push_pkg(&[0x10], &sb_name, &device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsdt_checksums_and_names_pci0() {
        let table = dsdt_table();
        assert_eq!(&table[0..4], b"DSDT");
        let sum = table.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        assert_eq!(sum, 0);
        assert!(table.windows(4).any(|w| w == b"PCI0"));
        let hid = eisa_id("PNP0A08").to_le_bytes();
        let cid = eisa_id("PNP0A03").to_le_bytes();
        assert!(
            table.windows(4).any(|w| w == hid),
            "DSDT missing PCI Express _HID"
        );
        assert!(table.windows(4).any(|w| w == cid), "DSDT missing PCI _CID");
    }

    #[test]
    fn acpi_reset_recognizes_cf9() {
        assert!(is_acpi_reset(0xCF9, &[0x06]));
        assert!(is_acpi_reset(0xCF9, &[0x0E]));
        assert!(!is_acpi_reset(0xCF9, &[0x00]));
        assert!(!is_acpi_reset(0x64, &[0x06]));
    }
}
