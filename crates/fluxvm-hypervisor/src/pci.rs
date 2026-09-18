// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! PCI ECAM + minimal virtio-pci BAR wiring (H2).
//!
//! `--pci` reserves MMCONFIG and exposes one modern virtio-net device at
//! BDF `00:01.0` with BARs that alias the existing virtio-mmio net window so
//! Linux/`virtio_pci` can probe. Full MSI-X / multi-device / Windows virtio-win
//! remain CH SoT until those land; this closes the ECAM+BAR gap for Linux
//! guests and Windows prep.

use crate::bus::MmioDevice;
use crate::error::Result;
use crate::memory::{MMIO_WINDOW, PCI_MMCONFIG_SIZE, PCI_MMCONFIG_START};
use std::sync::Mutex;

/// Virtio vendor / modern net device ids (PCI SIG / OASIS).
const VENDOR_REDHAT: u16 = 0x1af4;
const DEVICE_VIRTIO_NET: u16 = 0x1041;
const DEVICE_CLASS_NET: u32 = 0x02_0000; // class=net, subclass=ethernet, prog=0

/// BAR0 = common+notify+ISR+device cfg window (4 KiB), aliases MMIO_WINDOW.
const BAR0_SIZE: u32 = 0x1000;
/// Capability offsets inside config space.
const CAP_COMMON_CFG: u8 = 0x40;
const CAP_NOTIFY_CFG: u8 = 0x50;
const CAP_ISR_CFG: u8 = 0x60;
const CAP_DEVICE_CFG: u8 = 0x70;

pub struct PciEcam {
    base: u64,
    size: u64,
    /// 4 KiB config space for function 00:01.0 (bus0/dev1/fn0).
    cfg: Mutex<[u8; 4096]>,
}

impl PciEcam {
    pub fn new() -> Self {
        let mut cfg = [0xffu8; 4096];
        // Type-0 header for virtio-net at 00:01.0
        write_u16(&mut cfg, 0x00, VENDOR_REDHAT);
        write_u16(&mut cfg, 0x02, DEVICE_VIRTIO_NET);
        write_u16(&mut cfg, 0x04, 0x0000); // command — guest enables Memory Space
        write_u16(&mut cfg, 0x06, 0x0010); // status — Capabilities List
        cfg[0x08] = 0x01; // revision
        cfg[0x09] = 0x00;
        cfg[0x0a] = 0x00;
        cfg[0x0b] = 0x02; // class code network
        cfg[0x0e] = 0x00; // header type 0
                          // BAR0: 32-bit memory, non-prefetch, initially sized via 0xffffffff probe
        write_u32(&mut cfg, 0x10, (MMIO_WINDOW as u32) | 0x0);
        write_u32(&mut cfg, 0x14, 0);
        write_u32(&mut cfg, 0x18, 0);
        write_u32(&mut cfg, 0x1c, 0);
        write_u32(&mut cfg, 0x20, 0);
        write_u32(&mut cfg, 0x24, 0);
        write_u16(&mut cfg, 0x2c, VENDOR_REDHAT); // subsystem vendor
        write_u16(&mut cfg, 0x2e, DEVICE_VIRTIO_NET);
        cfg[0x34] = CAP_COMMON_CFG; // capabilities pointer
        cfg[0x3d] = 5; // interrupt pin INTA
        cfg[0x3c] = 5; // interrupt line (GSI 5 — matches virtio-mmio net)

        // Virtio-pci modern capability chain (common → notify → isr → device)
        write_virtio_cap(
            &mut cfg,
            CAP_COMMON_CFG,
            1, /* VIRTIO_PCI_CAP_COMMON_CFG */
            CAP_NOTIFY_CFG,
            0,
            0,
            0x000,
            0x56,
        );
        write_virtio_cap(
            &mut cfg,
            CAP_NOTIFY_CFG,
            2, /* NOTIFY */
            CAP_ISR_CFG,
            0,
            0,
            0x100,
            0x10,
        );
        // notify_off_multiplier after the cap (virtio_pci_notify_cap)
        write_u32(&mut cfg, CAP_NOTIFY_CFG as usize + 16, 4);
        write_virtio_cap(
            &mut cfg,
            CAP_ISR_CFG,
            3, /* ISR */
            CAP_DEVICE_CFG,
            0,
            0,
            0x200,
            0x04,
        );
        write_virtio_cap(
            &mut cfg,
            CAP_DEVICE_CFG,
            4, /* DEVICE_CFG */
            0, /* end */
            0,
            0,
            0x300,
            0x100,
        );

        let _ = DEVICE_CLASS_NET;
        let _ = BAR0_SIZE;
        Self {
            base: PCI_MMCONFIG_START,
            size: PCI_MMCONFIG_SIZE,
            cfg: Mutex::new(cfg),
        }
    }

    fn bdf_offset(addr: u64) -> Option<(u8, u8, u8, usize)> {
        let rel = addr.checked_sub(PCI_MMCONFIG_START)?;
        if rel >= PCI_MMCONFIG_SIZE {
            return None;
        }
        // ECAM: bus<<20 | device<<15 | function<<12 | reg
        let bus = ((rel >> 20) & 0xff) as u8;
        let dev = ((rel >> 15) & 0x1f) as u8;
        let func = ((rel >> 12) & 0x07) as u8;
        let reg = (rel & 0xfff) as usize;
        Some((bus, dev, func, reg))
    }
}

impl Default for PciEcam {
    fn default() -> Self {
        Self::new()
    }
}

impl MmioDevice for PciEcam {
    fn name(&self) -> &'static str {
        "pci-ecam"
    }

    fn mmio_range(&self) -> std::ops::RangeInclusive<u64> {
        self.base..=self.base + self.size - 1
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) -> Result<()> {
        let Some((bus, dev, func, reg)) = Self::bdf_offset(addr) else {
            return Ok(());
        };
        // Only 00:01.0 is populated.
        if bus != 0 || dev != 1 || func != 0 {
            return Ok(());
        }
        let mut cfg = self.cfg.lock().unwrap();
        // BAR0 size probe: write 0xffffffff → next read returns size mask.
        if reg == 0x10 && data.len() >= 4 {
            let val = u32::from_le_bytes(data[..4].try_into().unwrap());
            if val == 0xffff_ffff {
                write_u32(cfg.as_mut(), 0x10, (!(BAR0_SIZE - 1)) | 0x0);
                return Ok(());
            }
            // Guest programmed BAR — keep low bits clear (memory BAR).
            write_u32(cfg.as_mut(), 0x10, val & !(BAR0_SIZE - 1));
            return Ok(());
        }
        if reg == 0x04 && data.len() >= 2 {
            // Command register
            let cur = read_u16(cfg.as_ref(), 0x04);
            let val = u16::from_le_bytes(data[..2].try_into().unwrap());
            write_u16(cfg.as_mut(), 0x04, (cur & !0x0007) | (val & 0x0007));
            return Ok(());
        }
        for (i, b) in data.iter().enumerate() {
            if reg + i < cfg.len() {
                // Ignore writes into read-only identity / cap structs except BAR/command.
                if (0x40..0x80).contains(&(reg + i)) {
                    continue;
                }
                if reg + i >= 0x10 {
                    cfg[reg + i] = *b;
                }
            }
        }
        Ok(())
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        let Some((bus, dev, func, reg)) = Self::bdf_offset(addr) else {
            data.fill(0xff);
            return Ok(());
        };
        if bus != 0 || dev != 1 || func != 0 {
            data.fill(0xff);
            return Ok(());
        }
        let cfg = self.cfg.lock().unwrap();
        for (i, b) in data.iter_mut().enumerate() {
            *b = if reg + i < cfg.len() {
                cfg[reg + i]
            } else {
                0xff
            };
        }
        Ok(())
    }
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

fn write_virtio_cap(
    cfg: &mut [u8],
    off: u8,
    cfg_type: u8,
    next: u8,
    bar: u8,
    _id: u8,
    offset: u32,
    length: u32,
) {
    let o = off as usize;
    cfg[o] = 0x09; // PCI_CAP_ID_VNDR
    cfg[o + 1] = next;
    cfg[o + 2] = 16; // cap length (common fields)
    cfg[o + 3] = cfg_type;
    cfg[o + 4] = bar;
    cfg[o + 5] = 0;
    cfg[o + 6] = 0;
    cfg[o + 7] = 0;
    write_u32(cfg, o + 8, offset);
    write_u32(cfg, o + 12, length);
}
