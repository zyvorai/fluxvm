// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal PCI ECAM window (cloud-hypervisor / FC `--enable-pci` path).
//! Reserves MMCONFIG; returns zeros for unpopulated config space so Linux
//! with virtio-pci can probe without faulting. Full virtio-pci BAR wiring
//! is P2 follow-up — this establishes the ECAM SoT layout.

use crate::bus::MmioDevice;
use crate::error::Result;
use crate::memory::{PCI_MMCONFIG_SIZE, PCI_MMCONFIG_START};

pub struct PciEcam {
    base: u64,
    size: u64,
}

impl PciEcam {
    pub fn new() -> Self {
        Self {
            base: PCI_MMCONFIG_START,
            size: PCI_MMCONFIG_SIZE,
        }
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

    fn mmio_write(&self, _addr: u64, _data: &[u8]) -> Result<()> {
        Ok(())
    }

    fn mmio_read(&self, _addr: u64, data: &mut [u8]) -> Result<()> {
        data.fill(0xff); // empty slot
        Ok(())
    }
}
