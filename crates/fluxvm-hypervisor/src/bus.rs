// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use std::sync::Arc;

pub trait PioDevice: Send + Sync {
    fn name(&self) -> &'static str;
    fn port_range(&self) -> std::ops::RangeInclusive<u16>;
    fn io_out(&self, port: u16, data: &[u8]) -> Result<()>;
    fn io_in(&self, port: u16, data: &mut [u8]) -> Result<()>;
}

pub trait MmioDevice: Send + Sync {
    fn name(&self) -> &'static str;
    fn mmio_range(&self) -> std::ops::RangeInclusive<u64>;
    fn mmio_write(&self, addr: u64, data: &[u8]) -> Result<()>;
    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> Result<()>;
}

#[derive(Default)]
pub struct Bus {
    pio: Vec<Arc<dyn PioDevice>>,
    mmio: Vec<Arc<dyn MmioDevice>>,
}

impl Bus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_pio(&mut self, dev: Arc<dyn PioDevice>) {
        eprintln!(
            "[bus] PIO  {:#06x}-{:#06x}  {}",
            dev.port_range().start(),
            dev.port_range().end(),
            dev.name()
        );
        self.pio.push(dev);
    }

    pub fn add_mmio(&mut self, dev: Arc<dyn MmioDevice>) {
        eprintln!(
            "[bus] MMIO {:#010x}-{:#010x}  {}",
            dev.mmio_range().start(),
            dev.mmio_range().end(),
            dev.name()
        );
        self.mmio.push(dev);
    }

    pub fn pio_write(&self, port: u16, data: &[u8]) -> Result<()> {
        for d in &self.pio {
            if d.port_range().contains(&port) {
                return d.io_out(port, data);
            }
        }
        Ok(())
    }

    pub fn pio_read(&self, port: u16, data: &mut [u8]) -> Result<()> {
        for d in &self.pio {
            if d.port_range().contains(&port) {
                return d.io_in(port, data);
            }
        }
        data.fill(0xff);
        Ok(())
    }

    pub fn mmio_write(&self, addr: u64, data: &[u8]) -> Result<()> {
        for d in &self.mmio {
            if d.mmio_range().contains(&addr) {
                return d.mmio_write(addr, data);
            }
        }
        Err(FluxError::Device {
            device: "mmio",
            msg: format!("unhandled write {addr:#x}"),
        })
    }

    pub fn mmio_read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        for d in &self.mmio {
            if d.mmio_range().contains(&addr) {
                return d.mmio_read(addr, data);
            }
        }
        data.fill(0xff);
        Ok(())
    }

    pub fn inventory(&self) -> Vec<String> {
        let mut v = Vec::new();
        for d in &self.pio {
            v.push(format!(
                "PIO  {:#06x}-{:#06x}  {}",
                d.port_range().start(),
                d.port_range().end(),
                d.name()
            ));
        }
        for d in &self.mmio {
            v.push(format!(
                "MMIO {:#010x}-{:#010x}  {}",
                d.mmio_range().start(),
                d.mmio_range().end(),
                d.name()
            ));
        }
        v
    }
}
