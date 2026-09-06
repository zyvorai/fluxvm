// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::bus::Bus;
use crate::error::Result;
use crate::hypervisor::{VcpuBackend, VcpuExit};
use std::sync::Arc;

pub fn vcpu_loop(id: u8, mut vcpu: Box<dyn VcpuBackend>, bus: Arc<Bus>) -> Result<()> {
    eprintln!("[vcpu-{id}] start");
    loop {
        match vcpu.run()? {
            VcpuExit::IoOut { port, data } => bus.pio_write(port, &data)?,
            VcpuExit::IoIn { port, size } => {
                let mut buf = vec![0u8; size as usize];
                bus.pio_read(port, &mut buf)?;
            }
            VcpuExit::MmioWrite { addr, data } => {
                let _ = bus.mmio_write(addr, &data);
            }
            VcpuExit::MmioRead { addr, size } => {
                let mut buf = vec![0u8; size as usize];
                let _ = bus.mmio_read(addr, &mut buf);
            }
            VcpuExit::Halt | VcpuExit::Shutdown => {
                eprintln!("[vcpu-{id}] halt/shutdown");
                break;
            }
            VcpuExit::Interrupted => continue,
            VcpuExit::Unknown(s) => eprintln!("[vcpu-{id}] {s}"),
        }
    }
    Ok(())
}
