// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::bus::PioDevice;
use crate::error::Result;
use std::io::{self, Write};
use std::sync::Mutex;

pub struct Serial16550 {
    base: u16,
    ier: Mutex<u8>,
    lcr: Mutex<u8>,
    mcr: Mutex<u8>,
    scratch: Mutex<u8>,
    dll: Mutex<u8>,
    dlm: Mutex<u8>,
}

impl Serial16550 {
    pub fn com1() -> Self {
        Self {
            base: 0x3f8,
            ier: Mutex::new(0),
            lcr: Mutex::new(0),
            mcr: Mutex::new(0),
            scratch: Mutex::new(0),
            dll: Mutex::new(0x0c),
            dlm: Mutex::new(0),
        }
    }

    fn offset(&self, port: u16) -> u16 {
        port.saturating_sub(self.base)
    }
}

impl PioDevice for Serial16550 {
    fn name(&self) -> &'static str {
        "serial-16550"
    }

    fn port_range(&self) -> std::ops::RangeInclusive<u16> {
        self.base..=self.base + 7
    }

    fn io_out(&self, port: u16, data: &[u8]) -> Result<()> {
        let v = data.first().copied().unwrap_or(0);
        let dlab = *self.lcr.lock().unwrap() & 0x80 != 0;
        match self.offset(port) {
            0 if dlab => *self.dll.lock().unwrap() = v,
            0 => {
                let mut out = io::stdout().lock();
                let _ = out.write_all(&[v]);
                let _ = out.flush();
            }
            1 if dlab => *self.dlm.lock().unwrap() = v,
            1 => *self.ier.lock().unwrap() = v,
            3 => *self.lcr.lock().unwrap() = v,
            4 => *self.mcr.lock().unwrap() = v,
            7 => *self.scratch.lock().unwrap() = v,
            _ => {}
        }
        Ok(())
    }

    fn io_in(&self, port: u16, data: &mut [u8]) -> Result<()> {
        let dlab = *self.lcr.lock().unwrap() & 0x80 != 0;
        let v = match self.offset(port) {
            0 if dlab => *self.dll.lock().unwrap(),
            0 => 0,
            1 if dlab => *self.dlm.lock().unwrap(),
            1 => *self.ier.lock().unwrap(),
            5 => 0x20 | 0x40,
            3 => *self.lcr.lock().unwrap(),
            4 => *self.mcr.lock().unwrap(),
            6 => 0x10 | 0x20 | 0x80,
            7 => *self.scratch.lock().unwrap(),
            _ => 0xff,
        };
        if !data.is_empty() {
            data[0] = v;
        }
        Ok(())
    }
}
