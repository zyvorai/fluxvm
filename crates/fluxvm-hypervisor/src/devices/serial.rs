// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::bus::PioDevice;
use crate::error::Result;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Mutex;

/// COM1 (0x3f8) 16550A-ish UART with a small RX queue for interactive console.
pub struct Serial16550 {
    base: u16,
    /// ISA IRQ (COM1 = 4), for virtio-style edge pulse via the irqchip.
    pub irq: u32,
    ier: Mutex<u8>,
    lcr: Mutex<u8>,
    mcr: Mutex<u8>,
    scratch: Mutex<u8>,
    dll: Mutex<u8>,
    dlm: Mutex<u8>,
    fcr: Mutex<u8>,
    rx: Mutex<VecDeque<u8>>,
    /// Set when THR was written and guest enabled THRI; cleared on IIR read.
    thr_empty_int: Mutex<bool>,
}

impl Serial16550 {
    pub fn com1() -> Self {
        Self {
            base: 0x3f8,
            irq: 4,
            ier: Mutex::new(0),
            lcr: Mutex::new(0),
            mcr: Mutex::new(0),
            scratch: Mutex::new(0),
            dll: Mutex::new(0x0c),
            dlm: Mutex::new(0),
            fcr: Mutex::new(0),
            rx: Mutex::new(VecDeque::with_capacity(256)),
            thr_empty_int: Mutex::new(false),
        }
    }

    fn offset(&self, port: u16) -> u16 {
        port.saturating_sub(self.base)
    }

    /// Bytes waiting for the guest (data-ready).
    pub fn rx_len(&self) -> usize {
        self.rx.lock().unwrap().len()
    }

    /// Queue host→guest console bytes (e.g. stdin or smoke inject).
    pub fn push_rx(&self, bytes: &[u8]) {
        let mut q = self.rx.lock().unwrap();
        for &b in bytes {
            if q.len() < 1024 {
                q.push_back(b);
            }
        }
    }

    /// True when IER requests an interrupt that is currently pending.
    pub fn irq_pending(&self) -> bool {
        let ier = *self.ier.lock().unwrap();
        let rx = !self.rx.lock().unwrap().is_empty();
        let thr = *self.thr_empty_int.lock().unwrap();
        ((ier & 0x01) != 0 && rx) || ((ier & 0x02) != 0 && thr)
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
                // THR empty interrupt when guest enabled THRI.
                if *self.ier.lock().unwrap() & 0x02 != 0 {
                    *self.thr_empty_int.lock().unwrap() = true;
                }
            }
            1 if dlab => *self.dlm.lock().unwrap() = v,
            1 => {
                *self.ier.lock().unwrap() = v;
                // Enabling THRI with empty THR is immediately pending.
                if v & 0x02 != 0 {
                    *self.thr_empty_int.lock().unwrap() = true;
                }
            }
            2 => *self.fcr.lock().unwrap() = v, // FCR (write-only)
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
            0 => self.rx.lock().unwrap().pop_front().unwrap_or(0),
            1 if dlab => *self.dlm.lock().unwrap(),
            1 => *self.ier.lock().unwrap(),
            // IIR: bit0=0 means interrupt pending; 0x01 = no interrupt.
            2 => {
                let ier = *self.ier.lock().unwrap();
                let rx = !self.rx.lock().unwrap().is_empty();
                let thr = *self.thr_empty_int.lock().unwrap();
                let iir = if (ier & 0x01) != 0 && rx {
                    0x04 // received data available
                } else if (ier & 0x02) != 0 && thr {
                    *self.thr_empty_int.lock().unwrap() = false;
                    0x02 // THR empty
                } else {
                    0x01 // no interrupt pending
                };
                iir
            }
            3 => *self.lcr.lock().unwrap(),
            4 => *self.mcr.lock().unwrap(),
            // LSR: THRE|TEMT always; DR when RX non-empty.
            5 => {
                let mut lsr = 0x20 | 0x40;
                if !self.rx.lock().unwrap().is_empty() {
                    lsr |= 0x01;
                }
                lsr
            }
            // MSR: CTS|DSR|DCD
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
