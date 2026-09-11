// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::bus::PioDevice;
use crate::error::Result;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Mutex;

/// COM1 (0x3f8) 16550A-ish UART matching Firecracker `vm-superio` /
/// cloud-hypervisor `devices/src/legacy/serial.rs` semantics.
pub struct Serial16550 {
    base: u16,
    /// ISA IRQ / GSI (COM1 = 4), registered with `KVM_IRQFD`.
    pub irq: u32,
    ier: Mutex<u8>,
    lcr: Mutex<u8>,
    mcr: Mutex<u8>,
    scratch: Mutex<u8>,
    dll: Mutex<u8>,
    dlm: Mutex<u8>,
    fcr: Mutex<u8>,
    /// IIR pending bits (RDA=0x04, THRE=0x02); 0x01 means none.
    iir: Mutex<u8>,
    rx: Mutex<VecDeque<u8>>,
    /// Eventfd wired to `KVM_IRQFD` (Firecracker COM1 path). `-1` if unavailable.
    interrupt_evt: i32,
}

const IIR_NO_INT: u8 = 0x01;
const IIR_THR: u8 = 0x02;
const IIR_RDA: u8 = 0x04;
const IIR_FIFO_BITS: u8 = 0xc0;
const IER_RDA: u8 = 0x01;
const IER_THR: u8 = 0x02;

impl Serial16550 {
    pub fn com1() -> Self {
        let interrupt_evt = create_eventfd();
        Self {
            base: 0x3f8,
            irq: 4,
            ier: Mutex::new(0),
            // Match vm-superio / CH defaults.
            lcr: Mutex::new(0x03),
            mcr: Mutex::new(0x08), // OUT2
            scratch: Mutex::new(0),
            dll: Mutex::new(0x0c),
            dlm: Mutex::new(0),
            fcr: Mutex::new(0),
            iir: Mutex::new(IIR_NO_INT),
            rx: Mutex::new(VecDeque::with_capacity(256)),
            interrupt_evt,
        }
    }

    fn offset(&self, port: u16) -> u16 {
        port.saturating_sub(self.base)
    }

    /// Eventfd for `KVM_IRQFD` registration (Firecracker `interrupt_evt()`).
    pub fn interrupt_evt(&self) -> Option<i32> {
        if self.interrupt_evt >= 0 {
            Some(self.interrupt_evt)
        } else {
            None
        }
    }

    /// Bytes waiting for the guest (data-ready).
    pub fn rx_len(&self) -> usize {
        self.rx.lock().unwrap().len()
    }

    /// Queue host→guest console bytes (e.g. stdin or smoke inject).
    pub fn push_rx(&self, bytes: &[u8]) {
        let mut q = self.rx.lock().unwrap();
        let was_empty = q.is_empty();
        for &b in bytes {
            if q.len() < 1024 {
                q.push_back(b);
            }
        }
        let now_nonempty = !q.is_empty();
        drop(q);
        if was_empty && now_nonempty {
            self.recv_data_interrupt();
        }
    }

    /// True when an interrupt condition is currently pending (debug / diag).
    pub fn irq_pending(&self) -> bool {
        let iir = *self.iir.lock().unwrap();
        iir != IIR_NO_INT
    }

    fn trigger_interrupt(&self) {
        if self.interrupt_evt < 0 {
            return;
        }
        let buf = 1u64.to_ne_bytes();
        unsafe {
            let _ = libc::write(
                self.interrupt_evt,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            );
        }
    }

    /// Firecracker / CH: arm THRE + eventfd only on rising edge.
    fn thr_empty_interrupt(&self) {
        let ier = *self.ier.lock().unwrap();
        if ier & IER_THR == 0 {
            return;
        }
        let mut iir = self.iir.lock().unwrap();
        if *iir & IIR_THR != 0 {
            return;
        }
        *iir = (*iir & !IIR_NO_INT) | IIR_THR;
        drop(iir);
        self.trigger_interrupt();
    }

    fn recv_data_interrupt(&self) {
        let ier = *self.ier.lock().unwrap();
        if ier & IER_RDA == 0 {
            return;
        }
        let mut iir = self.iir.lock().unwrap();
        if *iir & IIR_RDA != 0 {
            return;
        }
        *iir = (*iir & !IIR_NO_INT) | IIR_RDA;
        drop(iir);
        self.trigger_interrupt();
    }
}

impl Drop for Serial16550 {
    fn drop(&mut self) {
        if self.interrupt_evt >= 0 {
            unsafe {
                let _ = libc::close(self.interrupt_evt);
            }
            self.interrupt_evt = -1;
        }
    }
}

fn create_eventfd() -> i32 {
    #[cfg(target_os = "linux")]
    {
        // EFD_NONBLOCK | EFD_CLOEXEC
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            -1
        } else {
            fd
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        -1
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
                // THR write → rising-edge THRE IRQ (vm-superio / CH).
                self.thr_empty_interrupt();
            }
            1 if dlab => *self.dlm.lock().unwrap() = v,
            1 => {
                // IER write only — FC/CH do not arm THRE here.
                *self.ier.lock().unwrap() = v & 0x0f;
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
            0 => {
                let mut q = self.rx.lock().unwrap();
                let b = q.pop_front().unwrap_or(0);
                if q.is_empty() {
                    let mut iir = self.iir.lock().unwrap();
                    *iir &= !IIR_RDA;
                    if *iir & (IIR_THR | IIR_RDA) == 0 {
                        *iir = IIR_NO_INT;
                    }
                }
                b
            }
            1 if dlab => *self.dlm.lock().unwrap(),
            1 => *self.ier.lock().unwrap(),
            // IIR: 16550A FIFO bits (0xc0); clear all pending on read (FC/CH).
            2 => {
                let mut iir = self.iir.lock().unwrap();
                let raw = *iir;
                let reported = if raw == IIR_NO_INT {
                    IIR_NO_INT
                } else if raw & IIR_RDA != 0 {
                    IIR_RDA
                } else if raw & IIR_THR != 0 {
                    IIR_THR
                } else {
                    raw & !IIR_NO_INT
                };
                *iir = IIR_NO_INT;
                reported | IIR_FIFO_BITS
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
