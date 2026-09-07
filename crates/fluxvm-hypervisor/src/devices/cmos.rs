// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal MC146818 CMOS/RTC so Linux `mach_get_cmos_time` does not spin forever.

use crate::bus::PioDevice;
use crate::error::Result;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CmosRtc {
    addr: Mutex<u8>,
    /// Sparse NVRAM; unset indices read as 0.
    data: Mutex<[u8; 128]>,
}

impl CmosRtc {
    pub fn new() -> Self {
        let mut data = [0u8; 128];
        // Status Register A: rate + UIP clear (bit7=0).
        data[0x0a] = 0x26;
        // Status Register B: 24-hour mode.
        data[0x0b] = 0x02;
        // Status Register D: battery OK.
        data[0x0d] = 0x80;
        Self {
            addr: Mutex::new(0),
            data: Mutex::new(data),
        }
    }

    fn refresh_time(data: &mut [u8; 128]) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Rough UTC breakdown without chrono dependency.
        let days = secs / 86400;
        let tod = secs % 86400;
        let hour = (tod / 3600) as u8;
        let min = ((tod % 3600) / 60) as u8;
        let sec = (tod % 60) as u8;
        // Civil date from days since 1970-01-01 (Howard Hinnant algorithm).
        let z = days as i64 + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        let year = (y % 100) as u8;
        let month = m as u8;
        let day = d as u8;
        let dow = ((days + 4) % 7) as u8; // 1970-01-01 was Thursday=4
        data[0x00] = to_bcd(sec);
        data[0x02] = to_bcd(min);
        data[0x04] = to_bcd(hour);
        data[0x06] = to_bcd(dow);
        data[0x07] = to_bcd(day);
        data[0x08] = to_bcd(month);
        data[0x09] = to_bcd(year);
        data[0x0a] &= !0x80; // UIP clear — critical for mach_get_cmos_time
    }
}

fn to_bcd(v: u8) -> u8 {
    ((v / 10) << 4) | (v % 10)
}

impl Default for CmosRtc {
    fn default() -> Self {
        Self::new()
    }
}

impl PioDevice for CmosRtc {
    fn name(&self) -> &'static str {
        "cmos-rtc"
    }

    fn port_range(&self) -> std::ops::RangeInclusive<u16> {
        0x70..=0x71
    }

    fn io_out(&self, port: u16, data: &[u8]) -> Result<()> {
        let v = data.first().copied().unwrap_or(0);
        match port {
            0x70 => *self.addr.lock().unwrap() = v & 0x7f,
            0x71 => {
                let idx = (*self.addr.lock().unwrap() & 0x7f) as usize;
                if idx < 128 {
                    self.data.lock().unwrap()[idx] = v;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn io_in(&self, port: u16, data: &mut [u8]) -> Result<()> {
        let v = match port {
            0x70 => *self.addr.lock().unwrap(),
            0x71 => {
                let idx = (*self.addr.lock().unwrap() & 0x7f) as usize;
                let mut mem = self.data.lock().unwrap();
                if idx <= 0x09 || idx == 0x0a {
                    Self::refresh_time(&mut mem);
                }
                mem.get(idx).copied().unwrap_or(0)
            }
            _ => 0xff,
        };
        if !data.is_empty() {
            data[0] = v;
        }
        Ok(())
    }
}
