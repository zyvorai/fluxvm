// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use crate::ffi;
use std::ffi::CString;
use std::os::raw::c_void;

pub struct Tap {
    pub fd: i32,
    pub name: String,
}

impl Tap {
    pub fn open(name: &str, host_ip: [u8; 4]) -> Result<Self> {
        let c = CString::new(name).unwrap();
        let fd = unsafe { ffi::flux_tap_open(c.as_ptr()) };
        if fd < 0 {
            return Err(FluxError::Network(format!(
                "tap open {name} errno {}",
                unsafe { ffi::flux_errno() }
            )));
        }
        if unsafe { ffi::flux_if_up(c.as_ptr()) } < 0 {
            eprintln!("[tap] warning: could not set IFF_UP errno {}", unsafe {
                ffi::flux_errno()
            });
        }
        let addr = u32::from_be_bytes(host_ip);
        let mask = u32::from_be_bytes([255, 255, 255, 0]);
        if unsafe { ffi::flux_if_addr(c.as_ptr(), addr, mask) } < 0 {
            eprintln!("[tap] warning: could not set IP errno {}", unsafe {
                ffi::flux_errno()
            });
        }
        eprintln!(
            "[tap] {name} fd={fd} {}.{}.{}.{}/24 UP",
            host_ip[0], host_ip[1], host_ip[2], host_ip[3]
        );
        Ok(Self {
            fd,
            name: name.into(),
        })
    }

    pub fn write_frame(&self, frame: &[u8]) -> Result<()> {
        let n = unsafe { ffi::write(self.fd, frame.as_ptr() as *const c_void, frame.len()) };
        if n < 0 {
            return Err(FluxError::Network(format!("tap write errno {}", unsafe {
                ffi::flux_errno()
            })));
        }
        Ok(())
    }

    pub fn read_frame(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        let n = unsafe { ffi::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 {
            let e = unsafe { ffi::flux_errno() };
            if e == 11 || e == 35 {
                return Ok(None);
            }
            return Err(FluxError::Network(format!("tap read errno {e}")));
        }
        if n == 0 {
            return Ok(None);
        }
        Ok(Some(n as usize))
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                ffi::close(self.fd);
            }
        }
    }
}
