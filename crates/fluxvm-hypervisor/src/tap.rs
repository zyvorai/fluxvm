// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FluxError, Result};
use crate::ffi;
use std::ffi::CString;
use std::os::raw::c_void;

/// `flux_if_addr` stores its arguments verbatim in `sin_addr.s_addr`, which is
/// network byte order: the four octets must sit in memory in written order.
/// `from_be_bytes` would byte-swap them on little-endian hosts (192.168.100.1
/// became 1.100.168.192, /24 became /8).
pub(crate) fn ipv4_net_order(octets: [u8; 4]) -> u32 {
    u32::from_ne_bytes(octets)
}

pub struct Tap {
    pub fd: i32,
    pub name: String,
}

impl Tap {
    pub fn open(name: &str, host_ip: [u8; 4]) -> Result<Self> {
        let c = CString::new(name)
            .map_err(|_| FluxError::Network("TAP name contains a NUL byte".into()))?;
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
        let addr = ipv4_net_order(host_ip);
        let mask = ipv4_net_order([255, 255, 255, 0]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_is_stored_in_network_byte_order() {
        let v = ipv4_net_order([192, 168, 100, 1]);
        assert_eq!(v.to_ne_bytes(), [192, 168, 100, 1]);
        assert_eq!(
            ipv4_net_order([255, 255, 255, 0]).to_ne_bytes(),
            [255, 255, 255, 0]
        );
        if cfg!(target_endian = "little") {
            assert_eq!(v, 0x0164_a8c0);
            assert_eq!(ipv4_net_order([255, 255, 255, 0]), 0x00ff_ffff);
        }
    }

    #[test]
    fn invalid_tap_name_is_error_not_panic() {
        let err = Tap::open("tap\0bad", [192, 168, 100, 1]).err().unwrap();
        assert!(format!("{err}").contains("NUL"));
    }
}
