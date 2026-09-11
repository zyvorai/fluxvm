// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Optional vhost-net acceleration (Firecracker path).
//! When `/dev/vhost-net` is unavailable or setup fails, callers keep the
//! userspace TAP datapath.

use crate::error::{FluxError, Result};

pub struct VhostNet {
    pub fd: i32,
}

impl VhostNet {
    /// Try to open `/dev/vhost-net`. Returns error if unsupported — caller
    /// must fall back to userspace virtio-net.
    pub fn open() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let path = std::ffi::CString::new("/dev/vhost-net").unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(FluxError::Hypervisor(format!(
                    "open /dev/vhost-net: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self { fd })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }
}

impl Drop for VhostNet {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                let _ = libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}
