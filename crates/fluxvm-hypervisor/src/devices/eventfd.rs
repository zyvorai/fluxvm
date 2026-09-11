// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Host eventfd helpers (Firecracker interrupt_evt pattern).

pub fn create_eventfd() -> i32 {
    #[cfg(target_os = "linux")]
    {
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

pub fn trigger_eventfd(fd: i32) {
    if fd < 0 {
        return;
    }
    let buf = 1u64.to_ne_bytes();
    unsafe {
        let _ = libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
    }
}

pub fn close_eventfd(fd: i32) {
    if fd >= 0 {
        unsafe {
            let _ = libc::close(fd);
        }
    }
}
