// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Optional vhost-net acceleration (Firecracker path).
//!
//! Full bind sequence (H3):
//! 1. `VHOST_SET_OWNER`
//! 2. `VHOST_SET_MEM_TABLE` — guest RAM GPA → host HVA
//! 3. `VHOST_SET_VRING_{NUM,ADDR,BASE,KICK,CALL}` per queue
//! 4. `VHOST_NET_SET_BACKEND` — attach TAP
//!
//! Callers that fail any step keep the userspace TAP datapath.

use crate::devices::virtio_mmio::QueueState;
use crate::error::{FluxError, Result};

#[cfg(target_os = "linux")]
mod linux_ioctl {
    // linux/vhost.h — VHOST_VIRTIO = 0xAF
    pub const VHOST_SET_OWNER: libc::c_ulong = 0xaf01;
    pub const VHOST_RESET_OWNER: libc::c_ulong = 0xaf02;
    // VHOST_SET_MEM_TABLE = _IOW(VHOST_VIRTIO, 0x03, struct vhost_memory)
    pub const VHOST_SET_MEM_TABLE: libc::c_ulong = 0x4008_af03;
    // VHOST_SET_VRING_NUM = _IOW(VHOST_VIRTIO, 0x10, struct vhost_vring_state)
    pub const VHOST_SET_VRING_NUM: libc::c_ulong = 0x4008_af10;
    // VHOST_SET_VRING_ADDR = _IOW(VHOST_VIRTIO, 0x11, struct vhost_vring_addr)
    pub const VHOST_SET_VRING_ADDR: libc::c_ulong = 0x4028_af11;
    // VHOST_SET_VRING_BASE = _IOW(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
    pub const VHOST_SET_VRING_BASE: libc::c_ulong = 0x4008_af12;
    // VHOST_SET_VRING_KICK = _IOW(VHOST_VIRTIO, 0x20, struct vhost_vring_file)
    pub const VHOST_SET_VRING_KICK: libc::c_ulong = 0x4008_af20;
    // VHOST_SET_VRING_CALL = _IOW(VHOST_VIRTIO, 0x21, struct vhost_vring_file)
    pub const VHOST_SET_VRING_CALL: libc::c_ulong = 0x4008_af21;
    // VHOST_NET_SET_BACKEND = _IOW(VHOST_VIRTIO, 0x30, struct vhost_vring_file)
    pub const VHOST_NET_SET_BACKEND: libc::c_ulong = 0x4008_af30;

    #[repr(C)]
    pub struct VhostVringFile {
        pub index: libc::c_uint,
        pub fd: libc::c_int,
    }

    #[repr(C)]
    pub struct VhostVringState {
        pub index: libc::c_uint,
        pub num: libc::c_uint,
    }

    #[repr(C)]
    pub struct VhostVringAddr {
        pub index: libc::c_uint,
        pub flags: libc::c_uint,
        pub desc_user_addr: u64,
        pub used_user_addr: u64,
        pub avail_user_addr: u64,
        pub log_guest_addr: u64,
    }

    #[repr(C)]
    pub struct VhostMemoryRegion {
        pub guest_phys_addr: u64,
        pub memory_size: u64,
        pub userspace_addr: u64,
        pub flags_padding: u64,
    }

    /// Flexible array is represented as a trailing region; we allocate a
    /// heap buffer with one region for the contiguous guest RAM mmap.
    #[repr(C)]
    pub struct VhostMemoryHeader {
        pub nregions: u32,
        pub padding: u32,
    }
}

/// Per-queue kick/call eventfds owned by [`VhostNet`] once programmed.
pub struct VhostQueueFds {
    pub kick: i32,
    pub call: i32,
}

pub struct VhostNet {
    pub fd: i32,
    /// True once TAP backend bind succeeded for at least queue 0.
    pub bound: bool,
    /// True once mem-table + VRING GPA/HVA programming succeeded.
    pub rings_programmed: bool,
    queue_fds: Vec<VhostQueueFds>,
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
            Ok(Self {
                fd,
                bound: false,
                rings_programmed: false,
                queue_fds: Vec::new(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }

    /// Whether the kernel datapath owns RX/TX (skip userspace pump).
    pub fn kernel_datapath(&self) -> bool {
        self.bound && self.rings_programmed
    }

    /// Kick fd for queue `index` (guest QueueNotify → write 1).
    pub fn kick_fd(&self, index: usize) -> Option<i32> {
        self.queue_fds.get(index).map(|q| q.kick)
    }

    /// Call fd for queue `index` (kernel used-ring update → raise IRQ).
    pub fn call_fd(&self, index: usize) -> Option<i32> {
        self.queue_fds.get(index).map(|q| q.call)
    }

    /// Signal the kick eventfd so vhost drains the avail ring.
    pub fn signal_kick(&self, index: usize) -> Result<()> {
        let fd = self.kick_fd(index).ok_or_else(|| {
            FluxError::Hypervisor(format!("vhost kick fd missing for queue {index}"))
        })?;
        let one: u64 = 1;
        let n = unsafe { libc::write(fd, &one as *const u64 as *const _, 8) };
        if n < 0 {
            return Err(FluxError::Hypervisor(format!(
                "vhost kick write: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Bind TAP as vhost-net backend for queue index 0 (RX) and 1 (TX).
    pub fn bind_tap(&mut self, tap_fd: i32, queues: u32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use linux_ioctl::*;
            let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_OWNER) };
            if rc < 0 {
                return Err(FluxError::Hypervisor(format!(
                    "VHOST_SET_OWNER: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let nq = queues.max(1).min(2);
            for index in 0..nq {
                let file = VhostVringFile { index, fd: tap_fd };
                let rc = unsafe {
                    libc::ioctl(
                        self.fd,
                        VHOST_NET_SET_BACKEND,
                        &file as *const VhostVringFile,
                    )
                };
                if rc < 0 {
                    let _ = unsafe { libc::ioctl(self.fd, VHOST_RESET_OWNER) };
                    return Err(FluxError::Hypervisor(format!(
                        "VHOST_NET_SET_BACKEND queue {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
            self.bound = true;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tap_fd, queues);
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }

    /// Program guest RAM mem-table + virtqueue rings (H3 finish).
    ///
    /// `host_base` / `ram_bytes` describe the contiguous guest RAM mmap
    /// (GPA 0 → `host_base`). `queues` must already have `ready != 0` and
    /// valid desc/avail/used GPAs from the guest driver.
    pub fn program_vrings(
        &mut self,
        host_base: *mut u8,
        ram_bytes: usize,
        queues: &[QueueState],
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use linux_ioctl::*;
            if host_base.is_null() || ram_bytes == 0 {
                return Err(FluxError::Hypervisor(
                    "vhost mem-table needs non-empty guest RAM".into(),
                ));
            }
            // Build VHOST_SET_MEM_TABLE with one region covering GPA [0, ram).
            let header = VhostMemoryHeader {
                nregions: 1,
                padding: 0,
            };
            let region = VhostMemoryRegion {
                guest_phys_addr: 0,
                memory_size: ram_bytes as u64,
                userspace_addr: host_base as u64,
                flags_padding: 0,
            };
            let mut buf = Vec::with_capacity(
                std::mem::size_of::<VhostMemoryHeader>() + std::mem::size_of::<VhostMemoryRegion>(),
            );
            buf.extend_from_slice(unsafe {
                std::slice::from_raw_parts(
                    &header as *const _ as *const u8,
                    std::mem::size_of::<VhostMemoryHeader>(),
                )
            });
            buf.extend_from_slice(unsafe {
                std::slice::from_raw_parts(
                    &region as *const _ as *const u8,
                    std::mem::size_of::<VhostMemoryRegion>(),
                )
            });
            let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_MEM_TABLE, buf.as_ptr()) };
            if rc < 0 {
                return Err(FluxError::Hypervisor(format!(
                    "VHOST_SET_MEM_TABLE: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Drop prior eventfds if re-programming.
            for q in self.queue_fds.drain(..) {
                unsafe {
                    let _ = libc::close(q.kick);
                    let _ = libc::close(q.call);
                }
            }

            let nq = queues.len().min(2);
            for (index, q) in queues.iter().take(nq).enumerate() {
                if q.ready == 0 || q.num == 0 || q.desc == 0 || q.avail == 0 || q.used == 0 {
                    return Err(FluxError::Hypervisor(format!(
                        "queue {index} not ready for vhost (ready={} num={} desc={:#x})",
                        q.ready, q.num, q.desc
                    )));
                }
                if (q.desc as usize) >= ram_bytes
                    || (q.avail as usize) >= ram_bytes
                    || (q.used as usize) >= ram_bytes
                {
                    return Err(FluxError::Hypervisor(format!(
                        "queue {index} ring GPA past guest RAM"
                    )));
                }

                let state = VhostVringState {
                    index: index as u32,
                    num: q.num,
                };
                let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_VRING_NUM, &state as *const _) };
                if rc < 0 {
                    return Err(FluxError::Hypervisor(format!(
                        "VHOST_SET_VRING_NUM {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }

                let addr = VhostVringAddr {
                    index: index as u32,
                    flags: 0,
                    desc_user_addr: host_base as u64 + q.desc,
                    used_user_addr: host_base as u64 + q.used,
                    avail_user_addr: host_base as u64 + q.avail,
                    log_guest_addr: 0,
                };
                let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_VRING_ADDR, &addr as *const _) };
                if rc < 0 {
                    return Err(FluxError::Hypervisor(format!(
                        "VHOST_SET_VRING_ADDR {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }

                let base = VhostVringState {
                    index: index as u32,
                    num: q.last_avail as u32,
                };
                let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_VRING_BASE, &base as *const _) };
                if rc < 0 {
                    return Err(FluxError::Hypervisor(format!(
                        "VHOST_SET_VRING_BASE {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }

                let kick = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
                let call = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
                if kick < 0 || call < 0 {
                    if kick >= 0 {
                        unsafe {
                            let _ = libc::close(kick);
                        }
                    }
                    if call >= 0 {
                        unsafe {
                            let _ = libc::close(call);
                        }
                    }
                    return Err(FluxError::Hypervisor(format!(
                        "eventfd for vhost queue {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let kick_file = VhostVringFile {
                    index: index as u32,
                    fd: kick,
                };
                let rc =
                    unsafe { libc::ioctl(self.fd, VHOST_SET_VRING_KICK, &kick_file as *const _) };
                if rc < 0 {
                    unsafe {
                        let _ = libc::close(kick);
                        let _ = libc::close(call);
                    }
                    return Err(FluxError::Hypervisor(format!(
                        "VHOST_SET_VRING_KICK {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let call_file = VhostVringFile {
                    index: index as u32,
                    fd: call,
                };
                let rc =
                    unsafe { libc::ioctl(self.fd, VHOST_SET_VRING_CALL, &call_file as *const _) };
                if rc < 0 {
                    unsafe {
                        let _ = libc::close(kick);
                        let _ = libc::close(call);
                    }
                    return Err(FluxError::Hypervisor(format!(
                        "VHOST_SET_VRING_CALL {index}: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                self.queue_fds.push(VhostQueueFds { kick, call });
            }
            self.rings_programmed = true;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (host_base, ram_bytes, queues);
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }
}

impl Drop for VhostNet {
    fn drop(&mut self) {
        for q in self.queue_fds.drain(..) {
            if q.kick >= 0 {
                unsafe {
                    let _ = libc::close(q.kick);
                }
            }
            if q.call >= 0 {
                unsafe {
                    let _ = libc::close(q.call);
                }
            }
        }
        if self.fd >= 0 {
            unsafe {
                let _ = libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}
