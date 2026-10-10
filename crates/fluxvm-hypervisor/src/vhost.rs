// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Optional vhost-net acceleration (Firecracker path).
//!
//! Full bind sequence (H3), run once the guest driver has programmed its rings
//! (the kernel rejects `VHOST_NET_SET_BACKEND` with `EFAULT` on unprogrammed
//! vrings, so the TAP is only remembered by [`VhostNet::attach_tap`]):
//! 1. `VHOST_SET_OWNER`
//! 2. `VHOST_SET_FEATURES` — negotiated virtio features ([`vhost_feature_mask`])
//! 3. `VHOST_SET_MEM_TABLE` — guest RAM GPA → host HVA
//! 4. `VHOST_SET_VRING_{NUM,BASE,ADDR,KICK,CALL}` per queue
//! 5. start the IRQ relay ([`IrqRelay`]): call eventfd → guest interrupt
//! 6. `VHOST_NET_SET_BACKEND` — attach TAP, per queue
//!
//! Callers that fail any step keep the userspace TAP datapath.
//!
//! One [`VhostNet`] (one `/dev/vhost-net` fd) serves exactly one RX/TX queue
//! pair, so multiqueue is one instance per pair, each bound to its own
//! multi_queue TAP queue fd ([`VhostPair`]). Which datapath is actually live is
//! published through [`NetDatapath`] so a silent fallback is visible.

use crate::devices::virtio_mmio::QueueState;
use crate::error::{FluxError, Result};
use crate::tap::Tap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// `FLUXVM_VHOST_NET=0` (or `off`/`false`/`no`) forces the userspace pump even
/// when the config asks for vhost-net, for A/B benchmarking. Unset or any
/// other value leaves the config in charge.
pub fn env_enabled() -> bool {
    !matches!(
        std::env::var("FLUXVM_VHOST_NET")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("0") | Some("off") | Some("false") | Some("no")
    )
}

/// Which virtio-net datapath is live, and why. Shared (`Arc`) between the VM,
/// the queue service that decides it and the control API that reports it.
pub struct NetDatapath {
    kernel: AtomicBool,
    pairs: AtomicU32,
    detail: Mutex<String>,
}

impl Default for NetDatapath {
    fn default() -> Self {
        Self {
            kernel: AtomicBool::new(false),
            pairs: AtomicU32::new(1),
            detail: Mutex::new("not initialised".into()),
        }
    }
}

impl NetDatapath {
    /// Record the current datapath. `kernel` is true only when vhost-net owns
    /// every queue pair; `detail` says why (or why not).
    pub fn set(&self, kernel: bool, pairs: u32, detail: impl Into<String>) {
        self.kernel.store(kernel, Ordering::SeqCst);
        self.pairs.store(pairs, Ordering::SeqCst);
        if let Ok(mut d) = self.detail.lock() {
            *d = detail.into();
        }
    }

    /// Adopt another status wholesale (used to hand the status computed while
    /// building a VM to the handle that reports it).
    pub fn copy_from(&self, other: &NetDatapath) {
        let detail = other.detail.lock().map(|d| d.clone()).unwrap_or_default();
        self.set(
            other.kernel.load(Ordering::SeqCst),
            other.pairs.load(Ordering::SeqCst),
            detail,
        );
    }

    pub fn is_kernel(&self) -> bool {
        self.kernel.load(Ordering::SeqCst)
    }

    /// `vhost-net` or `userspace-pump`.
    pub fn label(&self) -> &'static str {
        if self.is_kernel() {
            "vhost-net"
        } else {
            "userspace-pump"
        }
    }

    /// One-line status: `<label> pairs=<n> (<detail>)`.
    pub fn summary(&self) -> String {
        let detail = self.detail.lock().map(|d| d.clone()).unwrap_or_default();
        format!(
            "{} pairs={} ({detail})",
            self.label(),
            self.pairs.load(Ordering::SeqCst)
        )
    }
}

/// An extra queue pair (index >= 1) of a multiqueue device: its own vhost-net
/// instance and the TAP queue fd it is bound to. Field order drops vhost first.
pub struct VhostPair {
    pub vhost: VhostNet,
    pub tap: Tap,
}

const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
const VIRTIO_RING_F_INDIRECT_DESC: u64 = 1 << 28;
const VIRTIO_RING_F_EVENT_IDX: u64 = 1 << 29;
const VIRTIO_F_VERSION_1_BIT: u64 = 1 << 32;
/// `VHOST_NET_F_VIRTIO_NET_HDR`: vhost itself consumes/produces the virtio-net
/// header. Required because our TAP is opened without `IFF_VNET_HDR`; without
/// this bit vhost expects the TAP to carry the header and would corrupt frames.
const VHOST_NET_F_VIRTIO_NET_HDR: u64 = 1 << 27;

/// Features to hand to `VHOST_SET_FEATURES`: the subset of what the guest
/// driver negotiated that vhost-net understands (it rejects unknown bits with
/// `EOPNOTSUPP`; MAC/STATUS/MQ/CTRL_VQ are device-model only), plus
/// `VHOST_NET_F_VIRTIO_NET_HDR`.
pub fn vhost_feature_mask(driver_features: u64) -> u64 {
    let passthrough = VIRTIO_NET_F_MRG_RXBUF
        | VIRTIO_RING_F_INDIRECT_DESC
        | VIRTIO_RING_F_EVENT_IDX
        | VIRTIO_F_VERSION_1_BIT;
    (driver_features & passthrough) | VHOST_NET_F_VIRTIO_NET_HDR
}

/// Steps of the bring-up, in the only order the kernel accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindStep {
    Owner,
    Features,
    MemTable,
    Rings,
    IrqRelay,
    Backend,
}

impl BindStep {
    fn next(self) -> Option<BindStep> {
        match self {
            BindStep::Owner => Some(BindStep::Features),
            BindStep::Features => Some(BindStep::MemTable),
            BindStep::MemTable => Some(BindStep::Rings),
            BindStep::Rings => Some(BindStep::IrqRelay),
            BindStep::IrqRelay => Some(BindStep::Backend),
            BindStep::Backend => None,
        }
    }
}

/// Tracks bring-up progress and refuses out-of-order steps (notably the
/// backend before the rings).
#[derive(Default, Debug)]
pub struct BindOrder {
    last: Option<BindStep>,
}

impl BindOrder {
    /// Record that `step` is about to run; error if it is not the next one.
    pub fn enter(&mut self, step: BindStep) -> std::result::Result<(), String> {
        let expected = match self.last {
            None => Some(BindStep::Owner),
            Some(l) => l.next(),
        };
        if expected == Some(step) {
            self.last = Some(step);
            Ok(())
        } else {
            Err(format!(
                "vhost bring-up out of order: {step:?} after {:?}",
                self.last
            ))
        }
    }

    pub fn complete(&self) -> bool {
        self.last == Some(BindStep::Backend)
    }
}

/// Relays vhost call eventfds to a guest interrupt: one epoll thread waits on
/// (dup'd) call fds and invokes `raise` for each wakeup. Without it the guest
/// never learns the kernel updated a used ring.
pub struct IrqRelay {
    stop_fd: i32,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl IrqRelay {
    /// Start the relay over `call_fds` (duplicated; callers keep ownership of
    /// the originals). Once this returns `Ok` the thread is already waiting.
    pub fn start(call_fds: &[i32], raise: Arc<dyn Fn() + Send + Sync>) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let err = |what: &str| {
                FluxError::Hypervisor(format!(
                    "irq relay {what}: {}",
                    std::io::Error::last_os_error()
                ))
            };
            let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if epfd < 0 {
                return Err(err("epoll_create1"));
            }
            let stop_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if stop_fd < 0 {
                let e = err("eventfd");
                unsafe { libc::close(epfd) };
                return Err(e);
            }
            let mut owned: Vec<i32> = Vec::new();
            let cleanup = |epfd: i32, stop_fd: i32, owned: &[i32]| unsafe {
                libc::close(epfd);
                libc::close(stop_fd);
                for fd in owned {
                    libc::close(*fd);
                }
            };
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: u64::MAX,
            };
            if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, stop_fd, &mut ev) } < 0 {
                let e = err("epoll_ctl(stop)");
                cleanup(epfd, stop_fd, &owned);
                return Err(e);
            }
            for (i, fd) in call_fds.iter().enumerate() {
                let d = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 0) };
                if d < 0 {
                    let e = err("dup call fd");
                    cleanup(epfd, stop_fd, &owned);
                    return Err(e);
                }
                owned.push(d);
                let mut ev = libc::epoll_event {
                    events: libc::EPOLLIN as u32,
                    u64: i as u64,
                };
                if unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, d, &mut ev) } < 0 {
                    let e = err("epoll_ctl(call)");
                    cleanup(epfd, stop_fd, &owned);
                    return Err(e);
                }
            }
            let thread_fds = owned.clone();
            let spawned = std::thread::Builder::new()
                .name("vhost-irq-relay".into())
                .spawn(move || {
                    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 8];
                    'outer: loop {
                        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), 8, -1) };
                        if n < 0 {
                            if std::io::Error::last_os_error().kind()
                                == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            break;
                        }
                        for ev in &events[..n as usize] {
                            let tag = ev.u64;
                            if tag == u64::MAX {
                                break 'outer;
                            }
                            if let Some(fd) = thread_fds.get(tag as usize) {
                                let mut cnt: u64 = 0;
                                let r =
                                    unsafe { libc::read(*fd, &mut cnt as *mut u64 as *mut _, 8) };
                                if r == 8 && cnt > 0 {
                                    raise();
                                }
                            }
                        }
                    }
                    unsafe {
                        libc::close(epfd);
                        for fd in &thread_fds {
                            libc::close(*fd);
                        }
                    }
                });
            match spawned {
                Ok(h) => Ok(Self {
                    stop_fd,
                    thread: Some(h),
                }),
                Err(e) => {
                    cleanup(epfd, stop_fd, &owned);
                    Err(FluxError::Hypervisor(format!("irq relay thread: {e}")))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (call_fds, raise);
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }
}

impl Drop for IrqRelay {
    fn drop(&mut self) {
        let one: u64 = 1;
        unsafe {
            let _ = libc::write(self.stop_fd, &one as *const u64 as *const _, 8);
        }
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
        unsafe {
            let _ = libc::close(self.stop_fd);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_ioctl {
    // linux/vhost.h — VHOST_VIRTIO = 0xAF
    // VHOST_SET_FEATURES = _IOW(VHOST_VIRTIO, 0x00, __u64)
    pub const VHOST_SET_FEATURES: libc::c_ulong = 0x4008_af00;
    pub const VHOST_SET_OWNER: libc::c_ulong = 0xaf01;
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
    /// True once `VHOST_NET_SET_BACKEND` succeeded on every queue.
    pub bound: bool,
    /// True once mem-table + VRING GPA/HVA programming succeeded.
    pub rings_programmed: bool,
    /// TAP fd to attach as backend once the rings are programmed.
    tap_fd: Option<i32>,
    tap_queues: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    order: BindOrder,
    irq_relay: Option<IrqRelay>,
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
                tap_fd: None,
                tap_queues: 0,
                order: BindOrder::default(),
                irq_relay: None,
                queue_fds: Vec::new(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }

    /// Whether the kernel datapath owns RX/TX (skip userspace pump): the
    /// backend is attached to programmed rings AND the IRQ relay is running.
    pub fn kernel_datapath(&self) -> bool {
        self.bound && self.rings_programmed && self.irq_relay.is_some()
    }

    /// A TAP has been recorded for the late bind.
    pub fn has_tap(&self) -> bool {
        self.tap_fd.is_some()
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

    /// Remember the TAP to use as backend for queue 0 (RX) and 1 (TX) of this
    /// instance. No ioctl runs here: the kernel refuses the backend until the
    /// vrings are programmed, so [`Self::program_vrings`] attaches it last. A
    /// vhost-net fd has exactly two vrings, so `queues` is clamped to 2.
    pub fn attach_tap(&mut self, tap_fd: i32, queues: u32) -> Result<()> {
        if tap_fd < 0 {
            return Err(FluxError::Hypervisor("vhost attach_tap: bad TAP fd".into()));
        }
        self.tap_fd = Some(tap_fd);
        self.tap_queues = queues.clamp(1, 2);
        Ok(())
    }

    /// Run the full bring-up: owner, features, mem-table, rings, IRQ relay,
    /// then the TAP backend (H3 finish). `driver_features` are the features the
    /// guest negotiated; `raise` injects the guest vring interrupt.
    ///
    /// `host_base` / `ram_bytes` describe the contiguous guest RAM mmap
    /// (GPA 0 → `host_base`). `queues` must already have `ready != 0` and
    /// valid desc/avail/used GPAs from the guest driver.
    pub fn program_vrings(
        &mut self,
        host_base: *mut u8,
        ram_bytes: usize,
        queues: &[QueueState],
        driver_features: u64,
        raise: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use linux_ioctl::*;
            let tap_fd = self.tap_fd.ok_or_else(|| {
                FluxError::Hypervisor("vhost program_vrings before attach_tap".into())
            })?;
            if host_base.is_null() || ram_bytes == 0 {
                return Err(FluxError::Hypervisor(
                    "vhost mem-table needs non-empty guest RAM".into(),
                ));
            }
            self.order = BindOrder::default();
            self.order
                .enter(BindStep::Owner)
                .map_err(FluxError::Hypervisor)?;
            let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_OWNER) };
            if rc < 0 {
                return Err(FluxError::Hypervisor(format!(
                    "VHOST_SET_OWNER: {}",
                    std::io::Error::last_os_error()
                )));
            }
            self.order
                .enter(BindStep::Features)
                .map_err(FluxError::Hypervisor)?;
            let features: u64 = vhost_feature_mask(driver_features);
            let rc = unsafe { libc::ioctl(self.fd, VHOST_SET_FEATURES, &features as *const u64) };
            if rc < 0 {
                return Err(FluxError::Hypervisor(format!(
                    "VHOST_SET_FEATURES {features:#x}: {}",
                    std::io::Error::last_os_error()
                )));
            }
            self.order
                .enter(BindStep::MemTable)
                .map_err(FluxError::Hypervisor)?;
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

            self.order
                .enter(BindStep::Rings)
                .map_err(FluxError::Hypervisor)?;
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
            if self.queue_fds.len() < self.tap_queues as usize {
                return Err(FluxError::Hypervisor(
                    "vhost: fewer rings programmed than backend queues".into(),
                ));
            }
            self.rings_programmed = true;

            // The relay must be live before vhost can complete any buffer.
            self.order
                .enter(BindStep::IrqRelay)
                .map_err(FluxError::Hypervisor)?;
            let calls: Vec<i32> = self.queue_fds.iter().map(|q| q.call).collect();
            self.irq_relay = Some(IrqRelay::start(&calls, raise)?);

            self.order
                .enter(BindStep::Backend)
                .map_err(FluxError::Hypervisor)?;
            for index in 0..self.tap_queues {
                let file = VhostVringFile { index, fd: tap_fd };
                let rc = unsafe {
                    libc::ioctl(
                        self.fd,
                        VHOST_NET_SET_BACKEND,
                        &file as *const VhostVringFile,
                    )
                };
                if rc < 0 {
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
            let _ = (host_base, ram_bytes, queues, driver_features, raise);
            Err(FluxError::Hypervisor("vhost-net only on Linux".into()))
        }
    }
}

impl Drop for VhostNet {
    fn drop(&mut self) {
        self.irq_relay = None;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_mask_keeps_vhost_bits_and_drops_device_model_bits() {
        let mac = 1u64 << 5;
        let status = 1u64 << 16;
        let mq = 1u64 << 22;
        let m = vhost_feature_mask(VIRTIO_F_VERSION_1_BIT | mac | status | mq);
        assert_ne!(m & VIRTIO_F_VERSION_1_BIT, 0);
        assert_eq!(m & (mac | status | mq), 0);
        assert_ne!(m & VHOST_NET_F_VIRTIO_NET_HDR, 0);
        assert_eq!(m & VIRTIO_NET_F_MRG_RXBUF, 0);
    }

    #[test]
    fn feature_mask_follows_mrg_rxbuf_negotiation() {
        let with = vhost_feature_mask(VIRTIO_F_VERSION_1_BIT | VIRTIO_NET_F_MRG_RXBUF);
        assert_ne!(with & VIRTIO_NET_F_MRG_RXBUF, 0);
        let without = vhost_feature_mask(VIRTIO_F_VERSION_1_BIT);
        assert_eq!(without & VIRTIO_NET_F_MRG_RXBUF, 0);
        assert_eq!(vhost_feature_mask(0), VHOST_NET_F_VIRTIO_NET_HDR);
    }

    #[test]
    fn bind_order_accepts_only_the_kernel_sequence() {
        let mut o = BindOrder::default();
        for s in [
            BindStep::Owner,
            BindStep::Features,
            BindStep::MemTable,
            BindStep::Rings,
            BindStep::IrqRelay,
        ] {
            assert!(!o.complete());
            o.enter(s).unwrap();
        }
        o.enter(BindStep::Backend).unwrap();
        assert!(o.complete());
        assert!(o.enter(BindStep::Owner).is_err());
    }

    #[test]
    fn bind_order_rejects_backend_before_rings() {
        let mut o = BindOrder::default();
        assert!(o.enter(BindStep::Backend).is_err());
        o.enter(BindStep::Owner).unwrap();
        o.enter(BindStep::Features).unwrap();
        o.enter(BindStep::MemTable).unwrap();
        assert!(o.enter(BindStep::Backend).is_err());
        assert!(o.enter(BindStep::Features).is_err());
        assert!(!o.complete());
    }
}
