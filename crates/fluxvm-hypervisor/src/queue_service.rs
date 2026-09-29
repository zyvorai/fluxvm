// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Virtio queue servicing off the vCPU threads.
//!
//! Each virtio-mmio `QueueNotify` register is bound to an eventfd with
//! `KVM_IOEVENTFD` (one per device queue, matched on the queue index), the
//! way Firecracker and Cloud Hypervisor do it. A guest notify from *any*
//! vCPU is then completed inside the kernel and wakes this worker thread;
//! no vCPU exits to userspace and no vCPU has to own the device backends.

use crate::devices::eventfd::{close_eventfd, create_eventfd};
use crate::devices::rate_limiter::RateLimiter;
use crate::devices::virtio_blk::{self, BlockBackend};
use crate::devices::virtio_mmio::VirtioMmio;
use crate::devices::virtio_net;
use crate::devices::virtio_vsock::{self, VsockBackend};
use crate::devices::{virtio_balloon, virtio_rng};
use crate::error::Result;
use crate::kvm::KvmVm;
use crate::memory::GuestMemory;
use crate::tap::Tap;
use crate::vhost::VhostNet;

/// Per-notify/per-poll device diagnostics (`[blk] processed ...`, the
/// periodic `[net]` stats line, ...) are opt-in via this env var. They are
/// pure noise on a healthy boot, and each is one independent `eprintln!`
/// call racing the serial device's own per-byte `io::stdout()` lock
/// (`devices/serial.rs`) from a different thread: printed by default, they
/// can land mid-line of the guest's own console output and corrupt any test
/// harness that scrapes the combined stdout+stderr stream (observed:
/// `scripts/test-kvm-topology.sh` losing/garbling a `TOPO_CPUINFO` line).
/// Error paths stay unconditional; they are rare and worth seeing.
fn verbose_io() -> bool {
    static VERBOSE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *VERBOSE.get_or_init(|| std::env::var_os("FLUXVM_VERBOSE_IO").is_some())
}
use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// virtio-mmio register offset of `QueueNotify`.
const QUEUE_NOTIFY_OFFSET: u64 = 0x50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dev {
    Net,
    Blk,
    Vsock,
    Balloon,
    Rng,
}

/// Everything the queue handlers touch. Shared behind one mutex so the
/// worker, the vsock host-side poll and snapshot dumps never interleave on
/// the same rings or guest RAM.
pub struct QueueService {
    /// Shallow alias of the VM's RAM mapping; never unmapped from here.
    mem: ManuallyDrop<GuestMemory>,
    pub net: Option<Arc<VirtioMmio>>,
    pub blk: Option<Arc<VirtioMmio>>,
    pub blk_backend: Option<Arc<BlockBackend>>,
    pub vsock: Option<Arc<VirtioMmio>>,
    pub vsock_backend: Option<Arc<VsockBackend>>,
    pub balloon: Option<Arc<VirtioMmio>>,
    pub rng: Option<Arc<VirtioMmio>>,
    pub net_limiter: Arc<RateLimiter>,
    pub blk_limiter: Arc<RateLimiter>,
    pub tap: Option<Tap>,
    pub vhost: Option<VhostNet>,
    pub net_stats: virtio_net::NetStats,
    rx_scratch: Vec<u8>,
}

// SAFETY: the raw RAM pointer is a process-wide shared mapping that outlives
// the VM run, and every other field is either an `Arc` of a thread-safe
// device or an owned fd wrapper. All access is serialized by the mutex.
unsafe impl Send for QueueService {}

impl QueueService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mem: &GuestMemory,
        net: Option<Arc<VirtioMmio>>,
        blk: Option<Arc<VirtioMmio>>,
        blk_backend: Option<Arc<BlockBackend>>,
        vsock: Option<Arc<VirtioMmio>>,
        vsock_backend: Option<Arc<VsockBackend>>,
        balloon: Option<Arc<VirtioMmio>>,
        rng: Option<Arc<VirtioMmio>>,
        net_limiter: Arc<RateLimiter>,
        blk_limiter: Arc<RateLimiter>,
        tap: Option<Tap>,
        vhost: Option<VhostNet>,
    ) -> Self {
        Self {
            mem: ManuallyDrop::new(mem.clone()),
            net,
            blk,
            blk_backend,
            vsock,
            vsock_backend,
            balloon,
            rng,
            net_limiter,
            blk_limiter,
            tap,
            vhost,
            net_stats: virtio_net::NetStats::default(),
            rx_scratch: vec![0u8; virtio_net::RX_FRAME_MAX],
        }
    }

    /// Tap fd the worker should poll for guest-bound frames, when the
    /// userspace datapath owns it.
    fn rx_poll_fd(&self) -> Option<i32> {
        if self.net.is_none() || self.vhost_owns_tap() {
            return None;
        }
        self.tap.as_ref().map(|t| t.fd)
    }

    fn vhost_owns_tap(&self) -> bool {
        self.vhost
            .as_ref()
            .map(|v| v.kernel_datapath())
            .unwrap_or(false)
    }

    /// Deliver pending tap frames into guest RX buffers (queue 0).
    fn net_rx(&mut self) -> Result<virtio_net::RxPump> {
        let (Some(net), Some(tap)) = (self.net.clone(), self.tap.as_ref()) else {
            return Ok(virtio_net::RxPump::NoBuffers);
        };
        if self.vhost_owns_tap() {
            return Ok(virtio_net::RxPump::NoBuffers);
        }
        let mut st = net.state.lock().unwrap();
        if st.queues.is_empty() {
            return Ok(virtio_net::RxPump::NoBuffers);
        }
        let (state, irq) = virtio_net::rx_pump(
            &mut self.mem,
            &mut st,
            tap,
            Some(self.net_limiter.as_ref()),
            &mut self.net_stats,
            &mut self.rx_scratch,
            32,
        )?;
        drop(st);
        if irq {
            net.raise_vring_interrupt();
        }
        Ok(state)
    }

    fn net_stats_line(&self) -> String {
        let s = &self.net_stats;
        format!(
            "[net] rx frames={} bytes={} drops(no_buf={} too_small={} invalid={} rate={}) tx frames={}",
            s.rx_frames,
            s.rx_bytes,
            s.rx_no_buffer,
            s.rx_too_small,
            s.rx_invalid,
            s.rx_rate_limited,
            s.tx_frames
        )
    }

    fn device(&self, dev: Dev) -> Option<&Arc<VirtioMmio>> {
        match dev {
            Dev::Net => self.net.as_ref(),
            Dev::Blk => self.blk.as_ref(),
            Dev::Vsock => self.vsock.as_ref(),
            Dev::Balloon => self.balloon.as_ref(),
            Dev::Rng => self.rng.as_ref(),
        }
    }

    /// Service one queue of one device after a guest notify.
    pub fn notify(&mut self, dev: Dev, q: u32) {
        match dev {
            Dev::Net => self.notify_net(q),
            Dev::Blk => self.notify_blk(q),
            Dev::Vsock => self.notify_vsock(q),
            Dev::Balloon => self.notify_balloon(q),
            Dev::Rng => self.notify_rng(q),
        }
    }

    fn notify_net(&mut self, q: u32) {
        let Some(net) = self.net.clone() else { return };
        // H3: when vhost rings are programmed, kick the kernel datapath
        // instead of the userspace pump.
        if self
            .vhost
            .as_ref()
            .map(|v| v.kernel_datapath())
            .unwrap_or(false)
        {
            if let Some(v) = self.vhost.as_ref() {
                if let Err(e) = v.signal_kick(q as usize) {
                    eprintln!("[net] vhost kick q={q}: {e}");
                }
            }
            return;
        }
        // Late-bind VRING GPA once the guest marks both net queues ready
        // (desc/avail/used set).
        if let Some(v) = self.vhost.as_mut() {
            if v.bound && !v.rings_programmed {
                let qs = {
                    let st = net.state.lock().unwrap();
                    st.queues[..st.num_queues.min(2) as usize].to_vec()
                };
                let ready = qs.len() >= 2
                    && qs.iter().all(|qq| {
                        qq.ready != 0 && qq.num > 0 && qq.desc != 0 && qq.avail != 0 && qq.used != 0
                    });
                if ready {
                    match v.program_vrings(self.mem.host_ptr(), self.mem.len(), &qs) {
                        Ok(()) => {
                            if verbose_io() {
                                eprintln!("[net] vhost VRING GPA programmed (H3)");
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[net] vhost-net cannot program vrings ({e}); falling back to userspace virtio-net"
                            );
                            self.vhost = None;
                        }
                    }
                }
            }
        }
        // If programming just succeeded, kick instead of pump.
        if self
            .vhost
            .as_ref()
            .map(|v| v.kernel_datapath())
            .unwrap_or(false)
        {
            if let Some(v) = self.vhost.as_ref() {
                let _ = v.signal_kick(q as usize);
            }
            return;
        }
        let mut st = net.state.lock().unwrap();
        match virtio_net::handle_notify(
            &mut self.mem,
            &mut st,
            self.tap.as_ref(),
            q,
            Some(self.net_limiter.as_ref()),
        ) {
            Ok(n) => {
                drop(st);
                if q == 1 {
                    self.net_stats.tx_frames += n as u64;
                    net.raise_vring_interrupt();
                }
            }
            Err(e) => eprintln!("[net] notify err {e}"),
        }
    }

    fn notify_blk(&mut self, q: u32) {
        let (Some(blk), Some(backend)) = (self.blk.clone(), self.blk_backend.clone()) else {
            return;
        };
        let mut st = blk.state.lock().unwrap();
        match virtio_blk::handle_notify(
            &mut self.mem,
            &mut st,
            backend.as_ref(),
            q,
            Some(self.blk_limiter.as_ref()),
        ) {
            Ok(n) => {
                if verbose_io() {
                    eprintln!("[blk] processed q={q} reqs={n}");
                };
                drop(st);
                blk.raise_vring_interrupt();
            }
            Err(e) => eprintln!("[blk] notify err {e}"),
        }
    }

    fn notify_vsock(&mut self, q: u32) {
        let Some(vsock) = self.vsock.clone() else {
            return;
        };
        let mut st = vsock.state.lock().unwrap();
        match virtio_vsock::handle_notify(&mut self.mem, &mut st, q, self.vsock_backend.as_deref())
        {
            Ok(n) => {
                if n > 0 {
                    if verbose_io() {
                        eprintln!("[vsock] processed q={q} pkts={n}");
                    };
                }
                drop(st);
                vsock.raise_vring_interrupt();
            }
            Err(e) => eprintln!("[vsock] notify err {e}"),
        }
    }

    fn notify_balloon(&mut self, q: u32) {
        let Some(balloon) = self.balloon.clone() else {
            return;
        };
        let mut st = balloon.state.lock().unwrap();
        match virtio_balloon::handle_notify(&mut self.mem, &mut st, q) {
            Ok(n) => {
                if n > 0 {
                    if verbose_io() {
                        eprintln!("[balloon] q={q} bufs={n}");
                    };
                }
                drop(st);
                balloon.raise_vring_interrupt();
            }
            Err(e) => eprintln!("[balloon] notify err {e}"),
        }
    }

    fn notify_rng(&mut self, q: u32) {
        let Some(rng) = self.rng.clone() else { return };
        let mut st = rng.state.lock().unwrap();
        match virtio_rng::handle_notify(&mut self.mem, &mut st, q) {
            Ok(n) => {
                if n > 0 {
                    if verbose_io() {
                        eprintln!("[rng] q={q} bufs={n}");
                    };
                }
                drop(st);
                rng.raise_vring_interrupt();
            }
            Err(e) => eprintln!("[rng] notify err {e}"),
        }
    }

    /// Host-initiated vsock work (accept CONNECT / shuttle RW) when the
    /// guest is not notifying.
    pub fn vsock_poll(&mut self) {
        let (Some(vsock), Some(be)) = (self.vsock.clone(), self.vsock_backend.clone()) else {
            return;
        };
        let mut st = vsock.state.lock().unwrap();
        match virtio_vsock::poll(&mut self.mem, &mut st, be.as_ref()) {
            Ok(n) if n > 0 => {
                drop(st);
                vsock.raise_vring_interrupt();
            }
            Ok(_) => {}
            Err(e) => eprintln!("[vsock] poll err {e}"),
        }
    }
}

/// One registered `(eventfd, device, queue)` binding.
struct Binding {
    fd: i32,
    dev: Dev,
    queue: u32,
}

/// Bind every device queue's `QueueNotify` write to an eventfd and start the
/// worker that drains them. Returns once registration is complete; any
/// registration failure is fatal because without it guest notifies would be
/// silently dropped.
pub fn start(
    kvm: &KvmVm,
    svc: Arc<Mutex<QueueService>>,
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) -> Result<()> {
    let mut bindings: Vec<Binding> = Vec::new();
    {
        let s = svc.lock().unwrap();
        for dev in [Dev::Net, Dev::Blk, Dev::Vsock, Dev::Balloon, Dev::Rng] {
            let Some(d) = s.device(dev) else { continue };
            let queues = d.state.lock().unwrap().num_queues.min(4);
            for queue in 0..queues {
                let fd = create_eventfd();
                if fd < 0 {
                    for b in &bindings {
                        close_eventfd(b.fd);
                    }
                    return Err(crate::error::FluxError::Hypervisor(
                        "eventfd for queue notify".into(),
                    ));
                }
                if let Err(e) = kvm.register_ioeventfd(d.base() + QUEUE_NOTIFY_OFFSET, queue, fd) {
                    close_eventfd(fd);
                    for b in &bindings {
                        close_eventfd(b.fd);
                    }
                    return Err(e);
                }
                bindings.push(Binding { fd, dev, queue });
            }
        }
    }
    if bindings.is_empty() {
        return Ok(());
    }
    std::thread::spawn(move || worker(svc, bindings, stop, paused));
    Ok(())
}

#[cfg(target_os = "linux")]
fn worker(
    svc: Arc<Mutex<QueueService>>,
    bindings: Vec<Binding>,
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    use crate::devices::virtio_net::RxPump;
    let tap_fd = svc.lock().unwrap().rx_poll_fd();
    let mut pfds: Vec<libc::pollfd> = bindings
        .iter()
        .map(|b| libc::pollfd {
            fd: b.fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let tap_idx = pfds.len();
    if let Some(fd) = tap_fd {
        pfds.push(libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
    }
    // Level-triggered tap polling stays off while the guest has no RX buffer
    // (or the VM is paused) so a backlog cannot spin this thread; a queue 0
    // kick or the 100 ms tick turns it back on.
    let mut rx_armed = tap_fd.is_some();
    let mut last_stats = String::new();
    let mut last_log = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let is_paused = paused.load(Ordering::Relaxed);
        if tap_fd.is_some() {
            pfds[tap_idx].events = if rx_armed && !is_paused {
                libc::POLLIN
            } else {
                0
            };
        }
        if tap_fd.is_some() && last_log.elapsed() >= std::time::Duration::from_secs(5) {
            last_log = std::time::Instant::now();
            let line = svc.lock().unwrap().net_stats_line();
            if line != last_stats {
                if verbose_io() {
                    eprintln!("{line}");
                }
                last_stats = line;
            }
        }
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 100) };
        if rc == 0 {
            rx_armed = tap_fd.is_some();
            continue;
        }
        if rc < 0 {
            continue;
        }
        let mut rx_kick = false;
        for (pfd, b) in pfds.iter_mut().zip(&bindings) {
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            pfd.revents = 0;
            let mut counter = 0u64;
            let n = unsafe {
                libc::read(
                    b.fd,
                    &mut counter as *mut u64 as *mut libc::c_void,
                    std::mem::size_of::<u64>(),
                )
            };
            if n == std::mem::size_of::<u64>() as isize {
                if b.dev == Dev::Net && b.queue == 0 && tap_fd.is_some() {
                    rx_kick = true;
                } else {
                    svc.lock().unwrap().notify(b.dev, b.queue);
                }
            }
        }
        if tap_fd.is_some() {
            let tap_ready = pfds[tap_idx].revents & (libc::POLLIN | libc::POLLERR) != 0;
            pfds[tap_idx].revents = 0;
            if rx_kick {
                rx_armed = true;
            }
            if (tap_ready || rx_kick) && !paused.load(Ordering::Relaxed) {
                loop {
                    let r = svc.lock().unwrap().net_rx();
                    match r {
                        Ok(RxPump::More) if !stop.load(Ordering::Relaxed) => continue,
                        Ok(RxPump::More) | Ok(RxPump::Idle) => break,
                        Ok(RxPump::NoBuffers) => {
                            rx_armed = false;
                            break;
                        }
                        Err(e) => {
                            eprintln!("[net] rx: {e}");
                            rx_armed = false;
                            break;
                        }
                    }
                }
            }
        }
    }
    if verbose_io() {
        eprintln!("{}", svc.lock().unwrap().net_stats_line());
    }
    for b in &bindings {
        close_eventfd(b.fd);
    }
}

#[cfg(not(target_os = "linux"))]
fn worker(
    _svc: Arc<Mutex<QueueService>>,
    bindings: Vec<Binding>,
    _stop: Arc<AtomicBool>,
    _paused: Arc<AtomicBool>,
) {
    for b in &bindings {
        close_eventfd(b.fd);
    }
}
