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
        }
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
                        Ok(()) => eprintln!("[net] vhost VRING GPA programmed (H3)"),
                        Err(e) => eprintln!("[net] vhost VRING program deferred: {e}"),
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
                eprintln!("[net] processed q={q} frames={n}");
                drop(st);
                net.raise_vring_interrupt();
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
                eprintln!("[blk] processed q={q} reqs={n}");
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
                    eprintln!("[vsock] processed q={q} pkts={n}");
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
                    eprintln!("[balloon] q={q} bufs={n}");
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
                    eprintln!("[rng] q={q} bufs={n}");
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
pub fn start(kvm: &KvmVm, svc: Arc<Mutex<QueueService>>, stop: Arc<AtomicBool>) -> Result<()> {
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
    std::thread::spawn(move || worker(svc, bindings, stop));
    Ok(())
}

#[cfg(target_os = "linux")]
fn worker(svc: Arc<Mutex<QueueService>>, bindings: Vec<Binding>, stop: Arc<AtomicBool>) {
    let mut pfds: Vec<libc::pollfd> = bindings
        .iter()
        .map(|b| libc::pollfd {
            fd: b.fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    while !stop.load(Ordering::Relaxed) {
        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 100) };
        if rc <= 0 {
            continue;
        }
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
                svc.lock().unwrap().notify(b.dev, b.queue);
            }
        }
    }
    for b in &bindings {
        close_eventfd(b.fd);
    }
}

#[cfg(not(target_os = "linux"))]
fn worker(_svc: Arc<Mutex<QueueService>>, bindings: Vec<Binding>, _stop: Arc<AtomicBool>) {
    for b in &bindings {
        close_eventfd(b.fd);
    }
}
