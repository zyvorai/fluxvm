// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Multi-vCPU pause barrier.
//!
//! Same shape as Firecracker (`Pause` event + signal kick + `Paused`
//! response from every vCPU thread), Cloud Hypervisor (per-vCPU paused flag)
//! and QEMU (`pause_all_vcpus`): the controller sets the pause flag, kicks
//! every vCPU out of `KVM_RUN` (`immediate_exit` plus a signal to the
//! thread), and only reports the guest quiesced once *every* vCPU thread has
//! parked in userspace and acknowledged the current pause epoch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Byte offset of `immediate_exit` in the `kvm_run` page.
const IMMEDIATE_EXIT_OFFSET: usize = 1;

extern "C" fn noop_signal_handler(_: i32) {}

/// vCPU thread registry used to force each vCPU out of a blocking `KVM_RUN`.
pub struct VcpuKick {
    /// Per vCPU: `(tid, address of the kvm_run page)` once its thread runs.
    slots: Mutex<Vec<Option<(i32, usize)>>>,
}

impl VcpuKick {
    pub fn new(num_cpus: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(vec![None; num_cpus]),
        })
    }

    /// Call from the vCPU's own thread before its `KVM_RUN` loop.
    ///
    /// `run` must stay mapped until [`VcpuKick::clear`] is called.
    pub fn register(&self, idx: usize, run: *mut u8) {
        install_signal_handler();
        if let Some(slot) = self.slots.lock().unwrap().get_mut(idx) {
            *slot = Some((current_tid(), run as usize));
        }
    }

    /// Forget every vCPU; called before the `kvm_run` pages are unmapped.
    pub fn clear(&self) {
        for slot in self.slots.lock().unwrap().iter_mut() {
            *slot = None;
        }
    }

    /// Make every registered vCPU's current or next `KVM_RUN` return.
    pub fn kick_all(&self) {
        for slot in self.slots.lock().unwrap().iter().flatten() {
            let (tid, run) = *slot;
            // SAFETY: registered pages stay mapped until `clear`, which
            // takes this same lock.
            unsafe {
                std::ptr::write_volatile((run as *mut u8).add(IMMEDIATE_EXIT_OFFSET), 1);
            }
            signal_thread(tid);
        }
    }
}

/// Clears the registry on drop so no kick can touch an unmapped `kvm_run`
/// page, including on early error returns.
pub struct KickGuard(pub Arc<VcpuKick>);

impl Drop for KickGuard {
    fn drop(&mut self) {
        self.0.clear();
    }
}

/// Everything a running VM needs to take part in the controller's pause.
#[derive(Clone)]
pub struct PauseHandles {
    /// Bumped by the controller for every pause request.
    pub requested: Arc<AtomicU64>,
    /// Published by the BSP once every vCPU acknowledged `requested`.
    pub quiesced: Arc<AtomicU64>,
    pub kick: Arc<VcpuKick>,
}

/// Per-AP acknowledgements of the current pause epoch (index 0 unused: the
/// BSP publishes the aggregate itself).
pub struct ApAcks {
    acks: Vec<AtomicU64>,
}

impl ApAcks {
    pub fn new(num_cpus: usize) -> Arc<Self> {
        Arc::new(Self {
            acks: (0..num_cpus).map(|_| AtomicU64::new(0)).collect(),
        })
    }

    pub fn ack(&self, idx: usize, epoch: u64) {
        if let Some(a) = self.acks.get(idx) {
            a.store(epoch, Ordering::SeqCst);
        }
    }

    pub fn all_aps_acked(&self, epoch: u64) -> bool {
        self.acks
            .iter()
            .skip(1)
            .all(|a| a.load(Ordering::SeqCst) == epoch)
    }
}

/// SIGUSR1 defaults to terminating the process; a no-op handler turns it
/// into a pure "interrupt the blocking ioctl" signal.
fn install_signal_handler() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        libc::signal(libc::SIGUSR1, noop_signal_handler as *const () as usize);
    });
}

#[cfg(target_os = "linux")]
fn current_tid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

#[cfg(not(target_os = "linux"))]
fn current_tid() -> i32 {
    0
}

#[cfg(target_os = "linux")]
fn signal_thread(tid: i32) {
    if tid != 0 {
        unsafe {
            libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGUSR1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_thread(_tid: i32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_ack_needs_every_ap_on_the_current_epoch() {
        let acks = ApAcks::new(4);
        assert!(!acks.all_aps_acked(1));
        acks.ack(1, 1);
        acks.ack(2, 1);
        assert!(!acks.all_aps_acked(1));
        acks.ack(3, 1);
        assert!(acks.all_aps_acked(1));
        // A newer pause request invalidates the old acknowledgements.
        assert!(!acks.all_aps_acked(2));
    }

    #[test]
    fn single_vcpu_has_no_aps_to_wait_for() {
        assert!(ApAcks::new(1).all_aps_acked(7));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kick_sets_immediate_exit_and_survives_clear() {
        let kick = VcpuKick::new(2);
        let mut page = [0u8; 16];
        kick.register(1, page.as_mut_ptr());
        kick.kick_all();
        assert_eq!(page[IMMEDIATE_EXIT_OFFSET], 1);
        kick.clear();
        page[IMMEDIATE_EXIT_OFFSET] = 0;
        kick.kick_all();
        assert_eq!(
            page[IMMEDIATE_EXIT_OFFSET], 0,
            "cleared slots must not be touched"
        );
    }
}
