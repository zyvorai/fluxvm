// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Runtime control of the in-tree KVM engine's virtio-balloon.
//!
//! The VMM runs on its own thread and owns the `VirtualMachine`, so the
//! control API cannot reach the balloon device directly. The thread publishes
//! the device handle into a [`BalloonSlot`] once the VM is built; the control
//! API (`ApiRequest::Balloon`) reads the slot, writes the new target into the
//! device config and raises a config-change interrupt so the guest driver
//! inflates or deflates toward it.

use crate::devices::virtio_mmio::VirtioMmio;
use crate::error::{FluxError, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Guest memory that is never reclaimed through the balloon.
pub const MIN_GUEST_MIB: u64 = 64;

const PAGES_PER_MIB: u64 = 256;

/// Where the running VMM publishes its balloon device.
#[derive(Default)]
pub struct BalloonSlot {
    dev: Mutex<Option<Arc<VirtioMmio>>>,
    memory_mib: Mutex<u64>,
}

/// What `ApiRequest::Balloon` reports (JSON-encoded into the response).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonStatus {
    pub memory_mib: u64,
    /// Requested balloon size: memory taken away from the guest.
    pub target_mib: u64,
    /// Balloon size the guest driver has reached so far.
    pub actual_mib: u64,
}

impl BalloonSlot {
    pub fn publish(&self, dev: Option<Arc<VirtioMmio>>, memory_mib: u64) {
        *self.dev.lock().unwrap_or_else(|e| e.into_inner()) = dev;
        *self.memory_mib.lock().unwrap_or_else(|e| e.into_inner()) = memory_mib;
    }

    fn device(&self) -> Result<Arc<VirtioMmio>> {
        self.dev
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| FluxError::Unsupported("this VM has no virtio-balloon device".into()))
    }

    fn memory_mib(&self) -> u64 {
        *self.memory_mib.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current target and progress.
    pub fn status(&self) -> Result<BalloonStatus> {
        let dev = self.device()?;
        let st = dev.state.lock().unwrap_or_else(|e| e.into_inner());
        Ok(BalloonStatus {
            memory_mib: self.memory_mib(),
            target_mib: pages_to_mib(st.balloon_num_pages),
            actual_mib: pages_to_mib(st.balloon_actual),
        })
    }

    /// Ask the guest to give back `balloon_mib` MiB (0 deflates fully).
    pub fn set_target(&self, balloon_mib: u64) -> Result<BalloonStatus> {
        let dev = self.device()?;
        let pages = plan_balloon_pages(self.memory_mib(), balloon_mib)?;
        {
            let mut st = dev.state.lock().unwrap_or_else(|e| e.into_inner());
            st.balloon_num_pages = pages;
        }
        dev.raise_config_interrupt();
        self.status()
    }
}

fn pages_to_mib(pages: u32) -> u64 {
    pages as u64 / PAGES_PER_MIB
}

/// Validate a balloon size against the VM's memory and return 4 KiB pages.
pub fn plan_balloon_pages(memory_mib: u64, balloon_mib: u64) -> Result<u32> {
    let max = memory_mib.saturating_sub(MIN_GUEST_MIB);
    if balloon_mib > max {
        return Err(FluxError::Unsupported(format!(
            "balloon of {balloon_mib} MiB leaves the guest under {MIN_GUEST_MIB} MiB \
             (memory {memory_mib} MiB, max balloon {max} MiB)"
        )));
    }
    u32::try_from(balloon_mib * PAGES_PER_MIB)
        .map_err(|_| FluxError::Unsupported("balloon size overflows the page counter".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_mib_to_pages() {
        assert_eq!(plan_balloon_pages(1024, 0).unwrap(), 0);
        assert_eq!(plan_balloon_pages(1024, 256).unwrap(), 65536);
    }

    #[test]
    fn keeps_a_floor_of_guest_memory() {
        assert_eq!(plan_balloon_pages(1024, 960).unwrap(), 960 * 256);
        assert!(plan_balloon_pages(1024, 961).is_err());
        assert!(plan_balloon_pages(32, 1).is_err());
    }

    #[test]
    fn empty_slot_reports_no_device() {
        let slot = BalloonSlot::default();
        assert!(slot.status().is_err());
        assert!(slot.set_target(10).is_err());
    }
}
