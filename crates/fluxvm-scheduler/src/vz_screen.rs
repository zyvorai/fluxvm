// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Screenshots and keyboard/mouse input for the display of a running `vz` VM (Linux or macOS guest), for agents that
//! drive a guest's GUI or text console.

use crate::VmManager;
use anyhow::{Result, bail};
pub use fluxvm_apple::screen::{InputAction, Screenshot};
use fluxvm_core::model::{BackendKind, VmRecord, VmStatus};
use uuid::Uuid;

impl VmManager {
    async fn vz_display_vm(&self, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Vz {
            bail!("screenshots and input are a vz backend feature");
        }
        if vm.status != VmStatus::Running {
            bail!("the VM is {:?}; start it first", vm.status);
        }
        Ok(vm)
    }

    /// The guest display as a PNG, scaled down to `max_width` pixels wide if it is wider.
    pub async fn vm_screenshot(&self, id: Uuid, max_width: Option<u32>) -> Result<Screenshot> {
        if max_width.is_some_and(|w| !(64..=8192).contains(&w)) {
            bail!("max_width must be 64-8192");
        }
        let vm = self.vz_display_vm(id).await?;
        fluxvm_apple::screen::screenshot(&vm, max_width).await
    }

    /// Sends keyboard and mouse `actions` to the guest display in order; returns how many ran.
    pub async fn vm_input(&self, id: Uuid, actions: &[InputAction]) -> Result<usize> {
        let vm = self.vz_display_vm(id).await?;
        let n = fluxvm_apple::screen::input(&vm, actions).await?;
        tracing::info!(vm = %id, actions = n, "display input");
        Ok(n)
    }
}
