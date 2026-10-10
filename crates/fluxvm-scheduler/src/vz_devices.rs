// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Read-only device state and a few controls of a running `vz` VM that the runner already serves over its control
//! socket: EFI Secure Boot status, the custom Virtio device, and USB devices (mounted mass storage and passthrough).

use crate::{VmManager, audit_event};
use anyhow::{Result, bail};
use fluxvm_core::model::{BackendKind, VmRecord, VmStatus};
use serde_json::Value;
use uuid::Uuid;

impl VmManager {
    async fn vz_running_vm(&self, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Vz {
            bail!("this is a vz backend feature");
        }
        if vm.status != VmStatus::Running {
            bail!("the VM is {:?}; start it first", vm.status);
        }
        Ok(vm)
    }

    /// `{"enabled", "kek", "db", "dbx"}`; `"as_of":"boot"` while the guest runs (the variable store is locked).
    pub async fn vz_secure_boot_status(&self, id: Uuid) -> Result<Value> {
        fluxvm_apple::vz27::secure_boot_status(&self.vz_running_vm(id).await?).await
    }

    /// Driver state and request counters of the custom Virtio device.
    pub async fn vz_custom_virtio_status(&self, id: Uuid) -> Result<Value> {
        fluxvm_apple::vz27::custom_virtio_status(&self.vz_running_vm(id).await?).await
    }

    /// Asks the custom Virtio device to reset; the guest driver re-negotiates.
    pub async fn vz_custom_virtio_reset(&self, id: Uuid) -> Result<()> {
        let vm = self.vz_running_vm(id).await?;
        fluxvm_apple::vz27::custom_virtio_reset(&vm).await?;
        audit_event("vm.custom_virtio_reset", &[("vm_id", &id.to_string())]);
        Ok(())
    }

    /// USB devices on the VM's controllers right now.
    pub async fn vz_usb_list(&self, id: Uuid) -> Result<Vec<Value>> {
        fluxvm_apple::vz27::usb_list(&self.vz_running_vm(id).await?).await
    }

    /// Host USB accessories the user has granted to FluxVMUSBAccess.app.
    pub async fn vz_usb_physical_list(&self, id: Uuid) -> Result<Vec<Value>> {
        fluxvm_apple::physical_usb_list(&self.vz_running_vm(id).await?).await
    }

    /// Passes a host USB accessory through to the guest; returns the attached device's UUID.
    pub async fn vz_usb_physical_attach(&self, id: Uuid, registry_id: u64) -> Result<String> {
        let vm = self.vz_running_vm(id).await?;
        let uuid = fluxvm_apple::physical_usb_attach(&vm, registry_id).await?;
        audit_event(
            "vm.usb_passthrough",
            &[
                ("vm_id", &id.to_string()),
                ("registry_id", &registry_id.to_string()),
            ],
        );
        Ok(uuid)
    }
}

/// What this Mac's Virtualization.framework offers (OS version, vmnet, custom Virtio, Secure Boot, Rosetta...), asked
/// of the signed runner helper. Errors off macOS.
pub async fn apple_host_capabilities() -> Result<Value> {
    let caps = tokio::task::spawn_blocking(fluxvm_apple::host_capabilities).await??;
    Ok(serde_json::to_value(caps)?)
}
