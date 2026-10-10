// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Runner control calls for the macOS 27 Virtualization additions: EFI Secure Boot status, the custom Virtio device's
//! lifecycle, and the USB devices currently on the VM's controllers.

use anyhow::{Context, Result, bail};
use fluxvm_core::model::VmRecord;
use serde_json::Value;

async fn call(vm: &VmRecord, cmd: &str) -> Result<Value> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let reply = crate::control_call_with(sock, serde_json::json!({ "cmd": cmd }))
        .await
        .with_context(|| format!("runner `{cmd}`"))?;
    if !reply.ok() {
        bail!(
            "runner refused {cmd}: {}",
            reply.error().unwrap_or("unknown error")
        );
    }
    Ok(reply.0)
}

/// `{"enabled": bool, "kek": n, "db": n, "dbx": n}` for an EFI guest.
pub async fn secure_boot_status(vm: &VmRecord) -> Result<Value> {
    call(vm, "secure-boot-status").await
}

/// Asks the custom Virtio device to reset; the guest driver re-negotiates.
pub async fn custom_virtio_reset(vm: &VmRecord) -> Result<()> {
    call(vm, "virtio-reset").await.map(|_| ())
}

/// Driver state and request counters of the custom Virtio device.
pub async fn custom_virtio_status(vm: &VmRecord) -> Result<Value> {
    call(vm, "virtio-status").await
}

/// USB devices attached right now (`kind` is `mass-storage` or `passthrough`); a passthrough device the host
/// reclaimed is already gone from this list.
pub async fn usb_list(vm: &VmRecord) -> Result<Vec<Value>> {
    Ok(call(vm, "usb-list")
        .await?
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}
