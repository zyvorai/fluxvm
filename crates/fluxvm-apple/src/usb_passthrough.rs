// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result, bail};
use fluxvm_core::model::VmRecord;
use serde_json::Value;

fn socket(vm: &VmRecord) -> Result<&std::path::Path> {
    vm.control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")
}

pub async fn physical_usb_list(vm: &VmRecord) -> Result<Vec<Value>> {
    let reply =
        crate::control_call_with(socket(vm)?, serde_json::json!({"cmd":"usb-physical-list"}))
            .await?;
    if !reply.ok() {
        bail!(
            "runner refused usb-physical-list: {}",
            reply.error().unwrap_or("unknown error")
        );
    }
    Ok(reply
        .0
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

pub async fn physical_usb_attach(vm: &VmRecord, registry_id: u64) -> Result<String> {
    let reply = crate::control_call_with(
        socket(vm)?,
        serde_json::json!({"cmd":"usb-physical-attach","registry_id":registry_id}),
    )
    .await?;
    if !reply.ok() {
        bail!(
            "runner refused usb-physical-attach: {}",
            reply.error().unwrap_or("unknown error")
        );
    }
    reply
        .0
        .get("uuid")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .context("usb-physical-attach reply had no uuid")
}
