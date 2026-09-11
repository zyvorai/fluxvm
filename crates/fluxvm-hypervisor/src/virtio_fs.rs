// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! P3: virtio-fs (vhost-user-fs) — cloud-hypervisor SoT.
//! Built only when product demands shared FS; API surface is ready.

use crate::error::{FluxError, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct VirtioFsConfig {
    pub tag: String,
    pub socket: PathBuf,
}

pub fn attach(_cfg: &VirtioFsConfig) -> Result<()> {
    Err(FluxError::Unsupported(
        "virtio-fs deferred (P3): enable when product requires shared FS; SoT=cloud-hypervisor"
            .into(),
    ))
}
