// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! P3: live migration — cloud-hypervisor SoT. Demand-driven.

use crate::error::{FluxError, Result};
use std::path::Path;

pub fn export_state(_path: &Path) -> Result<()> {
    Err(FluxError::Unsupported(
        "live migration deferred (P3): SoT=cloud-hypervisor".into(),
    ))
}

pub fn import_state(_path: &Path) -> Result<()> {
    Err(FluxError::Unsupported(
        "live migration deferred (P3): SoT=cloud-hypervisor".into(),
    ))
}
