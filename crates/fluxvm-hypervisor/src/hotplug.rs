// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! P3: CPU/device hotplug — cloud-hypervisor SoT. Demand-driven.

use crate::error::{FluxError, Result};

pub fn add_vcpu(_id: u8) -> Result<()> {
    Err(FluxError::Unsupported(
        "CPU hotplug deferred (P3): SoT=cloud-hypervisor".into(),
    ))
}

pub fn remove_vcpu(_id: u8) -> Result<()> {
    Err(FluxError::Unsupported(
        "CPU hotplug deferred (P3): SoT=cloud-hypervisor".into(),
    ))
}

pub fn hotplug_disk(_path: &str) -> Result<()> {
    Err(FluxError::Unsupported(
        "device hotplug deferred (P3): SoT=cloud-hypervisor".into(),
    ))
}
