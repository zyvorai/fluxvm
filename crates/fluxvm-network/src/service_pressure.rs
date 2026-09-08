// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Adaptive map pressure controller for Service Fabric.
//!
//! `max_entries` is an ELF/object ABI property — live resize requires a
//! controlled program reload (generation bump + pin recreate). This module
//! observes conntrack pressure, runs GC, and optionally fail-closes until
//! `sync_all` restores maps.

use anyhow::{Context, Result};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

use crate::service::{self, ConntrackGcReport, SERVICE_PROGRAM_GENERATION};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PressureAction {
    None,
    GcOnly,
    SoftWarn,
    HardReload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PressureReport {
    pub map_tier: String,
    pub program_generation: u32,
    pub soft_percent: u8,
    pub hard_percent: u8,
    pub pressure_percent: u8,
    pub action: PressureAction,
    pub gc: ConntrackGcReport,
    pub notes: Vec<String>,
}

/// Run GC and decide whether soft warn or hard reload is required.
pub fn reconcile(cfg: &Config) -> Result<PressureReport> {
    let svc = &cfg.sandbox.dataplane.service;
    let soft = svc.pressure_soft_percent.max(1);
    let hard = svc.pressure_hard_percent.max(soft);
    let gc = service::gc_conntrack(cfg)?;
    let mut notes = Vec::new();
    let mut action = PressureAction::GcOnly;

    if gc.pressure_percent >= hard {
        action = PressureAction::HardReload;
        notes.push(format!(
            "pressure {}% >= hard {}%; clearing generation markers and forcing sync_all reload",
            gc.pressure_percent, hard
        ));
        clear_generation_markers()?;
        warn!(
            pressure = gc.pressure_percent,
            hard,
            tier = %svc.map_tier,
            "service fabric pressure controller: hard reload armed"
        );
        let _ = service::sync_all(cfg).context("pressure hard reload sync_all")?;
        notes.push("sync_all completed after hard reload".into());
    } else if gc.pressure_percent >= soft {
        action = PressureAction::SoftWarn;
        notes.push(format!(
            "pressure {}% >= soft {}%; GC completed — consider map_tier upsize + ELF rebuild",
            gc.pressure_percent, soft
        ));
        info!(
            pressure = gc.pressure_percent,
            soft,
            tier = %svc.map_tier,
            "service fabric pressure controller: soft threshold"
        );
    } else if gc.maps_scanned == 0 {
        action = PressureAction::None;
        notes.push("no service maps pinned yet".into());
    } else {
        notes.push("pressure within budget".into());
    }

    Ok(PressureReport {
        map_tier: svc.map_tier.clone(),
        program_generation: SERVICE_PROGRAM_GENERATION,
        soft_percent: soft,
        hard_percent: hard,
        pressure_percent: gc.pressure_percent,
        action,
        gc,
        notes,
    })
}

fn clear_generation_markers() -> Result<()> {
    let root = PathBuf::from("/run/fluxvm/ebpf/service");
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".generation") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}
