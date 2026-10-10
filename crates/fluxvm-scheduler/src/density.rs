// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Memory density: balloon control, pressure-aware admission, idle reclaim and
//! per-VM PSS reporting.
//!
//! * Balloon: the in-tree KVM engine's virtio-balloon is driven over the
//!   hypervisor control socket (`ApiRequest::Balloon`).
//! * Admission: [`VmManager::admit_under_pressure`] applies the optional
//!   `[policy]` memory-pressure thresholds on the create path.
//! * Idle reclaim: [`VmManager::idle_reclaim_tick`] inflates the balloon of
//!   idle sandboxes and deflates it again once they are active.
//! * PSS: `/proc/<pid>/smaps_rollup` of the VMM process, split into private
//!   and shared memory.

use crate::{VmManager, audit_event};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use fluxvm_core::model::{BackendKind, VmRecord, VmStatus};
use fluxvm_core::pressure_admission::{check_pressure, is_enabled, sample_host};
use fluxvm_hypervisor::balloon_ctl::{BalloonStatus, MIN_GUEST_MIB};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

/// Memory accounting for one VMM process, from `smaps_rollup`. Sizes in KiB.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MemUsage {
    pub rss_kib: u64,
    /// Proportional set size: private plus this process's share of shared pages.
    pub pss_kib: u64,
    pub private_kib: u64,
    pub shared_kib: u64,
    pub swap_kib: u64,
}

/// Parse the text of `/proc/<pid>/smaps_rollup`.
pub fn parse_smaps_rollup(text: &str) -> Result<MemUsage> {
    let mut m = MemUsage::default();
    let mut seen_pss = false;
    let mut private_clean = 0u64;
    let mut private_dirty = 0u64;
    let mut shared_clean = 0u64;
    let mut shared_dirty = 0u64;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(kib) = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "Rss" => m.rss_kib = kib,
            "Pss" => {
                m.pss_kib = kib;
                seen_pss = true;
            }
            "Private_Clean" => private_clean = kib,
            "Private_Dirty" => private_dirty = kib,
            "Shared_Clean" => shared_clean = kib,
            "Shared_Dirty" => shared_dirty = kib,
            "Swap" => m.swap_kib = kib,
            _ => {}
        }
    }
    if !seen_pss {
        bail!("smaps_rollup has no Pss line");
    }
    m.private_kib = private_clean + private_dirty;
    m.shared_kib = shared_clean + shared_dirty;
    Ok(m)
}

/// Balloon size an idle sandbox is inflated to: `percent` of its memory,
/// never leaving the guest under the balloon floor. 0 when disabled.
pub fn idle_balloon_target_mib(memory_mib: u64, percent: u8) -> u64 {
    let pct = u64::from(percent.min(90));
    (memory_mib * pct / 100).min(memory_mib.saturating_sub(MIN_GUEST_MIB))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimAction {
    Inflate,
    Deflate,
    Nothing,
}

/// What the idle scanner does for a VM given whether it is idle and whether
/// the scanner inflated it earlier.
pub fn reclaim_action(idle: bool, inflated: bool) -> ReclaimAction {
    match (idle, inflated) {
        (true, false) => ReclaimAction::Inflate,
        (false, true) => ReclaimAction::Deflate,
        _ => ReclaimAction::Nothing,
    }
}

/// VMs whose balloon the idle scanner inflated (so it only deflates its own).
fn inflated_set() -> &'static Mutex<HashSet<Uuid>> {
    static SET: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Memory report for one VM.
#[derive(Debug, Serialize)]
pub struct VmMemoryReport {
    pub vm_id: Uuid,
    pub configured_mib: u64,
    /// `None` when the VM has no VMM process or `smaps_rollup` is unreadable.
    pub usage: Option<MemUsage>,
    /// `None` when the VM has no balloon (not the KVM engine).
    pub balloon: Option<BalloonStatus>,
}

impl VmManager {
    /// Set (`Some`) or read (`None`) the balloon of a KVM-engine VM. `Some(0)`
    /// deflates it fully.
    pub async fn balloon_control(
        &self,
        id: Uuid,
        balloon_mib: Option<u64>,
    ) -> Result<BalloonStatus> {
        let vm = self.get(id).await?;
        let status = balloon_request(&vm, balloon_mib).await?;
        if balloon_mib.is_some() {
            audit_event(
                "vm.balloon",
                &[
                    ("vm_id", &id.to_string()),
                    ("target_mib", &status.target_mib.to_string()),
                ],
            );
        }
        Ok(status)
    }

    /// PSS, private and shared memory of the VM's VMM process, plus its
    /// balloon state when it has one.
    pub async fn vm_memory_report(&self, id: Uuid) -> Result<VmMemoryReport> {
        let vm = self.get(id).await?;
        let usage = match vm.pid {
            Some(pid) => {
                let path = format!("/proc/{pid}/smaps_rollup");
                match tokio::fs::read_to_string(&path).await {
                    Ok(text) => Some(parse_smaps_rollup(&text)?),
                    Err(_) => None,
                }
            }
            None => None,
        };
        let balloon = if matches!(vm.backend, BackendKind::FluxVm | BackendKind::Vz)
            && vm.status == VmStatus::Running
        {
            balloon_request(&vm, None).await.ok()
        } else {
            None
        };
        Ok(VmMemoryReport {
            vm_id: id,
            configured_mib: vm.request.memory_mib,
            usage,
            balloon,
        })
    }

    /// Create-path gate on actual host pressure (see
    /// `fluxvm_core::pressure_admission`). Does nothing unless a threshold is
    /// configured. With `policy.pressure_defer_secs` set, waits for pressure to
    /// clear before refusing. Audits refusals as `quota.deny`.
    pub async fn admit_under_pressure(&self, requested_mib: u64) -> Result<()> {
        let policy = &self.cfg.policy;
        if !is_enabled(policy) {
            return Ok(());
        }
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(policy.pressure_defer_secs);
        loop {
            let host = sample_host();
            match check_pressure(requested_mib, policy, &host) {
                Ok(()) => return Ok(()),
                Err(deny) => {
                    if std::time::Instant::now() >= deadline {
                        let reason = deny.to_string();
                        audit_event("quota.deny", &[("scope", "pressure"), ("reason", &reason)]);
                        return Err(deny.into());
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Idle reclaim: inflate the balloon of KVM-engine sandboxes idle longer
    /// than `sandbox.idle_balloon_secs`, deflate it again once they are active.
    /// Returns how many VMs changed. Off when `idle_balloon_secs` is 0.
    pub async fn idle_reclaim_tick(&self) -> Result<usize> {
        let secs = self.cfg.sandbox.idle_balloon_secs;
        if secs == 0 {
            return Ok(0);
        }
        let cutoff = Utc::now() - Duration::seconds(secs as i64);
        let mut changed = 0;
        for vm in self.list().await {
            if !crate::sandbox_density::autopause_eligible(&vm) || vm.status != VmStatus::Running {
                continue;
            }
            let last = self.last_activity(vm.id).await.unwrap_or(vm.created_at);
            let inflated = inflated_set()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&vm.id);
            let target = match reclaim_action(last < cutoff, inflated) {
                ReclaimAction::Inflate => idle_balloon_target_mib(
                    vm.request.memory_mib,
                    self.cfg.sandbox.idle_balloon_percent,
                ),
                ReclaimAction::Deflate => 0,
                ReclaimAction::Nothing => continue,
            };
            if target == 0 && !inflated {
                continue;
            }
            match self.balloon_control(vm.id, Some(target)).await {
                Ok(_) => {
                    let mut set = inflated_set().lock().unwrap_or_else(|e| e.into_inner());
                    if target == 0 {
                        set.remove(&vm.id);
                    } else {
                        set.insert(vm.id);
                    }
                    changed += 1;
                    tracing::info!(vm = %vm.id, target_mib = target, "idle reclaim moved balloon");
                }
                Err(e) => {
                    // Not the KVM engine, or the VMM is busy: do not retry
                    // every scan for a VM that cannot be ballooned.
                    tracing::debug!(vm = %vm.id, error = %e, "idle reclaim skipped");
                }
            }
        }
        Ok(changed)
    }
}

async fn balloon_request(vm: &VmRecord, balloon_mib: Option<u64>) -> Result<BalloonStatus> {
    if vm.status != VmStatus::Running {
        bail!(
            "balloon control needs a running VM (status={:?})",
            vm.status
        );
    }
    if vm.backend == BackendKind::Vz {
        let s = fluxvm_apple::balloon_control(vm, balloon_mib).await?;
        return Ok(BalloonStatus {
            memory_mib: s.memory_mib,
            target_mib: s.target_mib,
            actual_mib: s.actual_mib,
        });
    }
    if vm.backend != BackendKind::FluxVm {
        bail!(
            "balloon control is unsupported for backend={:?}",
            vm.backend
        );
    }
    let sock = vm
        .control_socket
        .as_ref()
        .context("VM has no control socket")?;
    let req = fluxvm_hypervisor::ApiRequest::Balloon { balloon_mib };
    match fluxvm_hypervisor::control::request(sock, &req).await? {
        fluxvm_hypervisor::ApiResponse::Ok { message } => {
            serde_json::from_str(&message).context("unexpected balloon response")
        }
        fluxvm_hypervisor::ApiResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected balloon response: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMAPS: &str = "\
00400000-7ffd1234 ---p 00000000 00:00 0                                  [rollup]
Rss:              204800 kB
Pss:              102400 kB
Pss_Dirty:         90000 kB
Shared_Clean:      20000 kB
Shared_Dirty:      30000 kB
Private_Clean:     10000 kB
Private_Dirty:    144800 kB
Referenced:       204800 kB
Swap:               512 kB
";

    #[test]
    fn parses_smaps_rollup() {
        let m = parse_smaps_rollup(SMAPS).unwrap();
        assert_eq!(m.rss_kib, 204800);
        assert_eq!(m.pss_kib, 102400);
        assert_eq!(m.private_kib, 154800);
        assert_eq!(m.shared_kib, 50000);
        assert_eq!(m.swap_kib, 512);
    }

    #[test]
    fn rejects_text_without_pss() {
        assert!(parse_smaps_rollup("").is_err());
        assert!(parse_smaps_rollup("Rss: 4 kB\n").is_err());
    }

    #[test]
    fn idle_target_is_a_percentage_with_a_floor() {
        assert_eq!(idle_balloon_target_mib(1024, 50), 512);
        assert_eq!(idle_balloon_target_mib(1024, 0), 0);
        // Clamped to 90 percent, then to memory minus the guest floor.
        assert_eq!(idle_balloon_target_mib(1024, 200), 921);
        assert_eq!(idle_balloon_target_mib(100, 90), 36);
        assert_eq!(idle_balloon_target_mib(32, 50), 0);
    }

    #[test]
    fn reclaim_inflates_idle_and_deflates_only_its_own() {
        assert_eq!(reclaim_action(true, false), ReclaimAction::Inflate);
        assert_eq!(reclaim_action(true, true), ReclaimAction::Nothing);
        assert_eq!(reclaim_action(false, true), ReclaimAction::Deflate);
        assert_eq!(reclaim_action(false, false), ReclaimAction::Nothing);
    }
}
