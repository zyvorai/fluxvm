// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Running many idle agent sandboxes on one Mac.
//!
//! * Every `vz` sandbox carries [`SANDBOX_LABEL`], so the AutoPause scan (pause, balloon, hibernate) touches sandboxes only and
//!   never an ordinary `vz` VM.
//! * Hibernate: a `vz` sandbox idle for `sandbox.hibernate_idle_secs` has its memory saved to disk and is stopped, so it holds no
//!   RAM at all. The next request to it ([`VmManager::ensure_running_for_request`]) restores the saved state.
//! * `POST /v1/sandboxes/warm` fills the warm pool to a count; `GET /v1/sandboxes/density` reports what the host is carrying.

use crate::VmManager;
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use fluxvm_core::agent_density::{DensityReport, MAX_WARM_SLOTS, warm_hits, warm_misses};
use fluxvm_core::model::{BackendKind, VmPatch, VmRecord, VmStatus};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

pub const SANDBOX_LABEL: &str = "fluxvm.sandbox";
pub const HIBERNATED_LABEL: &str = "fluxvm.hibernated";
const HIBERNATE_TAG: &str = "hibernate";

pub fn is_vz_sandbox(vm: &VmRecord) -> bool {
    vm.backend == BackendKind::Vz && vm.labels.contains_key(SANDBOX_LABEL)
}

pub fn is_hibernated(vm: &VmRecord) -> bool {
    vm.status == VmStatus::Stopped && vm.labels.contains_key(HIBERNATED_LABEL)
}

/// What AutoPause may pause: KVM-engine sandboxes (every FluxVm VM is one) and labelled `vz` sandboxes.
pub(crate) fn autopause_eligible(vm: &VmRecord) -> bool {
    (vm.backend == BackendKind::FluxVm && !crate::procbox_sandbox::is_procbox(vm))
        || is_vz_sandbox(vm)
}

/// Pure count over the VM list, so the report is testable without a daemon.
pub(crate) fn summarize(vms: &[VmRecord], warm_slots_configured: usize) -> DensityReport {
    let mut r = DensityReport {
        warm_slots_configured,
        warm_hits: warm_hits(),
        warm_misses: warm_misses(),
        ..DensityReport::default()
    };
    for vm in vms {
        if crate::sandbox_pool::is_slot(vm) {
            if vm.status == VmStatus::Stopped {
                r.warm_slots_ready += 1;
            }
            continue;
        }
        if !autopause_eligible(vm) {
            continue;
        }
        match vm.status {
            VmStatus::Running => {
                r.active_sandboxes += 1;
                r.resident_estimate_mib += vm.request.memory_mib;
            }
            VmStatus::Paused => {
                r.paused_sandboxes += 1;
                r.resident_estimate_mib += vm.request.memory_mib;
            }
            _ if is_hibernated(vm) => r.hibernated_sandboxes += 1,
            _ => {}
        }
    }
    r
}

impl VmManager {
    /// Marks a freshly created or claimed `vz` VM as a sandbox.
    pub(crate) async fn label_vz_sandbox(&self, id: Uuid) -> Result<VmRecord> {
        let labels = BTreeMap::from([(SANDBOX_LABEL.to_owned(), Some("1".to_owned()))]);
        self.patch(id, VmPatch { name: None, labels }).await
    }

    /// Saves the sandbox's memory and stops it.
    pub(crate) async fn hibernate_sandbox(self: &Arc<Self>, id: Uuid) -> Result<()> {
        if self
            .list_vm_snapshots(id)
            .await?
            .iter()
            .any(|s| s.tag == HIBERNATE_TAG)
        {
            self.delete_vm_snapshot(id, HIBERNATE_TAG).await?;
        }
        self.create_vm_snapshot(id, HIBERNATE_TAG)
            .await
            .context("saving the sandbox's memory")?;
        let labels = BTreeMap::from([(HIBERNATED_LABEL.to_owned(), Some("1".to_owned()))]);
        self.patch(id, VmPatch { name: None, labels }).await?;
        self.stop(id)
            .await
            .context("stopping the hibernated sandbox")?;
        Ok(())
    }

    /// Restores a hibernated sandbox; falls back to a cold boot when the saved state will not restore (a locked screen, an
    /// updated macOS).
    pub(crate) async fn wake_sandbox(self: &Arc<Self>, id: Uuid) -> Result<VmRecord> {
        let vm = match self.start_from_snapshot(id, HIBERNATE_TAG).await {
            Ok(vm) => vm,
            Err(e) => {
                tracing::warn!(vm = %id, error = %format!("{e:#}"), "restoring a hibernated sandbox failed; cold-booting it");
                self.start(id).await.context("waking the sandbox")?
            }
        };
        let _ = self.delete_vm_snapshot(id, HIBERNATE_TAG).await;
        let labels = BTreeMap::from([(HIBERNATED_LABEL.to_owned(), None)]);
        self.patch(id, VmPatch { name: None, labels }).await?;
        Ok(vm)
    }

    /// One hibernate pass of the AutoPause scan.
    pub(crate) async fn hibernate_tick(self: &Arc<Self>) -> usize {
        let secs = self.cfg.sandbox.hibernate_idle_secs;
        if secs == 0 {
            return 0;
        }
        let cutoff = Utc::now() - Duration::seconds(secs as i64);
        let mut n = 0;
        for vm in self.list().await {
            if !is_vz_sandbox(&vm)
                || !matches!(vm.status, VmStatus::Running | VmStatus::Paused)
                || crate::oci_pool::runs_claimed(&vm)
            {
                continue;
            }
            let last = self.last_activity(vm.id).await.unwrap_or(vm.created_at);
            if last >= cutoff {
                continue;
            }
            match self.hibernate_sandbox(vm.id).await {
                Ok(()) => {
                    n += 1;
                    tracing::info!(vm = %vm.id, "hibernated idle sandbox");
                }
                Err(e) => {
                    tracing::warn!(vm = %vm.id, error = %format!("{e:#}"), "hibernating an idle sandbox failed")
                }
            }
        }
        n
    }

    /// Fills the warm pool to `count` slots in the background. Returns the target.
    pub async fn warm_sandboxes(self: &Arc<Self>, count: usize) -> Result<usize> {
        if !cfg!(target_os = "macos") {
            bail!("the warm sandbox pool needs the vz backend (macOS)");
        }
        if count == 0 || count > MAX_WARM_SLOTS {
            bail!("count must be 1-{MAX_WARM_SLOTS}");
        }
        let want = count.max(self.cfg.sandbox.warm_slots);
        self.spawn_pool_fill_to(want);
        Ok(want)
    }

    pub async fn sandbox_density(&self) -> DensityReport {
        let vms = self.list().await;
        let mut r = summarize(&vms, self.cfg.sandbox.warm_slots);
        crate::oci_pool::summarize(&vms, self.oci_warm_configured(), &mut r);
        let host = fluxvm_core::pressure_admission::sample_host();
        r.host_mem_available_mib = host.mem_available_mib;
        r.host_mem_total_mib = host.mem_total_mib;
        r.host_pressure_level = host.level;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_pool::{POOL_LABEL, POOL_VALUE};

    fn vm(backend: BackendKind, status: VmStatus, labels: &[(&str, &str)], mib: u64) -> VmRecord {
        let b = serde_json::to_value(backend).unwrap();
        let mut rec: VmRecord = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(), "name": "x", "backend": b, "status": status, "pid": null,
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null, "workspace": "/tmp/w",
            "disk": "/tmp/w/disk.raw", "seed_disk": null, "tap_name": null, "control_socket": null,
            "log_path": "/tmp/w/console.log", "error": null,
            "request": {"name": "x", "image": "/img", "vcpus": 1, "memory_mib": mib, "backend": b},
        }))
        .unwrap();
        rec.labels = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        rec
    }

    #[test]
    fn shipped_tiny_example_parses() {
        let req: crate::SandboxCreateRequest =
            serde_json::from_str(include_str!("../../../examples/sandbox-tiny.json")).unwrap();
        assert_eq!(
            req.profile,
            Some(fluxvm_core::agent_density::AgentProfile::Tiny)
        );
    }

    #[test]
    fn shipped_agent_micro_example_parses() {
        let req: crate::SandboxCreateRequest =
            serde_json::from_str(include_str!("../../../examples/sandbox-agent-micro.json"))
                .unwrap();
        assert_eq!(req.image.as_deref(), Some("agent-micro"));
        assert!(req.offline && req.spec.is_none());
    }

    #[test]
    fn only_sandboxes_are_eligible() {
        assert!(autopause_eligible(&vm(
            BackendKind::FluxVm,
            VmStatus::Running,
            &[],
            512
        )));
        assert!(autopause_eligible(&vm(
            BackendKind::Vz,
            VmStatus::Running,
            &[(SANDBOX_LABEL, "1")],
            512
        )));
        assert!(!autopause_eligible(&vm(
            BackendKind::Vz,
            VmStatus::Running,
            &[],
            512
        )));
        assert!(!autopause_eligible(&vm(
            BackendKind::Qemu,
            VmStatus::Running,
            &[],
            512
        )));
    }

    #[test]
    fn density_report_counts_by_state() {
        let sb = [(SANDBOX_LABEL, "1")];
        let vms = vec![
            vm(BackendKind::Vz, VmStatus::Running, &sb, 512),
            vm(BackendKind::Vz, VmStatus::Paused, &sb, 1024),
            vm(
                BackendKind::Vz,
                VmStatus::Stopped,
                &[(SANDBOX_LABEL, "1"), (HIBERNATED_LABEL, "1")],
                2048,
            ),
            vm(
                BackendKind::Vz,
                VmStatus::Stopped,
                &[(POOL_LABEL, POOL_VALUE)],
                2048,
            ),
            vm(
                BackendKind::Vz,
                VmStatus::Running,
                &[(POOL_LABEL, POOL_VALUE)],
                2048,
            ),
            vm(BackendKind::Vz, VmStatus::Running, &[], 8192),
        ];
        let r = summarize(&vms, 2);
        assert_eq!(r.warm_slots_configured, 2);
        assert_eq!(r.warm_slots_ready, 1);
        assert_eq!(r.active_sandboxes, 1);
        assert_eq!(r.paused_sandboxes, 1);
        assert_eq!(r.hibernated_sandboxes, 1);
        assert_eq!(r.resident_estimate_mib, 1536);
    }
}
