// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! In-place snapshot restore for flux-vm VMs, and the VM-sandbox dry-run built
//! on it (snapshot, run, diff, restore).
//!
//! How a flux-vm snapshot restores (found by reading the code, then proved on
//! a real guest):
//!
//! * `SnapshotSave` (hypervisor control API) pauses the guest and writes
//!   `snap.mem`, `snap.vmstate`, a reflink/copy of the root disk
//!   (`snap.rootfs`) and `snap` (JSON metadata) under
//!   `<workspace>/snapshots/<tag>/`, then resumes.
//! * `SnapshotRestore` on a **running** hypervisor already restores in place:
//!   it shuts the guest down and boots it again from the snapshot inside the
//!   same hypervisor process (same pid and control socket).
//! * The metadata points the restored guest at `snap.rootfs`, not at the VM's
//!   own disk. Restoring it verbatim would revert file contents, but leave the
//!   VM record pointing at a stale `root.raw`, let the guest write into the
//!   snapshot itself (so the snapshot could not be restored twice), and make
//!   deleting the tag delete the disk in use. This module therefore swaps a
//!   fresh copy of `snap.rootfs` over the VM's own disk while the guest is
//!   paused and restores from a private copy of the metadata that names that
//!   disk. Snapshots stay immutable and reusable.

use crate::VmManager;
use crate::changes::{diff_manifests, validate_paths};
use crate::procbox_sandbox::DryRunReport;
use anyhow::{Context, Result, bail};
use fluxvm_core::model::{BackendKind, VmRecord, VmStatus};
use fluxvm_guest_protocol::AgentResponse;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

/// After a pause/resume or a restore the guest agent is briefly unreachable
/// (the vsock proxy refuses the connection); wait this long for it to return.
const AGENT_READY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
const RESTORE_META: &str = "snap.restore.json";

/// Typed failures so the API can answer with precise statuses.
#[derive(Debug)]
pub enum RestoreError {
    /// The tag has no snapshot for this VM.
    NoSnapshot(String),
    /// The VM is in the wrong state, or another restore/dry-run is running.
    Conflict(String),
    /// This backend or engine has no complete in-place snapshot/restore.
    Unsupported(String),
}

impl std::fmt::Display for RestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSnapshot(m) | Self::Conflict(m) | Self::Unsupported(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for RestoreError {}

static BUSY: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();

/// Held while a restore or dry-run runs on one VM; a second one is rejected.
struct BusyGuard(Uuid);

impl BusyGuard {
    fn acquire(id: Uuid) -> Result<Self, RestoreError> {
        let set = BUSY.get_or_init(|| Mutex::new(HashSet::new()));
        let mut set = set.lock().unwrap_or_else(|p| p.into_inner());
        if !set.insert(id) {
            return Err(RestoreError::Conflict(format!(
                "another restore or dry-run is already running on {id}"
            )));
        }
        Ok(Self(id))
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        if let Some(set) = BUSY.get() {
            set.lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.0);
        }
    }
}

/// Rewrite snapshot metadata so a restore boots from `disk` (the VM's own
/// root disk) instead of the snapshot's private clone. Returns the JSON text
/// and the snapshot's clone path.
pub(crate) fn retarget_metadata(raw: &[u8], disk: &std::path::Path) -> Result<(Vec<u8>, PathBuf)> {
    let mut spec: serde_json::Value =
        serde_json::from_slice(raw).context("snapshot metadata is not valid JSON")?;
    let clone = spec
        .get("disk_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .context("snapshot metadata has no disk_path")?;
    spec["disk_path"] = serde_json::json!(disk);
    let boot = spec
        .get_mut("boot")
        .and_then(|b| b.as_object_mut())
        .context("snapshot metadata has no boot section")?;
    boot.insert("rootfs".into(), serde_json::json!(disk));
    Ok((serde_json::to_vec_pretty(&spec)?, clone))
}

impl VmManager {
    /// Restore a VM from a snapshot tag. A running or paused flux-vm VM is
    /// restored in place (memory, CPU, devices and disk); a stopped VM of any
    /// backend takes the existing relaunch path; other running backends must
    /// be stopped first.
    pub async fn restore_vm_snapshot(self: &Arc<Self>, id: Uuid, tag: &str) -> Result<VmRecord> {
        crate::validate_snapshot_tag(tag)?;
        let vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::SnapshotRestore,
        )?;
        if crate::procbox_sandbox::is_procbox(&vm) {
            return Err(RestoreError::Unsupported(
                "a procbox sandbox has no VM state to restore".into(),
            )
            .into());
        }
        if let Some(e) = crate::snapshot_backend_error(vm.backend) {
            return Err(RestoreError::Unsupported(e).into());
        }
        let running = matches!(vm.status, VmStatus::Running | VmStatus::Paused);
        if !running {
            return self.start_from_snapshot(id, tag).await;
        }
        if vm.backend != BackendKind::FluxVm {
            return Err(RestoreError::Conflict(format!(
                "in-place restore is only implemented for the flux-vm backend; stop the {:?} VM \
                 first and restore it from the tag",
                vm.backend
            ))
            .into());
        }
        let _guard = BusyGuard::acquire(id)?;
        // The only file a crashed restore can leave is the disk copy it was
        // about to rename into place; `reconcile()` removes it.
        let op = crate::journal::OpGuard::begin(
            &self.cfg.state_dir,
            crate::journal::OpKind::Restore,
            Uuid::new_v4(),
            id,
            vec![crate::journal::Resource::TempFile {
                path: vm.disk.with_extension("restore.tmp"),
            }],
        )
        .context("journaling restore intent")?;
        let out = self.restore_fluxvm_in_place(id, tag).await;
        if out.is_ok() {
            op.finish();
        }
        if let Ok(vm) = &out {
            if vm.request.agent.as_ref().is_some_and(|a| a.enabled) {
                if let Err(e) = self.wait_for_agent(id).await {
                    tracing::warn!(%id, "guest agent did not return after restore: {e:#}");
                }
            }
        }
        if out.is_ok() {
            crate::audit_event(
                "vm.snapshot.restore",
                &[("vm_id", &id.to_string()), ("tag", tag)],
            );
        }
        out
    }

    /// First-command latency: wait for a trivial guest-agent exec to succeed
    /// and report timings measured from `started` (the API request start).
    /// `create_done_ms` is when the create/fork/claim returned; `agent_wait_ms`
    /// is the extra wait until the first `true` exec succeeded. Records a
    /// `vm.first_command` event. `source` is "create", "fork" or "claim".
    pub async fn measure_first_command(
        self: &Arc<Self>,
        id: Uuid,
        source: &str,
        started: std::time::Instant,
    ) -> Result<serde_json::Value> {
        let create_done_ms = started.elapsed().as_millis() as u64;
        let waited = self.wait_for_agent(id).await?;
        let first_command_ms = started.elapsed().as_millis() as u64;
        crate::events::record(
            "vm.first_command",
            &[
                ("vm_id", &id.to_string()),
                ("source", source),
                ("first_command_ms", &first_command_ms.to_string()),
                ("create_done_ms", &create_done_ms.to_string()),
            ],
        );
        Ok(serde_json::json!({
            "first_command_ms": first_command_ms,
            "phases": {
                "create_done_ms": create_done_ms,
                "agent_wait_ms": waited.as_millis() as u64,
                "first_exec_ms": first_command_ms,
            },
        }))
    }

    /// Wait until the guest agent answers again; returns how long that took.
    pub(crate) async fn wait_for_agent(self: &Arc<Self>, id: Uuid) -> Result<std::time::Duration> {
        let started = std::time::Instant::now();
        let mut last = String::from("no attempt");
        while started.elapsed() < AGENT_READY_DEADLINE {
            match self.exec(id, "true".into(), Some(5)).await {
                Ok(AgentResponse::Exec { exit_code: 0, .. }) => {
                    let took = started.elapsed();
                    tracing::info!(%id, ?took, "guest agent is answering");
                    return Ok(took);
                }
                Ok(other) => last = format!("{other:?}"),
                Err(e) => {
                    last = format!("{e:#}");
                    // Only "the agent is not up yet" is worth waiting out; a
                    // missing socket or a dead VMM will not fix itself.
                    let transient = last.contains("vsock proxy refused")
                        || last.contains("timed out")
                        || last.contains("timeout");
                    if !transient {
                        bail!("guest agent unreachable: {last}");
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        bail!("guest agent did not answer within {AGENT_READY_DEADLINE:?}: {last}")
    }

    /// Restore a running QEMU, Cloud Hypervisor or Firecracker VM from a
    /// snapshot tag by stopping the VMM process and relaunching it from the
    /// snapshot (reusing the same well-tested `stop`/`start_from_snapshot`
    /// paths a stopped-VM restore already takes). Unlike flux-vm's in-place
    /// restore this gets a new pid and, for network VMs, a fresh tap/netns —
    /// but the VM id, workspace and vsock socket path are unchanged, so the
    /// guest agent reconnects once boot completes. This is not literally
    /// "in-place", but it produces the same observable result restore/dry-run
    /// need: the guest's disk and memory state revert to the snapshot, and
    /// the VM ends up running again.
    ///
    /// QEMU and Cloud Hypervisor snapshots are self-contained (qcow2
    /// internal snapshot / CH's own state+memory files respectively) and
    /// don't need flux-vm's disk-swap step; `start_from_snapshot` already
    /// handles loading them for a stopped VM, which is exactly the state
    /// this function puts the VM into first. Unlike flux-vm's tag, these
    /// backends don't necessarily leave a `workspace/snapshots/<tag>`
    /// directory behind, so existence is left to `start_from_snapshot`
    /// (and, beneath it, each backend's own loader) to check.
    async fn restore_other_backend_by_relaunch(
        self: &Arc<Self>,
        id: Uuid,
        tag: &str,
    ) -> Result<VmRecord> {
        self.stop(id)
            .await
            .context("stopping the VM before restoring it from a snapshot")?;
        let vm = self
            .start_from_snapshot(id, tag)
            .await
            .context("relaunching the VM from the snapshot")?;
        if vm.status != VmStatus::Running {
            bail!(
                "VM did not come back up after the snapshot relaunch (status={:?})",
                vm.status
            );
        }
        Ok(vm)
    }

    async fn restore_fluxvm_in_place(self: &Arc<Self>, id: Uuid, tag: &str) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        let dest = vm.workspace.join("snapshots").join(tag);
        let meta = dest.join("snap");
        let raw = match tokio::fs::read(&meta).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RestoreError::NoSnapshot(format!(
                    "snapshot {tag:?} not found for VM {id}"
                ))
                .into());
            }
            Err(e) => return Err(e).context("reading snapshot metadata"),
        };
        let sock = vm
            .control_socket
            .clone()
            .context("flux-vm VM has no control socket")?;
        let (retargeted, clone) = retarget_metadata(&raw, &vm.disk)?;
        if !clone.exists() {
            bail!("snapshot disk {} is missing", clone.display());
        }

        // Quiesce the guest so nothing writes the disk while it is swapped.
        // "Already paused" is fine; a dead control socket is not.
        match fluxvm_hypervisor::control::request(&sock, &fluxvm_hypervisor::ApiRequest::Pause)
            .await
        {
            Ok(_) => {}
            Err(e) => bail!("pausing the guest before restore: {e:#}"),
        }

        // Fresh copy of the snapshot's disk, renamed over the VM's own disk.
        // The running guest keeps the old inode open until it is shut down by
        // the restore itself.
        let disk = vm.disk.clone();
        let tmp = disk.with_extension("restore.tmp");
        let src = clone.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            fluxvm_hypervisor::snapshot::clone_cow(&src, &tmp)
                .with_context(|| format!("copying snapshot disk {}", src.display()))?;
            std::fs::rename(&tmp, &disk)
                .with_context(|| format!("replacing {}", disk.display()))?;
            Ok(())
        })
        .await
        .context("disk restore worker panicked")??;

        let restore_meta = dest.join(RESTORE_META);
        tokio::fs::write(&restore_meta, &retargeted)
            .await
            .context("writing restore metadata")?;

        let req = fluxvm_hypervisor::ApiRequest::SnapshotRestore { path: restore_meta };
        let resp = fluxvm_hypervisor::control::request(&sock, &req).await;
        let failure = match resp {
            Ok(fluxvm_hypervisor::ApiResponse::Ok { .. }) => None,
            Ok(fluxvm_hypervisor::ApiResponse::Error { message }) => Some(message),
            Ok(other) => Some(format!("unexpected restore response: {other:?}")),
            Err(e) => Some(format!("{e:#}")),
        };
        if let Some(message) = failure {
            // The hypervisor shut the guest down before trying: the VM is not
            // in a state we can vouch for.
            vm.status = VmStatus::Failed;
            vm.error = Some(format!("snapshot restore failed: {message}"));
            self.store.update(vm).await?;
            bail!("snapshot restore failed and the VM is now in a failed state: {message}");
        }

        vm.status = VmStatus::Running;
        vm.error = None;
        self.store.update(vm.clone()).await?;
        Ok(vm)
    }

    /// Dry-run a command on a VM sandbox: snapshot, measure, run, measure,
    /// restore, delete the snapshot. The guest (memory, processes and disk) is
    /// put back exactly as it was before the command.
    pub(crate) async fn vm_sandbox_dry_run(
        self: &Arc<Self>,
        id: Uuid,
        command: String,
        timeout: Option<u64>,
        paths: Option<Vec<String>>,
    ) -> Result<DryRunReport> {
        self.vm_sandbox_dry_run_capture(id, command, timeout, paths, None)
            .await
    }

    /// [`Self::vm_sandbox_dry_run`] that can also copy out the changed files
    /// before the guest is restored (used by speculative execution).
    pub(crate) async fn vm_sandbox_dry_run_capture(
        self: &Arc<Self>,
        id: Uuid,
        command: String,
        timeout: Option<u64>,
        paths: Option<Vec<String>>,
        capture: Option<&mut crate::speculate::Captured>,
    ) -> Result<DryRunReport> {
        let vm = self.get(id).await?;
        if let Some(e) = crate::snapshot_backend_error(vm.backend) {
            return Err(RestoreError::Unsupported(e).into());
        }
        if vm.status != VmStatus::Running {
            return Err(RestoreError::Conflict(format!(
                "dry-run needs a running sandbox (status={:?})",
                vm.status
            ))
            .into());
        }
        let paths = match paths {
            Some(p) => validate_paths(&p)?,
            None => bail!(
                "paths is required for a VM sandbox dry-run: the guest root is too large to scan"
            ),
        };
        let _guard = BusyGuard::acquire(id)?;

        if !vm.request.agent.as_ref().is_some_and(|a| a.enabled) {
            return Err(RestoreError::Conflict(
                "dry-run needs the guest agent, and this sandbox was created without it".into(),
            )
            .into());
        }
        if let Err(e) = self.wait_for_agent(id).await {
            return Err(RestoreError::Conflict(format!("guest agent unreachable: {e:#}")).into());
        }

        let tag = format!("dryrun-{}", Uuid::new_v4());
        if let Err(e) = self.create_vm_snapshot(id, &tag).await {
            let _ = self.delete_vm_snapshot(id, &tag).await;
            return Err(e.context("creating the dry-run snapshot"));
        }

        let measured: Result<DryRunReport> = async {
            // Pausing for the snapshot briefly drops the agent connection.
            self.wait_for_agent(id).await?;
            let before = self.take_manifest(id, &paths).await?;
            let (exit_code, stdout, stderr) = match self.exec(id, command, timeout).await? {
                AgentResponse::Exec {
                    exit_code,
                    stdout,
                    stderr,
                    ..
                } => (exit_code, stdout, stderr),
                AgentResponse::Error { message } => bail!("guest agent error: {message}"),
                other => bail!("unexpected guest response: {other:?}"),
            };
            let after = self.take_manifest(id, &paths).await?;
            let changes = diff_manifests(&before, &after)?;
            if let Some(c) = capture {
                c.before = Some(before.clone());
                c.staged = Some(crate::speculate::stage_files(self, id, &changes).await?);
            }
            Ok(DryRunReport {
                changes,
                exit_code,
                stdout,
                stderr,
                discarded: true,
                reverted_via: "snapshot",
                paths: paths.clone(),
            })
        }
        .await;

        // Always try to put the guest back, whatever the command did.
        let restored = if vm.backend == BackendKind::FluxVm {
            self.restore_fluxvm_in_place(id, &tag).await
        } else {
            self.restore_other_backend_by_relaunch(id, &tag).await
        };
        if restored.is_ok() {
            if let Err(e) = self.wait_for_agent(id).await {
                tracing::warn!(%id, "guest agent did not return after the dry-run restore: {e:#}");
            }
        }
        let _ = self.delete_vm_snapshot(id, &tag).await;
        self.touch_activity(id).await;

        match (measured, restored) {
            (Ok(report), Ok(_)) => Ok(report),
            (Ok(_), Err(e)) => Err(e.context(
                "the dry-run ran but restoring the snapshot failed; the command's changes may \
                 still be in the VM (NOT discarded)",
            )),
            (Err(run), Ok(_)) => Err(run.context("the dry-run failed; the VM was restored")),
            (Err(run), Err(restore)) => Err(anyhow::anyhow!(
                "the dry-run failed ({run:#}) and restoring the snapshot also failed \
                 ({restore:#}); the VM may still contain the command's changes"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retarget_points_the_restore_at_the_vms_own_disk() {
        let raw = br#"{"memory_path":"/w/s/snap.mem","disk_path":"/w/s/snap.rootfs",
            "vmstate_path":"/w/s/snap.vmstate",
            "boot":{"kernel":"/k","rootfs":"/w/s/snap.rootfs","memory_mib":64,"vcpus":1}}"#;
        let (out, clone) = retarget_metadata(raw, std::path::Path::new("/w/root.raw")).unwrap();
        assert_eq!(clone, PathBuf::from("/w/s/snap.rootfs"));
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["disk_path"], "/w/root.raw");
        assert_eq!(v["boot"]["rootfs"], "/w/root.raw");
        assert_eq!(v["memory_path"], "/w/s/snap.mem");
        assert_eq!(v["boot"]["memory_mib"], 64);
    }

    #[test]
    fn retarget_rejects_metadata_without_a_disk_or_boot_section() {
        assert!(retarget_metadata(b"not json", std::path::Path::new("/d")).is_err());
        assert!(retarget_metadata(br#"{"boot":{}}"#, std::path::Path::new("/d")).is_err());
        assert!(retarget_metadata(br#"{"disk_path":"/x"}"#, std::path::Path::new("/d")).is_err());
    }

    #[test]
    fn a_second_restore_on_the_same_vm_is_rejected_until_the_first_ends() {
        let id = Uuid::new_v4();
        let first = BusyGuard::acquire(id).unwrap();
        let err = BusyGuard::acquire(id).err().unwrap();
        assert!(matches!(err, RestoreError::Conflict(_)));
        assert!(
            BusyGuard::acquire(Uuid::new_v4()).is_ok(),
            "other VMs are independent"
        );
        drop(first);
        assert!(BusyGuard::acquire(id).is_ok(), "released on drop");
    }
}
