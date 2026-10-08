// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Live fork of a running flux-vm VM into N new VMs.
//!
//! One `SnapshotSave` of the parent (a pause of a few milliseconds plus a
//! reflink of its rootfs), then every child is restored from it:
//!
//! * `snap.mem` and `snap.vmstate` are shared read-only. The in-tree KVM
//!   engine maps `snap.mem` `MAP_PRIVATE` (clean pages shared between
//!   children, written pages copied on write) and falls back to an eager copy;
//!   either way the files can be unlinked once every child runs.
//! * each child gets its own reflink of `snap.rootfs` as its `root.raw`, its
//!   own workspace, vsock socket and CID, and its own tap from
//!   `fluxvm_network::prepare`.
//!
//! Only the KVM engine is forkable: a Firecracker vmstate names the parent's
//! drive and tap by absolute host path, so a restored child would open the
//! parent's disk. The guest keeps the parent's MAC and IP, which is why fork
//! requires per-VM network namespaces (or no tap at all): two VMs with one
//! MAC never share an L2 segment. After resume, `fork_child` calls the guest
//! agent's `ResetIdentity` so each child gets its own hostname, machine-id and
//! fresh entropy (best effort: a failure is logged loudly and audited).

use crate::{FIRST_GUEST_CID, VmManager, audit_event, validate_vm_name};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use fluxvm_core::model::{BackendKind, NetworkSpec, StorageBackend, VmRecord, VmStatus};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

/// Upper bound on children per call.
pub const MAX_FORK_COUNT: u32 = 32;

/// Label every child carries, naming the VM it was forked from.
pub const FORKED_FROM_LABEL: &str = "fluxvm.dev/forked-from";

impl VmManager {
    /// Fork running VM `id` into `count` new running VMs named
    /// `{name_prefix}-{n}`, n from 1 (prefix defaults to `{parent}-fork`).
    /// All-or-nothing: if any child fails, every child created by this call
    /// is deleted. The parent keeps running throughout.
    pub async fn fork_vm(
        self: &Arc<Self>,
        id: Uuid,
        count: u32,
        name_prefix: Option<String>,
        actor: Option<&str>,
    ) -> Result<Vec<VmRecord>> {
        let src = self.get(id).await?;
        check_forkable(&src, count)?;
        let prefix = name_prefix.unwrap_or_else(|| format!("{}-fork", src.name));
        let names: Vec<String> = (1..=count).map(|n| format!("{prefix}-{n}")).collect();
        for name in &names {
            validate_vm_name(name)?;
        }

        let tag = format!("fork-{}", &Uuid::new_v4().simple().to_string()[..12]);
        self.create_vm_snapshot(id, &tag).await?;
        let meta = src.workspace.join("snapshots").join(&tag).join("snap");
        let result = self.fork_children(&src, &meta, &tag, &names, actor).await;
        if let Err(e) = self.delete_vm_snapshot(id, &tag).await {
            tracing::warn!(vm = %id, tag, error = %e, "removing fork snapshot failed");
        }
        let children = result?;
        let ids: Vec<String> = children.iter().map(|c| c.id.to_string()).collect();
        audit_event(
            "vm.fork",
            &[
                ("vm_id", &id.to_string()),
                ("count", &count.to_string()),
                ("children", &ids.join(",")),
            ],
        );
        Ok(children)
    }

    async fn fork_children(
        self: &Arc<Self>,
        src: &VmRecord,
        meta: &Path,
        tag: &str,
        names: &[String],
        actor: Option<&str>,
    ) -> Result<Vec<VmRecord>> {
        let spec = fluxvm_hypervisor::snapshot::load_spec(meta)?;
        if spec.boot.engine != fluxvm_hypervisor::api::FluxVmEngine::Kvm {
            bail!(
                "fork needs the in-tree KVM engine ([fluxvm] engine = \"kvm\"): a Firecracker \
                 snapshot names the parent's disk and tap by path, so a child would share them"
            );
        }
        let mut children = Vec::with_capacity(names.len());
        for name in names {
            match self.fork_child(src, &spec, tag, name, actor).await {
                Ok(child) => children.push(child),
                Err(e) => {
                    for child in &children {
                        let _ = self.delete(child.id).await;
                    }
                    return Err(e.context(format!("forking child {name}")));
                }
            }
        }
        Ok(children)
    }

    async fn fork_child(
        self: &Arc<Self>,
        src: &VmRecord,
        spec: &fluxvm_hypervisor::api::SnapshotSpec,
        tag: &str,
        name: &str,
        actor: Option<&str>,
    ) -> Result<VmRecord> {
        let ledger = self.store.quota_ledger().await?;
        if let Some(tenant) = src.request.tenant.as_deref()
            && !self.cfg.policy.tenants.is_empty()
        {
            fluxvm_core::policy::enforce_tenant_totals(
                tenant,
                src.request.vcpus,
                src.request.memory_mib,
                &self.cfg.policy,
                &ledger,
            )?;
        }
        fluxvm_core::policy::enforce_host_totals(
            src.request.vcpus,
            src.request.memory_mib,
            &self.cfg.policy,
            &fluxvm_core::policy::ledger_for_host_admission(&ledger),
        )?;

        let id = Uuid::new_v4();
        let workspace = self.cfg.state_dir.join("instances").join(id.to_string());
        std::fs::create_dir_all(&workspace)?;
        let disk = workspace.join("root.raw");
        let mut req = src.request.clone();
        req.name = name.to_string();
        req.loadvm_tag = None;
        if let Some(actor) = actor {
            req.created_by_token = Some(actor.to_string());
        }
        if let NetworkSpec::Tap { mac, tap_name, .. } = &mut req.network {
            *mac = None;
            *tap_name = None;
        }
        let mut labels = src.labels.clone();
        labels.insert(FORKED_FROM_LABEL.to_string(), src.id.to_string());
        let placeholder = VmRecord {
            id,
            name: req.name.clone(),
            backend: BackendKind::FluxVm,
            status: VmStatus::Stopped,
            pid: None,
            created_at: Utc::now(),
            expires_at: req
                .ttl_seconds
                .map(|s| Utc::now() + Duration::seconds(s as i64)),
            workspace: workspace.clone(),
            disk: disk.clone(),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: workspace.join("console.log"),
            error: None,
            request: req,
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: Vec::new(),
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
            requested_security_profile: src.requested_security_profile,
            achieved_security_profile: src.achieved_security_profile,
            security_evidence: None,
            labels,
        };
        let needs_cid = src.guest_cid.is_some();
        let mut record = self
            .store
            .insert_with_cid(placeholder, needs_cid, FIRST_GUEST_CID)
            .await?;

        let prepared: Result<()> = async {
            fluxvm_hypervisor::snapshot::clone_cow(&spec.disk_path, &disk)
                .with_context(|| format!("cloning snapshot rootfs to {}", disk.display()))?;
            let vsock = record.guest_cid.map(|_| workspace.join("vsock.sock"));
            record.vsock_socket = vsock.clone();
            let network = fluxvm_network::prepare(&self.cfg, id, &record.request.network).await?;
            let mut boot = spec.boot.clone();
            boot.rootfs = disk.clone();
            boot.seed = None;
            boot.tap = network.tap_name.clone();
            boot.vsock_cid = record.guest_cid;
            boot.vsock_uds = vsock;
            let child_spec = fluxvm_hypervisor::api::SnapshotSpec {
                memory_path: spec.memory_path.clone(),
                disk_path: disk.clone(),
                vmstate_path: spec.vmstate_path.clone(),
                boot,
            };
            let dir = workspace.join("snapshots").join(tag);
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("snap"), serde_json::to_vec_pretty(&child_spec)?)?;
            self.store.update(record.clone()).await?;
            Ok(())
        }
        .await;
        if let Err(e) = prepared {
            let _ = self.delete(id).await;
            return Err(e);
        }

        let started = self.start_from_snapshot(id, tag).await;
        let _ = std::fs::remove_dir_all(workspace.join("snapshots").join(tag));
        match started {
            Ok(vm) => {
                reset_child_identity(&vm, name).await;
                Ok(vm)
            }
            Err(e) => {
                let _ = self.delete(id).await;
                Err(e)
            }
        }
    }
}

/// How long to keep retrying the identity reset while the resumed guest's
/// agent starts answering again.
const IDENTITY_RESET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Give a resumed child its own hostname, machine-id and RNG state through
/// the guest agent. A fork resumes the parent's memory, so without this every
/// child shares the parent's identity and entropy pool. Failure is not fatal
/// (the child still runs) but is logged at error level and audited, because a
/// child with a duplicate identity or RNG state is a correctness problem.
async fn reset_child_identity(vm: &VmRecord, hostname: &str) {
    use base64::Engine;
    use fluxvm_guest_protocol::{AgentRequest, AgentResponse};

    if !vm.request.agent.as_ref().is_some_and(|a| a.enabled) {
        tracing::warn!(vm = %vm.id, "fork child has no guest agent; identity not reset");
        return;
    }
    // 32 bytes of host entropy; two v4 UUIDs avoid a direct rand dependency.
    let mut entropy = Vec::with_capacity(32);
    entropy.extend_from_slice(Uuid::new_v4().as_bytes());
    entropy.extend_from_slice(Uuid::new_v4().as_bytes());
    let request = AgentRequest::ResetIdentity {
        hostname: Some(hostname.to_string()),
        regenerate_machine_id: true,
        reseed_entropy: true,
        entropy_base64: Some(base64::engine::general_purpose::STANDARD.encode(&entropy)),
    };
    let deadline = tokio::time::Instant::now() + IDENTITY_RESET_TIMEOUT;
    let outcome: Result<String> = loop {
        let attempt =
            fluxvm_vsock_client::call(vm, request.clone(), std::time::Duration::from_secs(5)).await;
        match attempt {
            Ok(AgentResponse::IdentityReset { applied, failures }) if failures.is_empty() => {
                break Ok(format!("applied: {}", applied.join(",")));
            }
            Ok(AgentResponse::IdentityReset { applied, failures }) => {
                break Err(anyhow::anyhow!(
                    "partial reset (applied: {}); failed: {}",
                    applied.join(","),
                    failures.join("; ")
                ));
            }
            Ok(AgentResponse::Error { message }) => {
                break Err(anyhow::anyhow!("guest agent error: {message}"));
            }
            Ok(other) => break Err(anyhow::anyhow!("unexpected response: {other:?}")),
            Err(e) if tokio::time::Instant::now() >= deadline => break Err(e),
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    };
    match outcome {
        Ok(detail) => {
            audit_event(
                "vm.fork.identity-reset",
                &[("vm_id", &vm.id.to_string()), ("detail", &detail)],
            );
        }
        Err(e) => {
            tracing::error!(
                vm = %vm.id,
                error = %format!("{e:#}"),
                "fork child identity reset FAILED: child shares the parent's hostname, \
                 machine-id and/or RNG state"
            );
            audit_event(
                "vm.fork.identity-reset-failed",
                &[("vm_id", &vm.id.to_string()), ("error", &format!("{e:#}"))],
            );
        }
    }
}

fn check_forkable(src: &VmRecord, count: u32) -> Result<()> {
    if count == 0 || count > MAX_FORK_COUNT {
        bail!("count must be between 1 and {MAX_FORK_COUNT}");
    }
    if src.backend != BackendKind::FluxVm {
        bail!(
            "fork supports the flux-vm backend only (backend={:?})",
            src.backend
        );
    }
    if src.status != VmStatus::Running && src.status != VmStatus::Paused {
        bail!(
            "fork needs a running or paused VM (status={:?})",
            src.status
        );
    }
    if src.request.storage != StorageBackend::Default {
        bail!("fork supports local file-backed disks only");
    }
    match &src.request.network {
        NetworkSpec::None | NetworkSpec::User { .. } => {}
        NetworkSpec::Tap {
            netns: true,
            direct: None,
            extra,
            ..
        } if extra.is_empty() => {}
        _ => bail!(
            "fork needs network mode none, user, or tap with netns: true and no extra NICs; \
             children keep the parent's MAC and IP, so they must not share an L2 segment"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(network: serde_json::Value, backend: &str, status: &str) -> VmRecord {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::nil(),
            "name": "parent",
            "backend": backend,
            "status": status,
            "pid": null,
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": null,
            "workspace": "/tmp/w",
            "disk": "/tmp/w/root.raw",
            "seed_disk": null,
            "tap_name": null,
            "control_socket": null,
            "log_path": "/tmp/w/console.log",
            "error": null,
            "request": {
                "name": "parent",
                "image": "/img",
                "vcpus": 1,
                "memory_mib": 256,
                "backend": backend,
                "network": network
            }
        }))
        .unwrap()
    }

    #[test]
    fn rejects_shared_l2_and_bad_counts() {
        let netns = serde_json::json!({"mode": "tap", "netns": true});
        let bridged = serde_json::json!({"mode": "tap", "bridge": "br0"});
        let ok = record(netns.clone(), "flux-vm", "running");
        assert!(format!("{:#}", check_forkable(&ok, 0).unwrap_err()).contains("count"));
        assert!(
            format!("{:#}", check_forkable(&ok, MAX_FORK_COUNT + 1).unwrap_err()).contains("count")
        );
        let err = check_forkable(&record(bridged, "flux-vm", "running"), 2).unwrap_err();
        assert!(format!("{err:#}").contains("netns"));
        let err = check_forkable(&record(netns.clone(), "qemu", "running"), 2).unwrap_err();
        assert!(format!("{err:#}").contains("flux-vm"));
        let err = check_forkable(&record(netns, "flux-vm", "stopped"), 2).unwrap_err();
        assert!(format!("{err:#}").contains("running"));
    }
}
