// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Receivers that become VMs: adopt-mode migration receivers, `adopt` and
//! source-side `finish`.
//!
//! A receiver created with the source's `record` launches QEMU from that
//! record's own device model (`fluxvm_qemu::build_args` plus `-incoming
//! defer`), with its own workspace, tap/netns and vsock CID, so the source and
//! the receiver can run side by side, even on one node. It is stored as a
//! `Creating` VM whose id is the receiver id and whose name is the source's.
//!
//! Order for a caller (Fabric, Machina):
//! 1. target: `POST /v1/migration/receivers` with `record`, then `activate`;
//! 2. source: `network/migration/quiesce` + `export` (optional), then
//!    `migration/start` with the receiver `uri`; poll `migration/status`;
//! 3. source: `migration/finish` once the phase is `completed`;
//! 4. target: `adopt`, then `network/migration/restore` + `resume` on the
//!    adopted id.
//!
//! Disks are never copied: the source must be on `storage: shared` or
//! `ceph-rbd-in-place`.

use crate::{
    VmManager, audit_event, backend, is_direct, process, validate_migration_receiver_request,
};
use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use fluxvm_core::backend::LaunchContext;
use fluxvm_core::model::{
    BackendKind, MigrationPhase, MigrationReceiver, MigrationReceiverRequest, NetworkSpec,
    StorageBackend, VmRecord, VmStatus,
};
use std::fs;
use uuid::Uuid;

/// Label on an adopt-mode receiver's VM record until it is adopted: the source VM id.
pub const MIGRATING_FROM_LABEL: &str = "fluxvm.dev/migrating-from";
/// Label on an adopted VM: the source VM id it was migrated from.
pub const MIGRATED_FROM_LABEL: &str = "fluxvm.dev/migrated-from";
/// Set on a VM after a CPU/memory hot-add, cleared on the next start.
pub const HOTPLUGGED_LABEL: &str = "fluxvm.dev/hotplugged";
/// Live vCPU / memory (MiB) after a hot-add, cleared on the next start.
pub const LIVE_VCPUS_LABEL: &str = "fluxvm.dev/live-vcpus";
pub const LIVE_MEMORY_LABEL: &str = "fluxvm.dev/live-memory-mib";

pub fn clear_hotplug_labels(labels: &mut std::collections::BTreeMap<String, String>) {
    for k in [HOTPLUGGED_LABEL, LIVE_VCPUS_LABEL, LIVE_MEMORY_LABEL] {
        labels.remove(k);
    }
}
/// Workspace socket an adopt-mode receiver's QEMU accepts the stream on.
const INCOMING_SOCKET: &str = "migrate-in.sock";
/// Workspace socket a netns source's QEMU sends the stream to.
pub(crate) const OUTGOING_SOCKET: &str = "migrate-out.sock";

/// Why `record` cannot be live-migrated by contract v1, if it cannot.
pub fn adopt_unsupported(record: &VmRecord) -> Option<String> {
    let req = &record.request;
    if record.labels.contains_key(HOTPLUGGED_LABEL) {
        return Some(
            "VM has hot-added CPUs or memory; restart it before migrating (a fresh boot matches the receiver's device model)".into(),
        );
    }
    if record.backend != BackendKind::Qemu {
        return Some(format!(
            "adopt-mode receivers support qemu only (source backend={:?})",
            record.backend
        ));
    }
    if !matches!(
        req.storage,
        StorageBackend::Shared | StorageBackend::CephRbdInPlace
    ) {
        return Some(format!(
            "live migration needs the disk on shared storage (storage: shared or ceph-rbd-in-place); FluxVM never copies disks (source storage={:?})",
            req.storage
        ));
    }
    if req.network.is_direct() || matches!(req.network, NetworkSpec::Macvtap { .. }) {
        return Some("direct-datapath and macvtap VMs are not migratable yet".into());
    }
    if let NetworkSpec::Tap { extra, .. } = &req.network
        && !extra.is_empty()
    {
        return Some("VMs with hot-added NICs are not migratable yet".into());
    }
    if req.tpm == Some(true) {
        return Some(
            "VMs with a vTPM are not migratable yet (swtpm state is not transferred)".into(),
        );
    }
    if !req.vfio_devices.is_empty() {
        return Some("VMs with VFIO passthrough devices cannot be live-migrated".into());
    }
    if !req.shared_folders.is_empty() {
        return Some("VMs with virtiofs shares are not migratable yet".into());
    }
    if !req.data_disks.is_empty() {
        return Some("VMs with data disks are not migratable yet".into());
    }
    if req.security_profile.is_confidential() {
        return Some("confidential VMs cannot be live-migrated".into());
    }
    None
}

impl VmManager {
    pub(crate) async fn launch_adopt_receiver(
        &self,
        req: MigrationReceiverRequest,
        source: VmRecord,
    ) -> Result<MigrationReceiver> {
        if let Some(why) = adopt_unsupported(&source) {
            bail!(why);
        }
        validate_migration_receiver_request(&req, &self.cfg)?;
        let sreq = source.request.clone();
        if sreq.storage == StorageBackend::Shared {
            fluxvm_image::storage::validate_shared_disk(&source.disk)?;
        }
        let ledger = self.store.quota_ledger().await?;
        fluxvm_core::policy::enforce_host_totals(
            sreq.vcpus,
            sreq.memory_mib,
            &self.cfg.policy,
            &fluxvm_core::policy::ledger_for_host_admission(&ledger),
        )?;

        let id = Uuid::new_v4();
        let workspace = self.cfg.state_dir.join("instances").join(id.to_string());
        fs::create_dir_all(&workspace)?;
        let log_path = workspace.join("console.log");
        let mut labels = source.labels.clone();
        labels.remove(MIGRATED_FROM_LABEL);
        clear_hotplug_labels(&mut labels);
        labels.insert(MIGRATING_FROM_LABEL.into(), source.id.to_string());
        let placeholder = VmRecord {
            id,
            name: source.name.clone(),
            backend: BackendKind::Qemu,
            status: VmStatus::Creating,
            pid: None,
            created_at: source.created_at,
            expires_at: source.expires_at,
            workspace: workspace.clone(),
            disk: source.disk.clone(),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: log_path.clone(),
            error: None,
            request: sreq.clone(),
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
            requested_security_profile: source.requested_security_profile,
            achieved_security_profile: source.achieved_security_profile,
            security_evidence: source.security_evidence.clone(),
            labels,
        };
        let needs_cid = sreq.agent.as_ref().is_some_and(|a| a.enabled);
        let mut record = self
            .store
            .insert_with_cid(placeholder, needs_cid, crate::FIRST_GUEST_CID)
            .await?;

        let result: Result<(String, String, tokio::net::TcpListener)> = async {
            if sreq.storage == StorageBackend::Shared {
                self.shared_disk_conflict(&source.disk, id, &[source.id]).await?;
            }
            let network = fluxvm_network::prepare(&self.cfg, id, &sreq.network).await?;
            let dataplane_if = fluxvm_network::dataplane_interface(id, &network);
            record.tap_name = network.tap_name.clone();
            record.netns = network.netns.clone();
            record.dhcp_leasefile = network.dhcp_leasefile.clone();
            record.guest_ip = network.guest_ip.clone();

            // The seed is a read-only drive the device model must still have;
            // its bytes only matter at first boot. Copy it when this node can
            // see the source's, otherwise rebuild it from the request.
            record.seed_disk = match &source.seed_disk {
                Some(src) if src.is_file() => {
                    let name = src.file_name().context("seed disk has no file name")?;
                    let dst = workspace.join(name);
                    fs::copy(src, &dst).context("copying the source's cloud-init seed")?;
                    Some(dst)
                }
                Some(_) => match Self::effective_cloud_init(&sreq) {
                    Some(ci) => {
                        let static_net = network
                            .guest_cidr
                            .as_deref()
                            .zip(network.gateway.as_deref());
                        Some(
                            fluxvm_image::cloudinit::build_seed(
                                &self.cfg, &workspace, &ci, static_net,
                            )
                            .await?,
                        )
                    }
                    None => None,
                },
                None => None,
            };
            let vars = source.workspace.join("ovmf_vars.fd");
            if vars.is_file() {
                fs::copy(&vars, workspace.join("ovmf_vars.fd"))
                    .context("copying the source's OVMF vars")?;
            }

            let guest_cidr_for_policy = network
                .guest_cidr
                .clone()
                .or_else(|| record.guest_ip.as_ref().map(|ip| format!("{ip}/32")));
            if let Err(e) = fluxvm_network::dataplane::apply_sandbox_policy(
                &self.cfg,
                id,
                dataplane_if.as_deref(),
                guest_cidr_for_policy.as_deref(),
                &[],
                sreq.pod_uid.as_deref(),
            ) {
                if is_direct(&network.spec)
                    || self.cfg.sandbox.dataplane.required
                    || self.cfg.sandbox.dataplane.mode
                        != fluxvm_core::config::DataplaneMode::Legacy
                {
                    return Err(e).context("applying VM dataplane for the migration receiver");
                }
                tracing::warn!(vm = %id, error = %e, "receiver dataplane apply failed");
            }

            let listen_host = if req.listen_host.is_empty() {
                "0.0.0.0"
            } else {
                req.listen_host.as_str()
            };
            // QEMU may sit in the VM's netns, so it listens on a workspace
            // socket and FluxVM owns the TCP side (see migration_relay).
            let bind = if listen_host == "::" || listen_host == "[::]" {
                format!("[::]:{}", req.listen_port)
            } else {
                format!("{listen_host}:{}", req.listen_port)
            };
            let listener = tokio::net::TcpListener::bind(&bind)
                .await
                .with_context(|| format!("binding migration receiver on {bind}"))?;
            let port = listener.local_addr()?.port();
            let (uri, _) =
                fluxvm_qemu::receiver::advertised_uri(listen_host, &req.advertise_host, port)?;
            let listen_uri =
                crate::migration_relay::unix_uri(&workspace.join(INCOMING_SOCKET));

            let ctx = LaunchContext {
                id,
                workspace: workspace.clone(),
                disk: source.disk.clone(),
                seed_disk: record.seed_disk.clone(),
                log_path: log_path.clone(),
                network,
                guest_cid: record.guest_cid,
                vsock_socket: None,
                disk_format: fluxvm_image::storage::disk_format(BackendKind::Qemu, sreq.storage),
                nbd_export: None,
            };
            let mut launch_req = sreq.clone();
            launch_req.loadvm_tag = None;
            launch_req
                .extra_args
                .extend(["-incoming".to_string(), "defer".to_string()]);
            let launch = backend(BackendKind::Qemu)?
                .launch(&self.cfg, &launch_req, &ctx)
                .await?;
            record.pid = Some(launch.pid);
            record.control_socket = launch.control_socket;
            if sreq.qga.as_ref().is_some_and(|q| q.enabled) {
                record.qga_socket = Some(workspace.join("qga.sock"));
            }
            process::wait_for_socket_ready(
                launch.pid,
                &workspace.join("qmp.sock"),
                std::time::Duration::from_secs(15),
                "QEMU migration receiver",
                &log_path,
            )
            .await?;
            let vfio = sreq.vfio_devices.clone();
            self.attach_cgroup(id, launch.pid, &mut record, &vfio);
            if let Some(ns) = &record.netns
                && let Err(e) = fluxvm_network::netns::repair_named_netns(ns, launch.pid).await
            {
                tracing::warn!(vm = %id, netns = %ns, error = %e, "receiver netns handle repair failed");
            }
            Ok((uri, listen_uri, listener))
        }
        .await;

        let (uri, listen_uri, listener) = match result {
            Ok(v) => v,
            Err(e) => {
                if let Some(pid) = record.pid {
                    let _ = process::terminate_pid(pid).await;
                }
                self.discard_receiver_record(&record).await;
                return Err(e);
            }
        };
        self.store.update(record.clone()).await?;

        let ttl = req.expires_in_seconds.unwrap_or(600);
        let rec = MigrationReceiver {
            id,
            uri,
            listen_uri,
            token: Uuid::new_v4().to_string(),
            expires_at_unix: (Utc::now() + Duration::seconds(ttl as i64)).timestamp() as u64,
            pid: record.pid.unwrap_or_default(),
            qmp_socket: workspace.join("qmp.sock"),
            workspace,
            disk: source.disk.clone(),
            cgroup_path: record.cgroup_path.clone(),
            // The VM record carries the quota; nothing untracked to release.
            vcpus: 0,
            memory_mib: 0,
            tls: req.tls,
            source_id: Some(source.id),
        };
        if let Err(e) = self.write_receiver(&rec) {
            if let Some(pid) = record.pid {
                let _ = process::terminate_pid(pid).await;
            }
            self.discard_receiver_record(&record).await;
            return Err(e);
        }
        let marker = self.receiver_dir().join(format!("{id}.json"));
        crate::migration_relay::spawn_tcp_to_unix(
            listener,
            rec.workspace.join(INCOMING_SOCKET),
            std::time::Duration::from_secs(ttl),
            move || marker.exists(),
        );
        audit_event(
            "migration.receiver",
            &[
                ("receiver_id", &id.to_string()),
                ("uri", &rec.uri),
                ("source_vm", &source.id.to_string()),
            ],
        );
        Ok(rec)
    }

    /// Tear down an adopt-mode receiver's VM record whose process is gone.
    pub(crate) async fn discard_receiver_record(&self, record: &VmRecord) {
        let id = record.id;
        let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
        if let Some(tap) = &record.tap_name {
            let _ = fluxvm_network::cleanup(
                &self.cfg.state_dir,
                id,
                &record.request.network,
                tap,
                record.netns.as_deref(),
            )
            .await;
        }
        if let Some(path) = &record.cgroup_path
            && let Ok(mgr) = fluxvm_cgroup::CgroupManager::from_path(path.clone())
        {
            let _ = mgr.remove();
        }
        let _ = self.store.remove(id).await;
        let _ = fs::remove_dir_all(&record.workspace);
    }

    /// Turn a completed adopt-mode receiver into a running VM with the
    /// receiver's id and the source's name and request.
    pub async fn adopt_migration_receiver(&self, id: Uuid, token: &str) -> Result<VmRecord> {
        let rec = self.read_receiver(id)?;
        if rec.token != token {
            bail!("migration receiver token does not match");
        }
        let Some(source_id) = rec.source_id else {
            bail!(
                "migration receiver {id} was created without a source record; only receivers created with `record` can be adopted"
            );
        };
        let state = fluxvm_qemu::receiver::run_state(&rec.qmp_socket).await?;
        let status = match state.as_str() {
            "running" => VmStatus::Running,
            "paused" => VmStatus::Paused,
            other => bail!(
                "incoming migration into receiver {id} has not completed (QEMU run state {other:?})"
            ),
        };
        let mut vm = self.get(id).await?;
        if vm.request.storage == StorageBackend::Shared {
            self.claim_shared_disk(&vm.disk, id, &[source_id]).await?;
        }
        vm.status = status;
        vm.error = None;
        vm.labels.remove(MIGRATING_FROM_LABEL);
        vm.labels
            .insert(MIGRATED_FROM_LABEL.into(), source_id.to_string());
        self.store.update(vm.clone()).await?;
        let path = self.receiver_dir().join(format!("{id}.json"));
        if let Err(e) = fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(receiver = %id, error = %e, "removing adopted receiver file");
        }
        audit_event(
            "migration.adopt",
            &[
                ("vm_id", &id.to_string()),
                ("source_vm", &source_id.to_string()),
            ],
        );
        Ok(vm)
    }

    /// Source side, after a completed migration: stop the paused source QEMU
    /// and remove the VM record and workspace. The disk stays (shared storage).
    pub async fn finish_migration(&self, id: Uuid) -> Result<()> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Qemu {
            bail!(
                "migration finish supports qemu only (backend={:?})",
                vm.backend
            );
        }
        let status = fluxvm_qemu::migration_status(&self.cfg, &vm).await?;
        if status.phase != MigrationPhase::Completed {
            bail!(
                "migration of {id} has not completed (phase {:?}); wait for it or cancel it",
                status.phase
            );
        }
        // The guest now runs on the target, so no graceful shutdown here.
        if let Some(pid) = vm.pid
            && process::process_alive(pid).await
        {
            process::terminate_pid(pid).await?;
        }
        self.delete(id).await?;
        audit_event("migration.finish", &[("vm_id", &id.to_string())]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::model::{CreateVmRequest, NetworkSpec};

    fn record(storage: StorageBackend) -> VmRecord {
        let req: CreateVmRequest = serde_json::from_value(serde_json::json!({
            "name": "m1",
            "backend": "qemu",
            "image": "/srv/shared/m1.raw",
            "vcpus": 1,
            "memory_mib": 512,
            "storage": storage,
        }))
        .unwrap();
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "name": "m1",
            "backend": "qemu",
            "status": "running",
            "created_at": Utc::now(),
            "workspace": "/tmp/ws",
            "disk": "/srv/shared/m1.raw",
            "log_path": "/tmp/ws/console.log",
            "request": req,
        }))
        .unwrap()
    }

    #[test]
    fn only_shared_qemu_records_are_adoptable() {
        assert!(adopt_unsupported(&record(StorageBackend::Shared)).is_none());
        assert!(adopt_unsupported(&record(StorageBackend::CephRbdInPlace)).is_none());
        let why = adopt_unsupported(&record(StorageBackend::Default)).unwrap();
        assert!(why.contains("shared storage"), "{why}");
        let mut ch = record(StorageBackend::Shared);
        ch.backend = BackendKind::CloudHypervisor;
        assert!(adopt_unsupported(&ch).unwrap().contains("qemu only"));
        let mut tpm = record(StorageBackend::Shared);
        tpm.request.tpm = Some(true);
        assert!(adopt_unsupported(&tpm).unwrap().contains("vTPM"));
        let mut user = record(StorageBackend::Shared);
        user.request.network = NetworkSpec::User { forwards: vec![] };
        assert!(adopt_unsupported(&user).is_none());
        let mut hot = record(StorageBackend::Shared);
        hot.labels.insert(HOTPLUGGED_LABEL.into(), "true".into());
        assert!(adopt_unsupported(&hot).unwrap().contains("restart"));
        clear_hotplug_labels(&mut hot.labels);
        assert!(adopt_unsupported(&hot).is_none());
    }
}
