// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Crash recovery for `reconcile()`.
//!
//! * [`VmManager::replay_pending_ops`] rolls back the create, snapshot, fork
//!   and restore intents (`journal.rs`) whose owner died or gave up.
//! * [`VmManager::sweep_orphans`] removes workspaces, network namespaces and
//!   taps that no VM record and no journal intent accounts for.
//!
//! Both are deliberately conservative. A journal file is only trusted for
//! resources whose names follow FluxVM's own scheme *and* derive from the VM
//! id the intent is about (`resource_is_ours`); the sweep only considers
//! names of that exact shape, and only after they stayed unclaimed for a
//! grace period. Anything else is left alone.

use crate::VmManager;
use crate::journal::{self, OpGuard, OpIntent, OpKind, Resource};
use anyhow::{Context, Result};
use fluxvm_core::model::{BackendKind, CreateVmRequest, NetworkSpec, StorageBackend, VmStatus};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

/// A workspace directory with no record and no intent is removed once its
/// newest change is this old. Long on purpose: some paths (sandbox staging,
/// migration receivers) create the directory a little before their record.
pub const ORPHAN_DIR_GRACE: Duration = Duration::from_secs(3600);

/// A netns or tap with no record and no intent is removed after it has been
/// seen unclaimed, by successive sweeps, for this long.
pub const ORPHAN_NET_GRACE: Duration = Duration::from_secs(120);

/// Only processes with one of these names (`/proc/<pid>/comm` prefixes) are
/// ever killed on behalf of a rolled-back VM.
const VMM_COMM_PREFIXES: [&str; 7] = [
    "qemu",
    "cloud-hyper",
    "firecracker",
    "jailer",
    "virtiofsd",
    "swtpm",
    "fluxvm",
];

/// First 8 hex digits of a VM id: the suffix of every per-VM host name.
pub(crate) fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

fn is_short_hex(s: &str) -> bool {
    s.len() == 8
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `<state_dir>/instances/<uuid>` and nothing else.
pub(crate) fn workspace_vm_id(state_dir: &Path, p: &Path) -> Option<Uuid> {
    let base = state_dir.join("instances");
    if p.parent() != Some(base.as_path()) {
        return None;
    }
    Uuid::parse_str(p.file_name()?.to_str()?).ok()
}

/// True when `r` is something the daemon would have named for `vm_id`.
pub(crate) fn resource_is_ours(state_dir: &Path, vm_id: Uuid, r: &Resource) -> bool {
    let short = short_id(vm_id);
    match r {
        Resource::Workspace { path } => workspace_vm_id(state_dir, path) == Some(vm_id),
        Resource::Netns { name } => name.strip_prefix("eph-") == Some(short.as_str()),
        Resource::Tap { name } => name.strip_prefix("eph") == Some(short.as_str()),
        Resource::LvmLv { path } => {
            let lv_ok = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == format!("eph-{short}"));
            let vg = path.parent();
            let vg_ok = vg.is_some_and(|v| {
                v.parent() == Some(Path::new("/dev"))
                    && v.file_name().is_some_and(|n| !n.is_empty())
            });
            lv_ok && vg_ok
        }
        Resource::CephClone { pool_image } => {
            pool_image.split_once('/').is_some_and(|(pool, image)| {
                !pool.is_empty()
                    && !pool.starts_with('-')
                    && pool
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                    && image == format!("eph-{short}")
            })
        }
        // Checked against the live process (start time) at rollback.
        Resource::NbdPid { .. } => true,
        Resource::SnapshotDir { path } => {
            let tag_ok = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|t| !t.is_empty() && t != "." && t != "..");
            let snaps = path.parent();
            let snaps_ok =
                snaps.and_then(|s| s.file_name()).and_then(|n| n.to_str()) == Some("snapshots");
            let ws_ok = snaps
                .and_then(|s| s.parent())
                .is_some_and(|w| workspace_vm_id(state_dir, w) == Some(vm_id));
            tag_ok && snaps_ok && ws_ok
        }
        Resource::ForkChild { .. } => true,
        Resource::TempFile { path } => {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".restore.tmp"))
                && path
                    .parent()
                    .is_some_and(|w| workspace_vm_id(state_dir, w) == Some(vm_id))
        }
    }
}

/// Everything `create()` may allocate under names it can compute up front.
/// qemu-nbd, extra-NIC taps and user-named taps are not predictable (or not
/// ours) and are handled by process matching / left alone.
pub(crate) fn planned_create_resources(
    state_dir: &Path,
    id: Uuid,
    req: &CreateVmRequest,
) -> Vec<Resource> {
    let short = short_id(id);
    let mut out = vec![Resource::Workspace {
        path: state_dir.join("instances").join(id.to_string()),
    }];
    if let NetworkSpec::Tap {
        netns, tap_name, ..
    } = &req.network
    {
        if *netns {
            out.push(Resource::Netns {
                name: format!("eph-{short}"),
            });
        } else if tap_name.is_none() {
            out.push(Resource::Tap {
                name: format!("eph{short}"),
            });
        }
    }
    match req.storage {
        StorageBackend::LvmThin => {
            if let Some(vg) = req
                .image
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
            {
                out.push(Resource::LvmLv {
                    path: PathBuf::from("/dev").join(vg).join(format!("eph-{short}")),
                });
            }
        }
        StorageBackend::CephRbd => {
            if let Ok((pool, _)) = fluxvm_image::storage::parse_rbd_ref(&req.image, "ceph-rbd") {
                out.push(Resource::CephClone {
                    pool_image: format!("{pool}/eph-{short}"),
                });
            }
        }
        _ => {}
    }
    out
}

/// Pids of VMM-like processes whose command line mentions any of `needles`.
fn vmm_pids_referencing(needles: &[String]) -> Vec<u32> {
    let me = std::process::id();
    let Ok(rd) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) else {
            continue;
        };
        let comm = comm.trim();
        if !VMM_COMM_PREFIXES.iter().any(|p| comm.starts_with(p)) {
            continue;
        }
        let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&raw).replace('\0', " ");
        if needles.iter().any(|n| cmdline.contains(n.as_str())) {
            out.push(pid);
        }
    }
    out
}

async fn kill_vmm_processes(state_dir: &Path, id: Uuid) {
    let ws = state_dir.join("instances").join(id.to_string());
    let needles = vec![ws.display().to_string(), id.to_string()];
    for pid in vmm_pids_referencing(&needles) {
        tracing::warn!(vm = %id, pid, "killing a VMM process left by an interrupted operation");
        let _ = fluxvm_core::process::terminate_pid(pid).await;
    }
}

/// Directory entries of `dir` that are `eph-<8hex>` (netns) or `eph<8hex>`
/// (tap) and whose short id is not in `known`.
pub(crate) fn unclaimed_names(
    dir: &Path,
    short_of: fn(&str) -> Option<&str>,
    known: &HashSet<String>,
) -> Vec<String> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            short_of(n)
                .filter(|s| is_short_hex(s))
                .is_some_and(|s| !known.contains(s))
        })
        .collect()
}

pub(crate) fn netns_short(name: &str) -> Option<&str> {
    name.strip_prefix("eph-")
}

pub(crate) fn tap_short(name: &str) -> Option<&str> {
    name.strip_prefix("eph")
}

/// Workspace directories under `state_dir/instances` that no record or
/// intent claims and that have been quiet for `grace`.
pub(crate) fn orphan_workspaces(
    state_dir: &Path,
    claimed: &HashSet<Uuid>,
    now: SystemTime,
    grace: Duration,
) -> Vec<PathBuf> {
    let Ok(rd) = fs::read_dir(state_dir.join("instances")) else {
        return Vec::new();
    };
    rd.flatten()
        .filter_map(|e| {
            let path = e.path();
            let id = workspace_vm_id(state_dir, &path)?;
            if claimed.contains(&id) {
                return None;
            }
            let meta = e.metadata().ok()?;
            if !meta.is_dir() {
                return None;
            }
            let age = now
                .duration_since(meta.modified().ok()?)
                .unwrap_or_default();
            (age >= grace).then_some(path)
        })
        .collect()
}

/// Remembers when each unclaimed name was first seen, so a name is only
/// acted on after it stayed unclaimed across sweeps for the grace period.
#[derive(Default)]
pub(crate) struct FirstSeen {
    seen: HashMap<String, Instant>,
}

impl FirstSeen {
    /// Records `current` (names unclaimed right now), forgets names no longer
    /// present, and returns those first seen at least `grace` ago.
    pub(crate) fn ripe(
        &mut self,
        current: &[String],
        now: Instant,
        grace: Duration,
    ) -> Vec<String> {
        self.seen.retain(|k, _| current.contains(k));
        let mut out = Vec::new();
        for name in current {
            let first = *self.seen.entry(name.clone()).or_insert(now);
            if now.saturating_duration_since(first) >= grace {
                out.push(name.clone());
            }
        }
        out
    }
}

fn first_seen() -> &'static Mutex<HashMap<&'static str, FirstSeen>> {
    static SEEN: OnceLock<Mutex<HashMap<&'static str, FirstSeen>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ripe_names(kind: &'static str, current: &[String]) -> Vec<String> {
    let mut all = first_seen().lock().unwrap_or_else(|p| p.into_inner());
    all.entry(kind)
        .or_default()
        .ripe(current, Instant::now(), ORPHAN_NET_GRACE)
}

/// A uuid whose first 8 hex digits are `short`; enough for the per-VM host
/// names derived from the short id (`netns::cleanup` keys its nft table and
/// veth off it). The IPAM lease it cannot release is keyed by the full id.
fn id_from_short(short: &str) -> Option<Uuid> {
    Uuid::parse_str(&format!("{short}-0000-4000-8000-000000000000")).ok()
}

impl VmManager {
    /// Journals a snapshot of `id` under `tag`. The snapshot directory is
    /// listed for rollback only when this snapshot is what creates it (a
    /// pre-existing tag is never removed), and only for backends that keep
    /// snapshots as a directory (QEMU stores them inside the disk image).
    pub(crate) async fn begin_snapshot_op(&self, id: Uuid, tag: &str) -> Result<OpGuard> {
        let resources = match self.get(id).await {
            Ok(vm) if vm.backend != BackendKind::Qemu => {
                let dir = vm.workspace.join("snapshots").join(tag);
                if dir.exists() {
                    Vec::new()
                } else {
                    vec![Resource::SnapshotDir { path: dir }]
                }
            }
            _ => Vec::new(),
        };
        OpGuard::begin(
            &self.cfg.state_dir,
            OpKind::Snapshot,
            Uuid::new_v4(),
            id,
            resources,
        )
        .context("journaling snapshot intent")
    }

    /// Rolls back operation intents whose owner is gone. Safe to call on
    /// every reconcile tick: intents of live owners are skipped.
    pub(crate) async fn replay_pending_ops(&self) {
        let state_dir = self.cfg.state_dir.clone();
        for mut intent in journal::pending_ops(&state_dir) {
            if journal::owner_alive(intent.owner_pid, intent.owner_start) {
                continue;
            }
            tracing::warn!(
                op = intent.op.as_str(),
                id = %intent.op_id,
                vm = %intent.vm_id,
                "rolling back an operation interrupted by a crash"
            );
            let done = match intent.op {
                OpKind::Create => self.rollback_create(&intent).await,
                OpKind::Snapshot | OpKind::Restore => self.rollback_files(&intent),
                OpKind::Fork => self.rollback_fork(&intent).await,
            };
            if done {
                let _ = journal::finish_op(&state_dir, intent.op, intent.op_id);
            } else if intent.attempts + 1 >= journal::MAX_ROLLBACK_ATTEMPTS {
                tracing::error!(
                    op = intent.op.as_str(),
                    id = %intent.op_id,
                    "giving up rolling back an interrupted operation; its resources may be leaked"
                );
                let _ = journal::finish_op(&state_dir, intent.op, intent.op_id);
            } else {
                intent.attempts += 1;
                let _ = journal::update_op(&state_dir, &intent);
            }
        }
    }

    /// Returns true when nothing is left to retry.
    async fn rollback_create(&self, intent: &OpIntent) -> bool {
        let state_dir = &self.cfg.state_dir;
        let id = intent.vm_id;
        if let Some(vm) = self.store.get(id).await {
            // `create()` got as far as its final record update: it completed
            // (or failed and cleaned up itself); only the intent is stale.
            if vm.status != VmStatus::Creating {
                return true;
            }
        }
        let mut ok = true;
        kill_vmm_processes(state_dir, id).await;
        for r in &intent.resources {
            if !resource_is_ours(state_dir, id, r) {
                tracing::warn!(vm = %id, resource = ?r, "ignoring a journaled resource that is not FluxVM's");
                continue;
            }
            match r {
                Resource::NbdPid { pid, start_time } => {
                    // Only the exact process we started, never a reused pid.
                    if start_time.is_some() && journal::proc_start_time(*pid) == *start_time {
                        let _ = fluxvm_core::process::terminate_pid(*pid).await;
                    }
                }
                Resource::Netns { name } => {
                    let _ = fluxvm_network::netns::cleanup(state_dir, id, name).await;
                }
                Resource::Tap { name } => {
                    let _ = fluxvm_network::cleanup_tap(name).await;
                }
                Resource::LvmLv { path } => {
                    if path.exists() {
                        ok &= fluxvm_image::storage::cleanup_lvm_lv(path).await.is_ok();
                    }
                }
                Resource::CephClone { pool_image } => {
                    ok &= fluxvm_image::storage::cleanup_ceph_rbd(&self.cfg, pool_image)
                        .await
                        .is_ok();
                }
                _ => {}
            }
        }
        let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
        // The Creating placeholder, and with it the workspace.
        if self.store.get(id).await.is_some() {
            if let Err(e) = self.delete(id).await {
                tracing::warn!(vm = %id, error = %e, "removing the interrupted VM failed");
                ok = false;
            }
        }
        for r in &intent.resources {
            if let Resource::Workspace { path } = r {
                if resource_is_ours(state_dir, id, r) {
                    ok &= journal::remove_tree(path).is_ok();
                }
            }
        }
        ok
    }

    /// Snapshot and restore leave partial files, nothing else.
    fn rollback_files(&self, intent: &OpIntent) -> bool {
        let mut ok = true;
        for r in &intent.resources {
            if !resource_is_ours(&self.cfg.state_dir, intent.vm_id, r) {
                continue;
            }
            match r {
                Resource::SnapshotDir { path } => ok &= journal::remove_tree(path).is_ok(),
                Resource::TempFile { path } => match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => ok = false,
                },
                _ => {}
            }
        }
        ok
    }

    /// Fork is all-or-nothing: every child it started is removed, finished or
    /// not, and so is the parent's fork snapshot.
    async fn rollback_fork(&self, intent: &OpIntent) -> bool {
        let state_dir = &self.cfg.state_dir;
        let mut ok = true;
        for r in &intent.resources {
            let Resource::ForkChild { vm_id: child } = r else {
                continue;
            };
            if self.store.get(*child).await.is_some() {
                if let Err(e) = self.delete(*child).await {
                    tracing::warn!(vm = %child, error = %e, "removing a fork child failed");
                    ok = false;
                }
                continue;
            }
            // No record: the crash came before it was written, or after a
            // delete that did not finish; the child's own names remain.
            kill_vmm_processes(state_dir, *child).await;
            let _ = fluxvm_network::netns::cleanup(
                state_dir,
                *child,
                &format!("eph-{}", short_id(*child)),
            )
            .await;
            let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, *child);
            ok &=
                journal::remove_tree(&state_dir.join("instances").join(child.to_string())).is_ok();
        }
        ok & self.rollback_files(intent)
    }

    /// Removes workspaces, network namespaces and taps that no VM record and
    /// no journal intent claims. See the module docs for the safety rules.
    pub(crate) async fn sweep_orphans(&self) {
        let state_dir = &self.cfg.state_dir;
        let records = self.store.list().await;
        let mut claimed: HashSet<Uuid> = records.iter().map(|vm| vm.id).collect();
        for i in journal::pending_ops(state_dir) {
            claimed.insert(i.vm_id);
            claimed.insert(i.op_id);
            for r in &i.resources {
                if let Resource::ForkChild { vm_id } = r {
                    claimed.insert(*vm_id);
                }
            }
        }
        for d in journal::pending_deletes(state_dir) {
            claimed.insert(d.vm_id);
        }
        let shorts: HashSet<String> = claimed.iter().map(|id| short_id(*id)).collect();

        for ws in orphan_workspaces(state_dir, &claimed, SystemTime::now(), ORPHAN_DIR_GRACE) {
            let Some(id) = workspace_vm_id(state_dir, &ws) else {
                continue;
            };
            // Something still running out of it means it is not an orphan.
            if !vmm_pids_referencing(&[ws.display().to_string()]).is_empty() {
                continue;
            }
            tracing::warn!(vm = %id, path = %ws.display(), "removing an orphaned VM workspace");
            let _ = journal::remove_tree(&ws);
        }

        // The netns and tap sweeps match host-wide names (`eph-<8hex>`,
        // `eph<8hex>`) against this daemon's own records, so on a host where
        // another daemon (or another state dir) owns VMs they would look like
        // orphans and be removed. Opt in only on a host this daemon owns.
        let host_sweep = std::env::var("FLUXVM_ORPHAN_NET_SWEEP").is_ok_and(|v| v == "1");
        let netns_dir = if !host_sweep {
            None
        } else if Path::new("/run/netns").is_dir() {
            Some(Path::new("/run/netns"))
        } else if Path::new("/var/run/netns").is_dir() {
            Some(Path::new("/var/run/netns"))
        } else {
            None
        };
        if let Some(dir) = netns_dir {
            let current = unclaimed_names(dir, netns_short, &shorts);
            for name in ripe_names("netns", &current) {
                let Some(id) = netns_short(&name).and_then(id_from_short) else {
                    continue;
                };
                tracing::warn!(netns = %name, "removing an orphaned VM network namespace");
                let _ = fluxvm_network::netns::cleanup(state_dir, id, &name).await;
            }
        }

        let current: Vec<String> = unclaimed_names(Path::new("/sys/class/net"), tap_short, &shorts)
            .into_iter()
            .filter(|_| host_sweep)
            // Only tuntap devices: a bridge or veth that happens to match is not ours.
            .filter(|n| {
                Path::new("/sys/class/net")
                    .join(n)
                    .join("tun_flags")
                    .exists()
            })
            .collect();
        for name in ripe_names("tap", &current) {
            tracing::warn!(tap = %name, "removing an orphaned VM tap");
            let _ = fluxvm_network::cleanup_tap(&name).await;
        }

        let purged = crate::idempotency::purge_expired(state_dir, chrono::Utc::now().timestamp());
        if purged > 0 {
            tracing::info!(purged, "expired idempotency records removed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fluxvm_core::config::Config;

    fn req(network: serde_json::Value, storage: &str, image: &str) -> CreateVmRequest {
        serde_json::from_value(serde_json::json!({
            "name": "vm",
            "image": image,
            "vcpus": 1,
            "memory_mib": 256,
            "backend": "qemu",
            "network": network,
            "storage": storage,
        }))
        .unwrap()
    }

    #[test]
    fn workspace_must_be_a_uuid_directly_under_instances() {
        let sd = Path::new("/var/lib/fluxvm");
        let id = Uuid::new_v4();
        let ws = sd.join("instances").join(id.to_string());
        assert_eq!(workspace_vm_id(sd, &ws), Some(id));
        assert_eq!(workspace_vm_id(sd, &sd.join("instances")), None);
        assert_eq!(workspace_vm_id(sd, &sd.join("instances/not-a-uuid")), None);
        assert_eq!(workspace_vm_id(sd, &ws.join("sub")), None);
        assert_eq!(
            workspace_vm_id(sd, &sd.join("instances/..").join(id.to_string())),
            None
        );
        assert_eq!(workspace_vm_id(Path::new("/other"), &ws), None);
    }

    #[test]
    fn resources_are_only_ours_when_named_for_the_vm() {
        let sd = Path::new("/var/lib/fluxvm");
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let short = short_id(id);
        let ours = |r: &Resource| resource_is_ours(sd, id, r);

        assert!(ours(&Resource::Netns {
            name: format!("eph-{short}")
        }));
        assert!(!ours(&Resource::Netns {
            name: format!("eph-{}", short_id(other))
        }));
        assert!(!ours(&Resource::Netns {
            name: "default".into()
        }));
        assert!(ours(&Resource::Tap {
            name: format!("eph{short}")
        }));
        assert!(!ours(&Resource::Tap { name: "br0".into() }));
        assert!(!ours(&Resource::Tap {
            name: format!("eph-{short}")
        }));

        assert!(ours(&Resource::LvmLv {
            path: PathBuf::from(format!("/dev/vg0/eph-{short}"))
        }));
        assert!(!ours(&Resource::LvmLv {
            path: PathBuf::from("/dev/vg0/base-image")
        }));
        assert!(!ours(&Resource::LvmLv {
            path: PathBuf::from(format!("/etc/vg0/eph-{short}"))
        }));
        assert!(!ours(&Resource::LvmLv {
            path: PathBuf::from(format!("/dev/eph-{short}"))
        }));

        assert!(ours(&Resource::CephClone {
            pool_image: format!("rbd/eph-{short}")
        }));
        assert!(!ours(&Resource::CephClone {
            pool_image: "rbd/fluxvm-base".into()
        }));
        assert!(!ours(&Resource::CephClone {
            pool_image: format!("-x/eph-{short}")
        }));

        let ws = sd.join("instances").join(id.to_string());
        assert!(ours(&Resource::Workspace { path: ws.clone() }));
        assert!(!ours(&Resource::Workspace {
            path: PathBuf::from("/")
        }));
        assert!(!ours(&Resource::Workspace {
            path: sd.join("instances").join(other.to_string())
        }));
        assert!(ours(&Resource::SnapshotDir {
            path: ws.join("snapshots").join("t1")
        }));
        assert!(!ours(&Resource::SnapshotDir {
            path: ws.join("snapshots")
        }));
        assert!(!ours(&Resource::SnapshotDir {
            path: ws.join("elsewhere").join("t1")
        }));
        assert!(ours(&Resource::TempFile {
            path: ws.join("root.restore.tmp")
        }));
        assert!(!ours(&Resource::TempFile {
            path: ws.join("root.raw")
        }));
        assert!(!ours(&Resource::TempFile {
            path: PathBuf::from("/etc/x.restore.tmp")
        }));
    }

    #[test]
    fn create_plan_names_what_create_will_allocate() {
        let sd = Path::new("/s");
        let id = Uuid::new_v4();
        let short = short_id(id);

        let netns = req(
            serde_json::json!({"mode": "tap", "netns": true}),
            "default",
            "/img",
        );
        let plan = planned_create_resources(sd, id, &netns);
        assert!(plan.contains(&Resource::Netns {
            name: format!("eph-{short}")
        }));
        assert!(matches!(plan[0], Resource::Workspace { .. }));

        let auto_tap = req(
            serde_json::json!({"mode": "tap", "bridge": "br0"}),
            "default",
            "/img",
        );
        assert!(
            planned_create_resources(sd, id, &auto_tap).contains(&Resource::Tap {
                name: format!("eph{short}")
            })
        );

        // A tap the caller named is not ours to remove.
        let named = req(
            serde_json::json!({"mode": "tap", "tap_name": "mytap"}),
            "default",
            "/img",
        );
        assert_eq!(planned_create_resources(sd, id, &named).len(), 1);

        let lvm = req(
            serde_json::json!({"mode": "none"}),
            "lvm-thin",
            "/dev/vg0/base",
        );
        assert!(
            planned_create_resources(sd, id, &lvm).contains(&Resource::LvmLv {
                path: PathBuf::from(format!("/dev/vg0/eph-{short}"))
            })
        );

        let ceph = req(serde_json::json!({"mode": "none"}), "ceph-rbd", "rbd/base");
        assert!(
            planned_create_resources(sd, id, &ceph).contains(&Resource::CephClone {
                pool_image: format!("rbd/eph-{short}")
            })
        );

        // Every planned resource passes the ownership check.
        for r in planned_create_resources(sd, id, &ceph)
            .iter()
            .chain(planned_create_resources(sd, id, &lvm).iter())
            .chain(planned_create_resources(sd, id, &netns).iter())
        {
            assert!(resource_is_ours(sd, id, r), "{r:?}");
        }
    }

    #[test]
    fn first_seen_waits_out_the_grace_and_forgets_vanished_names() {
        let mut seen = FirstSeen::default();
        let t0 = Instant::now();
        let grace = Duration::from_secs(120);
        let names = vec!["a".to_string(), "b".to_string()];
        assert!(seen.ripe(&names, t0, grace).is_empty());
        assert!(
            seen.ripe(&names, t0 + Duration::from_secs(119), grace)
                .is_empty()
        );
        let ripe = seen.ripe(&names, t0 + Duration::from_secs(120), grace);
        assert_eq!(ripe, names);
        // "b" disappears (claimed or cleaned) and later comes back: the clock restarts.
        seen.ripe(&["a".to_string()], t0 + Duration::from_secs(130), grace);
        let back = seen.ripe(&names, t0 + Duration::from_secs(140), grace);
        assert_eq!(back, vec!["a".to_string()]);
    }

    #[test]
    fn unclaimed_names_only_match_our_shape() {
        let td = tempfile::tempdir().unwrap();
        for n in [
            "eph-0123abcd",
            "eph-deadbeef",
            "eph-xyz",
            "eph-0123abcde",
            "br0",
            "lo",
        ] {
            fs::write(td.path().join(n), b"").unwrap();
        }
        let known: HashSet<String> = ["deadbeef".to_string()].into();
        let mut got = unclaimed_names(td.path(), netns_short, &known);
        got.sort();
        assert_eq!(got, vec!["eph-0123abcd".to_string()]);
        // A netns name is not a tap name: "eph-..." is not "eph" + 8 hex.
        assert!(unclaimed_names(td.path(), tap_short, &HashSet::new()).is_empty());
    }

    #[test]
    fn orphan_workspaces_skip_claimed_young_and_foreign_entries() {
        let td = tempfile::tempdir().unwrap();
        let sd = td.path();
        let inst = sd.join("instances");
        let (orphan, claimed, young) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for id in [orphan, claimed] {
            fs::create_dir_all(inst.join(id.to_string())).unwrap();
        }
        fs::create_dir_all(inst.join("not-a-uuid")).unwrap();
        fs::write(inst.join(Uuid::new_v4().to_string()), b"a file").unwrap();
        fs::create_dir_all(inst.join(young.to_string())).unwrap();
        let claimed_set: HashSet<Uuid> = [claimed].into();

        // Everything is brand new: nothing is old enough.
        assert!(
            orphan_workspaces(sd, &claimed_set, SystemTime::now(), ORPHAN_DIR_GRACE).is_empty()
        );

        // An hour and a bit later, only unclaimed UUID directories qualify.
        let later = SystemTime::now() + ORPHAN_DIR_GRACE + Duration::from_secs(60);
        let mut got = orphan_workspaces(sd, &claimed_set, later, ORPHAN_DIR_GRACE);
        got.sort();
        let mut want = vec![inst.join(orphan.to_string()), inst.join(young.to_string())];
        want.sort();
        assert_eq!(got, want);
    }

    fn manager(dir: &Path) -> std::sync::Arc<VmManager> {
        let cfg = Config {
            state_dir: dir.join("state"),
            run_dir: dir.join("run"),
            ..Config::default()
        };
        VmManager::new(cfg).unwrap()
    }

    fn creating_record(id: Uuid, workspace: &Path, age_secs: i64) -> fluxvm_core::model::VmRecord {
        let mut v = serde_json::json!({
            "id": id,
            "name": "stuck",
            "backend": "qemu",
            "status": "creating",
            "pid": null,
            "created_at": (Utc::now() - chrono::Duration::seconds(age_secs)).to_rfc3339(),
            "expires_at": null,
            "workspace": workspace,
            "disk": workspace.join("root.qcow2"),
            "seed_disk": null,
            "tap_name": null,
            "control_socket": null,
            "log_path": workspace.join("console.log"),
            "error": null,
            "request": {
                "name": "stuck", "image": "/img", "vcpus": 1, "memory_mib": 256,
                "backend": "qemu", "network": {"mode": "none"}
            }
        });
        v["status"] = serde_json::json!("creating");
        serde_json::from_value(v).unwrap()
    }

    #[tokio::test]
    async fn abandoned_create_is_rolled_back_with_its_placeholder() {
        let td = tempfile::tempdir().unwrap();
        let m = manager(td.path());
        let sd = m.cfg.state_dir.clone();
        let id = Uuid::new_v4();
        let ws = sd.join("instances").join(id.to_string());
        fs::create_dir_all(ws.join("junk")).unwrap();
        m.store
            .insert_with_cid(creating_record(id, &ws, 1), false, 3)
            .await
            .unwrap();
        let guard = journal::OpGuard::begin(
            &sd,
            OpKind::Create,
            id,
            id,
            vec![Resource::Workspace { path: ws.clone() }],
        )
        .unwrap();

        // The owner (this process) is alive: nothing happens.
        m.replay_pending_ops().await;
        assert!(ws.exists());
        assert!(m.store.get(id).await.is_some());

        // Dropped without finish(): abandoned, so the next pass rolls it back.
        drop(guard);
        m.replay_pending_ops().await;
        assert!(!ws.exists());
        assert!(m.store.get(id).await.is_none());
        assert!(journal::pending_ops(&sd).is_empty());
    }

    #[tokio::test]
    async fn completed_create_only_loses_its_stale_intent() {
        let td = tempfile::tempdir().unwrap();
        let m = manager(td.path());
        let sd = m.cfg.state_dir.clone();
        let id = Uuid::new_v4();
        let ws = sd.join("instances").join(id.to_string());
        fs::create_dir_all(&ws).unwrap();
        let mut rec = creating_record(id, &ws, 1);
        rec.status = VmStatus::Stopped;
        m.store.insert_with_cid(rec, false, 3).await.unwrap();
        let guard = journal::OpGuard::begin(
            &sd,
            OpKind::Create,
            id,
            id,
            vec![Resource::Workspace { path: ws.clone() }],
        )
        .unwrap();
        drop(guard);
        m.replay_pending_ops().await;
        assert!(ws.exists(), "a finished VM must keep its workspace");
        assert!(m.store.get(id).await.is_some());
        assert!(journal::pending_ops(&sd).is_empty());
    }

    #[tokio::test]
    async fn journal_cannot_aim_rollback_at_foreign_paths() {
        let td = tempfile::tempdir().unwrap();
        let m = manager(td.path());
        let sd = m.cfg.state_dir.clone();
        let victim = td.path().join("precious");
        fs::create_dir_all(&victim).unwrap();
        let id = Uuid::new_v4();
        let guard = journal::OpGuard::begin(
            &sd,
            OpKind::Create,
            id,
            id,
            vec![Resource::Workspace {
                path: victim.clone(),
            }],
        )
        .unwrap();
        drop(guard);
        m.replay_pending_ops().await;
        assert!(victim.exists());
        assert!(journal::pending_ops(&sd).is_empty());
    }

    #[tokio::test]
    async fn abandoned_snapshot_loses_its_partial_dir_only() {
        let td = tempfile::tempdir().unwrap();
        let m = manager(td.path());
        let sd = m.cfg.state_dir.clone();
        let vm = Uuid::new_v4();
        let ws = sd.join("instances").join(vm.to_string());
        let partial = ws.join("snapshots").join("t1");
        let good = ws.join("snapshots").join("t0");
        fs::create_dir_all(&partial).unwrap();
        fs::create_dir_all(&good).unwrap();
        let guard = journal::OpGuard::begin(
            &sd,
            OpKind::Snapshot,
            Uuid::new_v4(),
            vm,
            vec![Resource::SnapshotDir {
                path: partial.clone(),
            }],
        )
        .unwrap();
        drop(guard);
        m.replay_pending_ops().await;
        assert!(!partial.exists());
        assert!(good.exists());
        assert!(journal::pending_ops(&sd).is_empty());
    }

    #[tokio::test]
    async fn stuck_creating_record_is_reclaimed_by_reconcile() {
        let td = tempfile::tempdir().unwrap();
        let m = manager(td.path());
        let id = Uuid::new_v4();
        let ws = m.cfg.state_dir.join("instances").join(id.to_string());
        fs::create_dir_all(&ws).unwrap();
        // Older than STUCK_CREATING_GRACE, no journal intent at all.
        m.store
            .insert_with_cid(creating_record(id, &ws, 3600), false, 3)
            .await
            .unwrap();
        // A young Creating record next to it must survive.
        let young = Uuid::new_v4();
        let young_ws = m.cfg.state_dir.join("instances").join(young.to_string());
        fs::create_dir_all(&young_ws).unwrap();
        m.store
            .insert_with_cid(creating_record(young, &young_ws, 1), false, 4)
            .await
            .unwrap();
        m.reconcile().await.unwrap();
        assert!(m.store.get(id).await.is_none());
        assert!(!ws.exists());
        assert!(m.store.get(young).await.is_some());
        assert!(young_ws.exists());
    }
}
