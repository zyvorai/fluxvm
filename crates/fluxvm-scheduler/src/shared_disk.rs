// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Ownership lock for `StorageBackend::Shared` disks.
//!
//! The disk lives on storage several nodes can open, so FluxVM cannot rely on
//! a process-local lock. Instead `<disk>.fluxvm-lock` (next to the disk, so on
//! the same shared storage) names the VM and node that have it open. A launch
//! is refused while another VM holds it, except when that holder is provably
//! gone: same node and the VM record is missing or its process is dead. A
//! holder on another node is never assumed dead; the caller breaks the lock
//! explicitly (`POST /v1/vms?shared_takeover=true`) after fencing that node.

use crate::{VmManager, audit_event, process};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const LOCK_SUFFIX: &str = ".fluxvm-lock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedDiskLock {
    pub vm_id: Uuid,
    pub host: String,
    pub acquired_at: DateTime<Utc>,
}

pub fn lock_path(disk: &Path) -> PathBuf {
    let mut s = disk.as_os_str().to_owned();
    s.push(LOCK_SUFFIX);
    PathBuf::from(s)
}

pub fn local_host() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

pub fn read_lock(disk: &Path) -> Option<SharedDiskLock> {
    let raw = fs::read_to_string(lock_path(disk)).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_lock(disk: &Path, lock: &SharedDiskLock) -> Result<()> {
    let path = lock_path(disk);
    let tmp = {
        let mut s = path.as_os_str().to_owned();
        s.push(format!(".{}", lock.vm_id));
        PathBuf::from(s)
    };
    let mut f = fs::File::create(&tmp)
        .with_context(|| format!("writing shared disk lock {}", tmp.display()))?;
    f.write_all(&serde_json::to_vec(lock)?)?;
    f.sync_all()?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("installing shared disk lock {}", path.display()))?;
    Ok(())
}

impl VmManager {
    async fn shared_lock_is_stale(&self, held: &SharedDiskLock) -> bool {
        if held.host != local_host() {
            return false;
        }
        match self.store.get(held.vm_id).await {
            None => true,
            Some(vm) => match vm.pid {
                None => true,
                Some(pid) => !process::process_alive(pid).await,
            },
        }
    }

    /// Errors when a VM other than `vm_id` / `also_ok` holds `disk`.
    pub(crate) async fn shared_disk_conflict(
        &self,
        disk: &Path,
        vm_id: Uuid,
        also_ok: &[Uuid],
    ) -> Result<()> {
        let Some(held) = read_lock(disk) else {
            return Ok(());
        };
        if held.vm_id == vm_id || also_ok.contains(&held.vm_id) {
            return Ok(());
        }
        if self.shared_lock_is_stale(&held).await {
            return Ok(());
        }
        bail!(
            "shared disk {} is in use by VM {} on {} since {} (lock {}); stop or delete that VM, or retry with shared_takeover=true after fencing {}",
            disk.display(),
            held.vm_id,
            held.host,
            held.acquired_at.to_rfc3339(),
            lock_path(disk).display(),
            held.host
        )
    }

    /// Record `vm_id` as the holder of `disk` (see [`Self::shared_disk_conflict`]).
    pub(crate) async fn claim_shared_disk(
        &self,
        disk: &Path,
        vm_id: Uuid,
        also_ok: &[Uuid],
    ) -> Result<()> {
        self.shared_disk_conflict(disk, vm_id, also_ok).await?;
        write_lock(
            disk,
            &SharedDiskLock {
                vm_id,
                host: local_host(),
                acquired_at: Utc::now(),
            },
        )
    }

    /// Drops the lock only when `vm_id` still holds it.
    pub(crate) fn release_shared_disk(&self, disk: &Path, vm_id: Uuid) {
        if read_lock(disk).is_some_and(|l| l.vm_id == vm_id) {
            if let Err(e) = fs::remove_file(lock_path(disk)) {
                tracing::warn!(vm = %vm_id, error = %e, "removing shared disk lock");
            }
        }
    }

    /// Removes whatever lock is on `disk`. Only for a caller that has fenced
    /// the previous holder's node (HA re-create).
    pub fn break_shared_disk_lock(&self, disk: &Path) -> Result<Option<SharedDiskLock>> {
        fluxvm_image::storage::validate_shared_disk(disk)?;
        let held = read_lock(disk);
        match fs::remove_file(lock_path(disk)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("removing shared disk lock"),
        }
        if let Some(h) = &held {
            audit_event(
                "storage.shared_takeover",
                &[
                    ("disk", &disk.display().to_string()),
                    ("previous_vm", &h.vm_id.to_string()),
                    ("previous_host", &h.host),
                ],
            );
        }
        Ok(held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_sits_next_to_the_disk() {
        assert_eq!(
            lock_path(Path::new("/srv/nfs/vm1.raw")),
            PathBuf::from("/srv/nfs/vm1.raw.fluxvm-lock")
        );
    }

    fn manager() -> std::sync::Arc<VmManager> {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let cfg = fluxvm_core::config::Config {
            state_dir: dir.path().join("state"),
            run_dir: dir.path().join("run"),
            ..Default::default()
        };
        VmManager::new(cfg).unwrap()
    }

    fn running_record(id: Uuid, pid: u32) -> fluxvm_core::model::VmRecord {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": "holder",
            "backend": "qemu",
            "status": "running",
            "pid": pid,
            "created_at": Utc::now(),
            "workspace": "/tmp/ws",
            "disk": "/tmp/d.raw",
            "log_path": "/tmp/ws/console.log",
            "request": {
                "name": "holder",
                "backend": "qemu",
                "image": "/tmp/d.raw",
                "vcpus": 1,
                "memory_mib": 256,
                "storage": "shared"
            },
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_live_holder_blocks_other_vms_until_released() {
        let m = manager();
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("d.raw");
        std::fs::write(&disk, vec![0u8; 512]).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        m.store
            .insert(running_record(a, std::process::id()))
            .await
            .unwrap();

        m.claim_shared_disk(&disk, a, &[]).await.unwrap();
        let err = m.claim_shared_disk(&disk, b, &[]).await.unwrap_err();
        assert!(err.to_string().contains("in use by VM"), "{err}");
        // The migration receiver may share it with its source.
        m.shared_disk_conflict(&disk, b, &[a]).await.unwrap();
        // Releasing as a non-holder does nothing.
        m.release_shared_disk(&disk, b);
        assert_eq!(read_lock(&disk).unwrap().vm_id, a);
        m.release_shared_disk(&disk, a);
        assert!(read_lock(&disk).is_none());
        m.claim_shared_disk(&disk, b, &[]).await.unwrap();
        assert_eq!(read_lock(&disk).unwrap().vm_id, b);
    }

    #[tokio::test]
    async fn stale_local_holders_yield_but_remote_ones_need_a_takeover() {
        let m = manager();
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("d.raw");
        std::fs::write(&disk, vec![0u8; 512]).unwrap();
        let gone = Uuid::new_v4();
        // Same node, no such VM: stale.
        write_lock(
            &disk,
            &SharedDiskLock {
                vm_id: gone,
                host: local_host(),
                acquired_at: Utc::now(),
            },
        )
        .unwrap();
        m.claim_shared_disk(&disk, Uuid::new_v4(), &[])
            .await
            .unwrap();
        // Another node: never assumed dead.
        write_lock(
            &disk,
            &SharedDiskLock {
                vm_id: gone,
                host: "some-other-node".into(),
                acquired_at: Utc::now(),
            },
        )
        .unwrap();
        let err = m
            .claim_shared_disk(&disk, Uuid::new_v4(), &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("some-other-node"), "{err}");
        let broken = m.break_shared_disk_lock(&disk).unwrap().unwrap();
        assert_eq!(broken.vm_id, gone);
        m.claim_shared_disk(&disk, Uuid::new_v4(), &[])
            .await
            .unwrap();
    }

    #[test]
    fn lock_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("d.raw");
        let lock = SharedDiskLock {
            vm_id: Uuid::new_v4(),
            host: "node-a".into(),
            acquired_at: Utc::now(),
        };
        write_lock(&disk, &lock).unwrap();
        assert_eq!(read_lock(&disk), Some(lock));
    }
}
