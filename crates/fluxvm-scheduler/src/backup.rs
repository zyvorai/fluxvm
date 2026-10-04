// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Backups under `state_dir/backups`: guest quiescing for `backup_vm`, and
//! listing, deleting and restoring what it wrote.
//!
//! A backup is either `<name>.qcow2` (root disk only) with a `<name>.qcow2.json`
//! sidecar, or a directory `<name>/` holding `root.qcow2`, one `<disk>.qcow2`
//! per data disk and `backup.json`. Every qcow2 is standalone (no backing
//! file), so a restore is a plain copy.

use crate::{VmManager, audit_event};
use anyhow::{Context, Result, bail};
use fluxvm_core::model::{BackendKind, BackupQuiesce, StorageBackend, VmRecord, VmStatus};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DIR_SIDECAR: &str = "backup.json";

/// Where `backup_vm` writes the metadata for a backup at `dest`.
pub fn sidecar_path(dest: &Path, dir: bool) -> PathBuf {
    if dir {
        dest.join(DIR_SIDECAR)
    } else {
        let mut s = dest.as_os_str().to_owned();
        s.push(".json");
        PathBuf::from(s)
    }
}

/// A backup name is one path component under `state_dir/backups`.
pub fn validate_backup_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with(".json")
        || name.contains(['/', '\\', '\0'])
    {
        bail!("invalid backup name {name:?}");
    }
    Ok(())
}

/// Metadata for every backup in `dir`, newest first. Backups written before
/// sidecars existed are listed with what the filesystem shows.
pub fn list_backups(dir: &Path) -> Vec<serde_json::Value> {
    let Ok(rd) = fs::read_dir(dir) else {
        return vec![];
    };
    let mut out: Vec<(std::time::SystemTime, serde_json::Value)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = e.path();
            let meta = e.metadata().ok()?;
            let is_dir = meta.is_dir();
            if !is_dir && !name.ends_with(".qcow2") {
                return None;
            }
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            let mut v = fs::read(sidecar_path(&path, is_dir))
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "path": path,
                        "size_bytes": if is_dir { dir_qcow2_bytes(&path) } else { meta.len() },
                    })
                });
            v["name"] = name.into();
            v["kind"] = if is_dir { "dir" } else { "file" }.into();
            Some((mtime, v))
        })
        .collect();
    out.sort_by_key(|a| std::cmp::Reverse(a.0));
    out.into_iter().map(|(_, v)| v).collect()
}

fn dir_qcow2_bytes(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "qcow2"))
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// The `(disk name, qcow2)` pairs a backup holds; `root` is the boot disk.
pub fn backup_disks(path: &Path) -> Result<Vec<(String, PathBuf)>> {
    if path.is_file() {
        return Ok(vec![(
            fluxvm_qemu::disks::ROOT_DISK.to_string(),
            path.to_path_buf(),
        )]);
    }
    let mut out: Vec<(String, PathBuf)> = fs::read_dir(path)
        .with_context(|| format!("reading backup {}", path.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "qcow2"))
        .filter_map(|p| Some((p.file_stem()?.to_str()?.to_string(), p)))
        .collect();
    if !out.iter().any(|(n, _)| n == fluxvm_qemu::disks::ROOT_DISK) {
        bail!("backup {} has no root.qcow2", path.display());
    }
    out.sort();
    Ok(out)
}

impl VmManager {
    pub(crate) fn backups_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("backups")
    }

    /// Freezes the guest's filesystems for a backup snapshot when `quiesce`
    /// and the guest agent allow it. Returns whether they are now frozen
    /// (the caller thaws).
    pub(crate) async fn backup_freeze(
        &self,
        vm: &VmRecord,
        quiesce: BackupQuiesce,
    ) -> Result<bool> {
        if quiesce == BackupQuiesce::Never {
            return Ok(false);
        }
        let required = quiesce == BackupQuiesce::Required;
        if vm.status != VmStatus::Running {
            if required {
                bail!(
                    "quiesce=required needs a running VM (status is {:?})",
                    vm.status
                );
            }
            return Ok(false);
        }
        let sock = match Self::qga_socket_for(vm) {
            Ok(s) => s,
            Err(e) if required => return Err(e.context("quiesce=required")),
            Err(_) => return Ok(false),
        };
        let frozen = tokio::task::spawn_blocking(move || {
            fluxvm_image::qga::ping(&sock)?;
            fluxvm_image::qga::fsfreeze_freeze(&sock)
        })
        .await
        .context("qga fsfreeze worker panicked")?;
        match frozen {
            Ok(n) => {
                tracing::info!(vm=%vm.id, filesystems = n, "froze guest filesystems for backup");
                Ok(true)
            }
            Err(e) if required => Err(e.context("quiesce=required: guest fsfreeze failed")),
            Err(e) => {
                tracing::warn!(vm=%vm.id, "guest fsfreeze failed, taking a crash-consistent backup: {e:#}");
                Ok(false)
            }
        }
    }

    /// Every backup under `state_dir/backups`, newest first.
    pub fn list_backups(&self) -> Vec<serde_json::Value> {
        list_backups(&self.backups_dir())
    }

    fn backup_path(&self, name: &str) -> Result<PathBuf> {
        validate_backup_name(name)?;
        let path = self.backups_dir().join(name);
        if !path.exists() {
            bail!("backup {name:?} not found");
        }
        Ok(path)
    }

    /// Removes backup `name` and its metadata.
    pub fn delete_backup(&self, name: &str) -> Result<()> {
        let path = self.backup_path(name)?;
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
            let _ = fs::remove_file(sidecar_path(&path, false));
        }
        audit_event("vm.backup.delete", &[("backup", name)]);
        Ok(())
    }

    /// Restores backup `name` into stopped VM `id` in place: the root disk
    /// and every data disk the backup holds are replaced (a data disk the
    /// VM no longer has is recreated). Disks attached from an existing
    /// image are skipped; their source is not the VM's to overwrite.
    pub async fn restore_backup(&self, id: Uuid, name: &str) -> Result<serde_json::Value> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Qemu || vm.request.storage != StorageBackend::Default {
            bail!("backup restore supports QEMU VMs on the default qcow2 storage backend only");
        }
        if !matches!(vm.status, VmStatus::Stopped | VmStatus::Failed) {
            bail!(
                "stop the VM before restoring a backup (status is {:?})",
                vm.status
            );
        }
        let path = self.backup_path(name)?;
        let mut restored = Vec::new();
        let mut skipped = Vec::new();
        for (disk, src) in backup_disks(&path)? {
            let dst = if disk == fluxvm_qemu::disks::ROOT_DISK {
                vm.disk.clone()
            } else {
                if fluxvm_qemu::disks::validate_disk_name(&disk).is_err() {
                    skipped.push(serde_json::json!({"name": disk, "reason": "invalid disk name"}));
                    continue;
                }
                let existing = fluxvm_qemu::disks::data_disks(&vm.workspace)
                    .into_iter()
                    .find(|(n, _)| *n == disk);
                match existing {
                    Some((_, p)) if fluxvm_qemu::disks::is_external(&p) => {
                        skipped.push(serde_json::json!({"name": disk, "reason": "attached from an existing image"}));
                        continue;
                    }
                    Some((_, p)) if p.extension().is_some_and(|x| x == "qcow2") => p,
                    Some((_, p)) => {
                        skipped.push(serde_json::json!({"name": disk, "reason": format!("not a qcow2 disk: {}", p.display())}));
                        continue;
                    }
                    None => {
                        let dir = fluxvm_qemu::disks::disks_dir(&vm.workspace);
                        fs::create_dir_all(&dir)?;
                        dir.join(format!("{disk}.qcow2"))
                    }
                }
            };
            self.copy_backup_disk(&src, &dst).await?;
            restored.push(disk);
        }
        audit_event(
            "vm.backup.restore",
            &[("vm_id", &id.to_string()), ("backup", name)],
        );
        Ok(serde_json::json!({
            "vm_id": id,
            "backup": name,
            "restored": restored,
            "skipped": skipped,
        }))
    }

    /// Copies a standalone backup qcow2 over `dst` via a temp file in the
    /// same directory, so a failed copy leaves `dst` untouched.
    async fn copy_backup_disk(&self, src: &Path, dst: &Path) -> Result<()> {
        let mut tmp = dst.as_os_str().to_owned();
        tmp.push(".restore");
        let tmp = PathBuf::from(tmp);
        let out = tokio::process::Command::new(&self.cfg.qemu_img_binary)
            .args(["convert", "-O", "qcow2"])
            .arg(src)
            .arg(&tmp)
            .output()
            .await
            .with_context(|| format!("running {}", self.cfg.qemu_img_binary))?;
        if !out.status.success() {
            let _ = fs::remove_file(&tmp);
            bail!(
                "restoring {}: {}",
                dst.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        fs::rename(&tmp, dst).with_context(|| format!("replacing {}", dst.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_names_stay_inside_the_backups_dir() {
        assert!(validate_backup_name("web-20260101T000000Z.qcow2").is_ok());
        for bad in ["", "..", ".hidden", "a/b", "x.qcow2.json", "a\\b"] {
            assert!(validate_backup_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn lists_file_and_dir_backups_with_their_metadata() {
        let tmp = std::env::temp_dir().join(format!("fluxvm-backups-{}", Uuid::new_v4()));
        fs::create_dir_all(tmp.join("db-1")).unwrap();
        fs::write(tmp.join("db-1/root.qcow2"), b"xx").unwrap();
        fs::write(tmp.join("db-1/data.qcow2"), b"yyy").unwrap();
        fs::write(
            sidecar_path(&tmp.join("db-1"), true),
            br#"{"vm_name":"db","quiesced":true}"#,
        )
        .unwrap();
        fs::write(tmp.join("web-1.qcow2"), b"z").unwrap();
        fs::write(tmp.join("stray.txt"), b"").unwrap();

        let list = list_backups(&tmp);
        assert_eq!(list.len(), 2);
        let db = list.iter().find(|b| b["name"] == "db-1").unwrap();
        assert_eq!(db["kind"], "dir");
        assert_eq!(db["quiesced"], true);
        let web = list.iter().find(|b| b["name"] == "web-1.qcow2").unwrap();
        assert_eq!(web["kind"], "file");
        assert_eq!(web["size_bytes"], 1);

        let disks = backup_disks(&tmp.join("db-1")).unwrap();
        assert_eq!(
            disks.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["data", "root"]
        );
        fs::remove_file(tmp.join("db-1/root.qcow2")).unwrap();
        assert!(backup_disks(&tmp.join("db-1")).is_err());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
