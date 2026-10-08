// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Delete-intent journal (`<state_dir>/journal/delete-<vm_id>.json`).
//!
//! `delete()` removes the VM record before it reclaims the resources the
//! record points at (workspace, jail tree, LVM snapshot). A crash in between
//! leaves those resources with nothing that names them. Before the record is
//! removed, `delete()` writes an intent here; it clears the intent once the
//! cleanup finished. `reconcile()` rolls any leftover intent forward.
//!
//! Every step a replay performs is idempotent, so a crash during the replay
//! is also safe.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeleteIntent {
    pub vm_id: Uuid,
    pub workspace: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jail_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lvm_lv: Option<PathBuf>,
}

fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("journal")
}

fn intent_path(state_dir: &Path, vm_id: Uuid) -> PathBuf {
    dir(state_dir).join(format!("delete-{vm_id}.json"))
}

/// Durably records `intent`. Returns only after the file and its directory
/// entry are on disk.
pub fn begin_delete(state_dir: &Path, intent: &DeleteIntent) -> Result<()> {
    let d = dir(state_dir);
    fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    let path = intent_path(state_dir, intent.vm_id);
    let tmp = path.with_extension("json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec(intent)?)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, &path)?;
    fs::File::open(&d)?.sync_all()?;
    Ok(())
}

/// Clears the intent once the cleanup is complete. Missing is fine.
pub fn finish_delete(state_dir: &Path, vm_id: Uuid) -> Result<()> {
    match fs::remove_file(intent_path(state_dir, vm_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Intents left behind by a crashed `delete()`. Unreadable files are skipped
/// (a torn `.tmp` is never picked up: only `delete-*.json` is listed).
pub fn pending_deletes(state_dir: &Path) -> Vec<DeleteIntent> {
    let Ok(rd) = fs::read_dir(dir(state_dir)) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("delete-") && n.ends_with(".json")
        })
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
        .collect()
}

/// Removes `path` if present. Idempotent.
pub fn remove_tree(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(ws: &Path) -> DeleteIntent {
        DeleteIntent {
            vm_id: Uuid::new_v4(),
            workspace: ws.to_path_buf(),
            jail_path: None,
            lvm_lv: None,
        }
    }

    #[test]
    fn intent_round_trips_and_clears() {
        let td = tempfile::tempdir().unwrap();
        let i = intent(&td.path().join("ws"));
        begin_delete(td.path(), &i).unwrap();
        assert_eq!(pending_deletes(td.path()), vec![i.clone()]);
        finish_delete(td.path(), i.vm_id).unwrap();
        assert!(pending_deletes(td.path()).is_empty());
        // Clearing twice is fine.
        finish_delete(td.path(), i.vm_id).unwrap();
    }

    #[test]
    fn torn_tmp_file_is_ignored() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir(td.path())).unwrap();
        fs::write(dir(td.path()).join("delete-x.json.tmp"), b"{\"vm_id\"").unwrap();
        fs::write(dir(td.path()).join("delete-y.json"), b"not json").unwrap();
        assert!(pending_deletes(td.path()).is_empty());
    }

    #[test]
    fn remove_tree_is_idempotent() {
        let td = tempfile::tempdir().unwrap();
        let ws = td.path().join("ws");
        fs::create_dir_all(ws.join("a")).unwrap();
        remove_tree(&ws).unwrap();
        remove_tree(&ws).unwrap();
        assert!(!ws.exists());
    }
}
