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
//!
//! The same directory also holds *operation intents* for create, snapshot,
//! fork and restore (`<op>-<op_id>.json`, see [`OpIntent`]). Those are
//! written before the operation allocates anything, list every resource it
//! may have allocated, and are cleared when the operation finishes.
//! `reconcile()` rolls back whatever a dead owner left behind
//! (`recovery.rs`).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
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

/// Which mutating operation an [`OpIntent`] belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpKind {
    Create,
    Snapshot,
    Fork,
    Restore,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Snapshot => "snapshot",
            Self::Fork => "fork",
            Self::Restore => "restore",
        }
    }

    const ALL: [OpKind; 4] = [Self::Create, Self::Snapshot, Self::Fork, Self::Restore];
}

/// A host resource an operation may have allocated. Names are recorded
/// *before* the allocation they describe, so a crash at any point leaves a
/// complete list of what could exist. Rollback re-validates every entry
/// (`recovery.rs`) before touching the host: a journal file is trusted only
/// for resources that are clearly FluxVM's own.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    /// `<state_dir>/instances/<vm id>`.
    Workspace { path: PathBuf },
    /// Per-VM network namespace (`eph-<short id>`).
    Netns { name: String },
    /// Host-namespace tap the daemon names itself (`eph<short id>`).
    Tap { name: String },
    /// `/dev/<vg>/eph-<short id>` thin snapshot.
    LvmLv { path: PathBuf },
    /// `<pool>/eph-<short id>` RBD clone.
    CephClone { pool_image: String },
    /// A `qemu-nbd` export. `start_time` is the `/proc/<pid>/stat` start
    /// time captured right after it was spawned; rollback kills the pid
    /// only when the live process still has exactly that start time.
    NbdPid { pid: u32, start_time: Option<u64> },
    /// `<workspace>/snapshots/<tag>`, only when this operation creates it.
    SnapshotDir { path: PathBuf },
    /// A fork child VM id, recorded before its workspace is created.
    ForkChild { vm_id: Uuid },
    /// A temporary file the operation renames into place (`*.restore.tmp`).
    TempFile { path: PathBuf },
}

/// One in-flight mutating operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpIntent {
    pub op: OpKind,
    /// Unique per operation. For `Create` this is the new VM's id.
    pub op_id: Uuid,
    /// The VM the operation acts on (the parent, for fork and snapshot).
    pub vm_id: Uuid,
    pub started_at: DateTime<Utc>,
    /// Process that owns the operation. `0` marks it abandoned (the owning
    /// future was dropped or failed before it could clean up).
    #[serde(default)]
    pub owner_pid: u32,
    /// `/proc/<owner_pid>/stat` start time; guards against pid reuse.
    #[serde(default)]
    pub owner_start: Option<u64>,
    /// Failed rollback attempts so far; bounded so a resource that can never
    /// be removed does not pin the intent forever.
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub resources: Vec<Resource>,
}

/// Rollback gives up (and clears the intent, with an error log) after this
/// many failed attempts.
pub const MAX_ROLLBACK_ATTEMPTS: u32 = 5;

fn op_path(state_dir: &Path, op: OpKind, op_id: Uuid) -> PathBuf {
    dir(state_dir).join(format!("{}-{op_id}.json", op.as_str()))
}

/// Start time (clock ticks since boot) of `pid`, from `/proc/<pid>/stat`
/// field 22. `None` when `/proc` has no such process (or no `/proc`).
pub fn proc_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat_start_time(&stat)
}

/// Field 22 of a `/proc/<pid>/stat` line. The command name (field 2) may
/// contain spaces and parentheses, so parsing starts after the last `)`.
pub fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // `rest` starts at field 3 (state); starttime is field 22.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// True when the process that owns an intent may still be running it.
pub fn owner_alive(pid: u32, start: Option<u64>) -> bool {
    if pid == 0 {
        return false;
    }
    if let Some(cur) = proc_start_time(pid) {
        return start.is_none_or(|s| s == cur);
    }
    // SAFETY: signal 0 only probes for existence.
    let r = unsafe { libc::kill(pid as i32, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn write_op(state_dir: &Path, intent: &OpIntent) -> Result<()> {
    let d = dir(state_dir);
    fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    let path = op_path(state_dir, intent.op, intent.op_id);
    let tmp = path.with_extension("json.tmp");
    fluxvm_storage::write_durable(&tmp, &path, &serde_json::to_vec(intent)?)
        .with_context(|| format!("writing {}", path.display()))
}

fn read_op(state_dir: &Path, op: OpKind, op_id: Uuid) -> Result<OpIntent> {
    let path = op_path(state_dir, op, op_id);
    let raw = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Replaces an intent on disk (used by rollback to count attempts).
pub fn update_op(state_dir: &Path, intent: &OpIntent) -> Result<()> {
    write_op(state_dir, intent)
}

/// Removes an intent. Missing is fine.
pub fn finish_op(state_dir: &Path, op: OpKind, op_id: Uuid) -> Result<()> {
    match fs::remove_file(op_path(state_dir, op, op_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Every parseable operation intent (create, snapshot, fork, restore). Torn
/// `.tmp` files and unparseable files are skipped.
pub fn pending_ops(state_dir: &Path) -> Vec<OpIntent> {
    let Ok(rd) = fs::read_dir(dir(state_dir)) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.ends_with(".json")
                && OpKind::ALL
                    .iter()
                    .any(|k| n.starts_with(&format!("{}-", k.as_str())))
        })
        .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
        .collect()
}

/// RAII handle for one journaled operation.
///
/// * `finish()` clears the intent: the operation completed, or cleaned up
///   after itself.
/// * Dropping the guard any other way (an early `?`, a cancelled request
///   future, a panic) marks the intent *abandoned* instead of clearing it,
///   so the next `reconcile()` rolls the leftovers back.
/// * A crash runs neither; the intent then names a dead owner and
///   `reconcile()` treats it the same way.
pub struct OpGuard {
    state_dir: PathBuf,
    op: OpKind,
    op_id: Uuid,
    finished: bool,
}

impl OpGuard {
    /// Durably records the intent, with `resources` that may be allocated.
    pub fn begin(
        state_dir: &Path,
        op: OpKind,
        op_id: Uuid,
        vm_id: Uuid,
        resources: Vec<Resource>,
    ) -> Result<Self> {
        let pid = std::process::id();
        write_op(
            state_dir,
            &OpIntent {
                op,
                op_id,
                vm_id,
                started_at: Utc::now(),
                owner_pid: pid,
                owner_start: proc_start_time(pid),
                attempts: 0,
                resources,
            },
        )?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            op,
            op_id,
            finished: false,
        })
    }

    /// Appends `resource` to the intent (durably) before it is allocated.
    pub fn record(&self, resource: Resource) -> Result<()> {
        let mut intent = read_op(&self.state_dir, self.op, self.op_id)?;
        if !intent.resources.contains(&resource) {
            intent.resources.push(resource);
            write_op(&self.state_dir, &intent)?;
        }
        Ok(())
    }

    /// Clears the intent: nothing is left to roll back.
    pub fn finish(mut self) {
        self.finished = true;
        if let Err(e) = finish_op(&self.state_dir, self.op, self.op_id) {
            tracing::warn!(op = self.op.as_str(), id = %self.op_id, error = %e, "clearing journal intent failed");
        }
    }
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Hand the intent to reconcile(): owner 0 is "abandoned, roll back now".
        if let Ok(mut intent) = read_op(&self.state_dir, self.op, self.op_id) {
            intent.owner_pid = 0;
            intent.owner_start = None;
            let _ = write_op(&self.state_dir, &intent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_start_time_survives_odd_command_names() {
        let line = "42 (we ird) name)) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        assert_eq!(parse_stat_start_time(line), Some(987654));
        assert_eq!(parse_stat_start_time("garbage"), None);
    }

    #[test]
    fn owner_liveness() {
        assert!(!owner_alive(0, None));
        assert!(owner_alive(std::process::id(), None));
        // Same pid, different start time: the pid was reused.
        if let Some(start) = proc_start_time(std::process::id()) {
            assert!(owner_alive(std::process::id(), Some(start)));
            assert!(!owner_alive(std::process::id(), Some(start + 1)));
        }
    }

    #[test]
    fn op_guard_records_resources_and_clears() {
        let td = tempfile::tempdir().unwrap();
        let (op_id, vm) = (Uuid::new_v4(), Uuid::new_v4());
        let ws = Resource::Workspace {
            path: td.path().join("instances").join(op_id.to_string()),
        };
        let g = OpGuard::begin(td.path(), OpKind::Create, op_id, vm, vec![ws.clone()]).unwrap();
        g.record(Resource::Netns {
            name: "eph-deadbeef".into(),
        })
        .unwrap();
        // Recording the same resource twice is a no-op.
        g.record(ws.clone()).unwrap();
        let ops = pending_ops(td.path());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, OpKind::Create);
        assert_eq!(ops[0].resources.len(), 2);
        assert_eq!(ops[0].owner_pid, std::process::id());
        g.finish();
        assert!(pending_ops(td.path()).is_empty());
    }

    #[test]
    fn dropped_guard_marks_intent_abandoned() {
        let td = tempfile::tempdir().unwrap();
        let op_id = Uuid::new_v4();
        {
            let _g =
                OpGuard::begin(td.path(), OpKind::Snapshot, op_id, Uuid::new_v4(), vec![]).unwrap();
        }
        let ops = pending_ops(td.path());
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].owner_pid, 0);
        assert!(!owner_alive(ops[0].owner_pid, ops[0].owner_start));
    }

    #[test]
    fn ops_and_delete_intents_do_not_mix() {
        let td = tempfile::tempdir().unwrap();
        let d = intent(&td.path().join("ws"));
        begin_delete(td.path(), &d).unwrap();
        let g = OpGuard::begin(td.path(), OpKind::Fork, Uuid::new_v4(), d.vm_id, vec![]).unwrap();
        assert_eq!(pending_deletes(td.path()).len(), 1);
        assert_eq!(pending_ops(td.path()).len(), 1);
        g.finish();
        assert_eq!(pending_deletes(td.path()).len(), 1);
        assert!(pending_ops(td.path()).is_empty());
    }

    #[test]
    fn torn_op_files_are_ignored() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir(td.path())).unwrap();
        fs::write(dir(td.path()).join("create-x.json.tmp"), b"{").unwrap();
        fs::write(dir(td.path()).join("fork-y.json"), b"not json").unwrap();
        assert!(pending_ops(td.path()).is_empty());
    }

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
