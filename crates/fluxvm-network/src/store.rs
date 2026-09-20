// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Shared plumbing for the small node-local JSON stores under `network-groups/` (`pod-ids.json`,
//! `ipcache.json`).
//!
//! Every VM create reads, edits and rewrites these files. Two Pods created at the same instant used to
//! race twice over: both wrote one fixed `*.json.tmp`, so the loser's `rename` failed with a bare
//! ENOENT and its VM create was rejected (a Secure Containers Pod then fell back to the bridge chain, or
//! failed outright in `direct` mode); and the read-modify-write cycles could drop each other's
//! updates. [`STORE_LOCK`] serializes the cycles inside the daemon and [`write_atomic`] never shares a
//! temp file.

use std::{
    fs,
    io::Write,
    path::Path,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

static STORE_LOCK: Mutex<()> = Mutex::new(());
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Held across one whole load -> modify -> save cycle.
pub(crate) fn lock() -> MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Writes `bytes` to `path` through a uniquely named temp file in the same directory, then renames it
/// into place, so readers see the old or the new content and concurrent writers never collide.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "store".into());
    let tmp = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
