// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::SnapshotSpec;
use crate::state::{VmLifecycle, VmState};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Save a full template: Firecracker memory+vmstate snapshot + FICLONE of rootfs.
pub async fn save(st: &VmState, path: &Path) -> Result<()> {
    let boot = st.boot.as_ref().context("no boot config to snapshot")?;
    let guest = st.guest.as_ref().context("no live guest to snapshot")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let disk_snap = path.with_extension("rootfs");
    let mem_snap = path.with_extension("mem");
    let vmstate = path.with_extension("vmstate");

    // Guest must be paused (caller should have paused; ensure here).
    guest.pause().await.ok();
    guest
        .snapshot_create(&vmstate, &mem_snap)
        .await
        .context("guest snapshot/create")?;

    clone_cow(&boot.rootfs, &disk_snap)
        .with_context(|| format!("cloning rootfs to {}", disk_snap.display()))?;

    let mut boot = boot.clone();
    boot.rootfs = disk_snap.clone();
    let spec = SnapshotSpec {
        memory_path: mem_snap,
        disk_path: disk_snap,
        vmstate_path: Some(vmstate),
        boot,
    };
    fs::write(path, serde_json::to_vec_pretty(&spec)?)?;
    Ok(())
}

/// Load snapshot metadata only (caller reboots/restores guest).
pub fn load_spec(path: &Path) -> Result<SnapshotSpec> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading snapshot {}", path.display()))?;
    let spec: SnapshotSpec = serde_json::from_str(&raw)?;
    if !spec.disk_path.exists() {
        bail!("snapshot disk missing: {}", spec.disk_path.display());
    }
    if let Some(vs) = &spec.vmstate_path {
        if !vs.exists() {
            bail!("snapshot vmstate missing: {}", vs.display());
        }
    }
    if !spec.memory_path.exists() {
        bail!("snapshot memory missing: {}", spec.memory_path.display());
    }
    Ok(spec)
}

pub async fn restore_meta(st: &mut VmState, path: &Path) -> Result<SnapshotSpec> {
    let spec = load_spec(path)?;
    st.boot = Some(spec.boot.clone());
    st.lifecycle = VmLifecycle::Created;
    st.touch();
    Ok(spec)
}

/// Prefer `cp --reflink=auto`; fall back to plain copy.
pub fn clone_cow(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    let status = Command::new("cp")
        .args(["--reflink=auto", "--sparse=always"])
        .arg(src)
        .arg(dst)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            fs::copy(src, dst)?;
            Ok(())
        }
    }
}
