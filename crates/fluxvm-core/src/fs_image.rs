// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Pack a host directory into a sparse ext4 image for Firecracker (no virtio-fs).

use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::process::Command;

/// Pack `src_dir` into a sparse ext4 raw image at `out`.
///
/// Uses `truncate` + `mkfs.ext4 -d` (needs privileges on Linux). `size` is a
/// truncate size string such as `"2G"` or `"512M"`.
pub async fn pack_directory_ext4(src_dir: &Path, out: &Path, size: &str) -> Result<()> {
    if !src_dir.is_dir() {
        bail!("{} is not a directory", src_dir.display());
    }
    if let Some(parent) = out.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let _ = tokio::fs::remove_file(out).await;
    let status = Command::new("truncate")
        .args(["-s", size])
        .arg(out)
        .status()
        .await
        .context("truncate")?;
    if !status.success() {
        bail!("truncate -s {size} {} failed", out.display());
    }
    let status = Command::new("mkfs.ext4")
        .args(["-F", "-d"])
        .arg(src_dir)
        .arg(out)
        .status()
        .await
        .context("mkfs.ext4")?;
    if !status.success() {
        let _ = tokio::fs::remove_file(out).await;
        bail!(
            "mkfs.ext4 -d {} {} failed (needs privileges on Linux)",
            src_dir.display(),
            out.display()
        );
    }
    Ok(())
}
