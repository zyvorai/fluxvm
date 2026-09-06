// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OCI → raw rootfs export for FluxVm templates.

use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::process::Command;

/// Export `image_ref` (e.g. `docker.io/library/alpine:3.20`) to a sparse raw
/// disk image at `out` using `skopeo` + `umoci` when available, else treat
/// `image_ref` as a local tar path and unpack with `tar`.
pub async fn export_rootfs_raw(image_ref: &str, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let work = out.with_extension("oci-work");
    let _ = tokio::fs::remove_dir_all(&work).await;
    tokio::fs::create_dir_all(&work).await?;

    if Path::new(image_ref).exists() {
        // Local tar/rootfs archive.
        let status = Command::new("tar")
            .args(["-xf", image_ref, "-C"])
            .arg(&work)
            .status()
            .await
            .context("running tar")?;
        if !status.success() {
            bail!("tar extract failed for {image_ref}");
        }
    } else {
        let oci_dir = work.join("oci");
        let status = Command::new("skopeo")
            .args([
                "copy",
                &format!("docker://{image_ref}"),
                &format!("oci:{}", oci_dir.display()),
            ])
            .status()
            .await;
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => bail!("skopeo copy failed with {s}"),
            Err(e) => bail!(
                "skopeo not available ({e}); pass a local rootfs tar path as image_ref, or install skopeo"
            ),
        }
        let unpack = work.join("rootfs");
        let status = Command::new("umoci")
            .args([
                "unpack",
                "--image",
                &format!("{}:latest", oci_dir.display()),
            ])
            .arg(&unpack)
            .status()
            .await;
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => bail!("umoci unpack failed with {s}"),
            Err(e) => bail!("umoci not available ({e})"),
        }
        // Prefer unpacked rootfs dir for imaging.
        let root = unpack.join("rootfs");
        if root.is_dir() {
            // Create a modest ext4 raw image via mkfs + copy — requires root on Linux.
            let size = "2G";
            let status = Command::new("truncate")
                .args(["-s", size])
                .arg(out)
                .status()
                .await
                .context("truncate")?;
            if !status.success() {
                bail!("truncate failed");
            }
            let status = Command::new("mkfs.ext4")
                .args(["-F", "-d"])
                .arg(&root)
                .arg(out)
                .status()
                .await
                .context("mkfs.ext4")?;
            if !status.success() {
                bail!("mkfs.ext4 -d failed (needs privileges on Linux)");
            }
            let _ = tokio::fs::remove_dir_all(&work).await;
            return Ok(());
        }
    }

    // Fallback: pack work dir into a tar-as-raw placeholder file for CI/dev.
    let status = Command::new("tar")
        .args(["-cf"])
        .arg(out)
        .arg("-C")
        .arg(&work)
        .arg(".")
        .status()
        .await
        .context("tar pack fallback")?;
    if !status.success() {
        bail!("failed to pack rootfs to {}", out.display());
    }
    let _ = tokio::fs::remove_dir_all(&work).await;
    Ok(())
}
