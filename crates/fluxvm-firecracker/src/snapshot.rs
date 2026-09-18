// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Pause → Firecracker `/snapshot/create` → resume (and restore via `/snapshot/load`).

use anyhow::{Context, Result, bail};
use fluxvm_core::{config::Config, model::VmRecord, process::spawn_logged};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::http;

const API_TIMEOUT: Duration = Duration::from_secs(30);

fn control_socket(vm: &VmRecord) -> Result<&Path> {
    vm.control_socket
        .as_deref()
        .context("Firecracker VM has no control socket recorded")
}

/// Pause, write `vmstate` + `memory` under `dest`, resume. Mirrors Cloud
/// Hypervisor's pause/snapshot/resume error reporting.
pub async fn snapshot_save(_cfg: &Config, vm: &VmRecord, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)
        .with_context(|| format!("creating snapshot dir {}", dest.display()))?;
    let sock = control_socket(vm)?;
    let vmstate = dest.join("vmstate");
    let memory = dest.join("memory");

    http::request(
        sock,
        "PATCH",
        "/vm",
        Some(&json!({"state": "Paused"})),
        API_TIMEOUT,
    )
    .await
    .context("pausing Firecracker before snapshot")?;

    let snapshot_result = http::request(
        sock,
        "PUT",
        "/snapshot/create",
        Some(&json!({
            "snapshot_type": "Full",
            "snapshot_path": vmstate.display().to_string(),
            "mem_file_path": memory.display().to_string()
        })),
        API_TIMEOUT,
    )
    .await;

    if let Err(resume_err) = http::request(
        sock,
        "PATCH",
        "/vm",
        Some(&json!({"state": "Resumed"})),
        API_TIMEOUT,
    )
    .await
    {
        return match snapshot_result {
            Ok(_) => Err(resume_err).context(
                "snapshot saved, but the VM failed to resume afterward and is now paused, not running",
            ),
            Err(snapshot_err) => Err(snapshot_err.context(format!(
                "snapshot failed, and the VM also failed to resume afterward: {resume_err}"
            ))),
        };
    }
    snapshot_result.context("Firecracker /snapshot/create")?;
    Ok(())
}

/// Paths written by [`snapshot_save`].
pub fn snapshot_paths(dest: &Path) -> (PathBuf, PathBuf) {
    (dest.join("vmstate"), dest.join("memory"))
}

pub fn assert_snapshot_dir(dest: &Path) -> Result<()> {
    let (vmstate, memory) = snapshot_paths(dest);
    if !vmstate.exists() {
        bail!("Firecracker snapshot missing vmstate at {}", vmstate.display());
    }
    if !memory.exists() {
        bail!("Firecracker snapshot missing memory at {}", memory.display());
    }
    Ok(())
}

/// Spawn a fresh Firecracker process and `/snapshot/load` from `dest`.
/// Returns (pid, api socket path). Does not use the jailer (restore path).
pub async fn snapshot_restore(
    cfg: &Config,
    workspace: &Path,
    dest: &Path,
    log_path: &Path,
    vsock_uds: Option<&Path>,
    netns: Option<&str>,
) -> Result<(u32, PathBuf)> {
    assert_snapshot_dir(dest)?;
    let (vmstate, memory) = snapshot_paths(dest);
    let api = workspace.join("firecracker.sock");
    let _ = fs::remove_file(&api);

    let args = vec!["--api-sock".into(), api.display().to_string()];
    let (program, args) = fluxvm_core::process::netns_wrap(netns, &cfg.firecracker_binary, &args);
    let child = spawn_logged(&program, &args, log_path).await?;
    let pid = child
        .id()
        .context("Firecracker exited before PID was available")?;

    let deadline = tokio::time::Instant::now() + API_TIMEOUT;
    loop {
        if tokio::time::Instant::now() > deadline {
            bail!("Firecracker API not ready for snapshot load");
        }
        if api.exists()
            && http::request(&api, "GET", "/", None, Duration::from_millis(200))
                .await
                .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut body = json!({
        "snapshot_path": vmstate.display().to_string(),
        "mem_file_path": memory.display().to_string(),
        "resume_vm": true
    });
    if let Some(uds) = vsock_uds {
        body.as_object_mut()
            .unwrap()
            .insert("uds_path".into(), json!(uds.display().to_string()));
    }
    http::request(&api, "PUT", "/snapshot/load", Some(&body), API_TIMEOUT)
        .await
        .context("Firecracker /snapshot/load")?;
    Ok((pid, api))
}
