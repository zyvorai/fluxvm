// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Shared `virtiofsd` spawn helpers for QEMU and Cloud Hypervisor.
//!
//! Both backends speak the same vhost-user virtiofsd socket protocol. The
//! VMM-specific piece is only how the socket is attached (`-device
//! vhost-user-fs-pci` vs `--fs tag=,socket=`).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::backend::{LaunchContext, path_arg};
use crate::config::Config;
use crate::model::CreateVmRequest;
use crate::process::{spawn_logged, wait_for_socket_ready};

const VIRTIOFSD_SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

/// One ready virtiofsd: guest tag + Unix socket path.
pub type VirtiofsSocket = (String, PathBuf);

fn kill_pids(pids: &[u32]) {
    for pid in pids {
        unsafe {
            libc::kill(*pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

/// Starts one `virtiofsd` serving `host_path` on `workspace/virtiofs-{index}.sock`.
pub async fn spawn_virtiofsd_one(
    cfg: &Config,
    workspace: &Path,
    index: usize,
    host_path: &Path,
) -> Result<(u32, PathBuf)> {
    let socket = workspace.join(format!("virtiofs-{index}.sock"));
    let _ = tokio::fs::remove_file(&socket).await;
    let args = vec![
        "--sandbox".to_string(),
        "none".to_string(),
        "--seccomp".to_string(),
        "none".to_string(),
        "--socket-path".to_string(),
        path_arg(&socket),
        "--shared-dir".to_string(),
        path_arg(host_path),
    ];
    let log = workspace.join(format!("virtiofsd-{index}.log"));
    let child = spawn_logged(&cfg.virtiofsd_binary, &args, &log)
        .await
        .with_context(|| {
            format!(
                "spawning virtiofsd for shared_folders[{index}] ({})",
                host_path.display()
            )
        })?;
    let Some(pid) = child.id() else {
        anyhow::bail!("virtiofsd for shared_folders[{index}] exited before PID was available");
    };
    if let Err(e) = wait_for_socket_ready(
        pid,
        &socket,
        VIRTIOFSD_SOCKET_TIMEOUT,
        &format!("virtiofsd for shared_folders[{index}]"),
        &log,
    )
    .await
    {
        kill_pids(&[pid]);
        return Err(e);
    }
    Ok((pid, socket))
}

/// Spawns one `virtiofsd` per `req.shared_folders` entry (tags `fs0`, `fs1`, …).
/// On failure, already-spawned instances from this call are killed.
pub async fn spawn_virtiofsd_instances(
    cfg: &Config,
    req: &CreateVmRequest,
    ctx: &LaunchContext,
) -> Result<(Vec<u32>, Vec<VirtiofsSocket>)> {
    let mut pids = Vec::new();
    let mut sockets = Vec::new();
    for (i, share) in req.shared_folders.iter().enumerate() {
        match spawn_virtiofsd_one(cfg, &ctx.workspace, i, &share.host_path).await {
            Ok((pid, socket)) => {
                pids.push(pid);
                sockets.push((format!("fs{i}"), socket));
            }
            Err(e) => {
                kill_pids(&pids);
                return Err(e);
            }
        }
    }
    Ok((pids, sockets))
}

/// SIGKILL every pid in `pids` (best-effort).
pub fn terminate_virtiofsd_pids(pids: &[u32]) {
    kill_pids(pids);
}
