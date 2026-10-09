// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Apple Virtualization.framework backend for FluxVM (`backend: "vz"`).
//!
//! The daemon never links Virtualization.framework. Each VM is run by a small signed helper,
//! `fluxvm-vz-runner` (see `runner/Runner.swift`), which the backend supervises over a unix control
//! socket (one JSON line per request). See `docs/macos.md` for the contract and the capability matrix.

mod capability;
mod control;
mod runner;
pub mod ssh;

pub use capability::{
    CAPABILITIES, Capability, validate_request, with_egress_forwarder, with_guest_reporting,
    with_shared_folder_mounts,
};
pub use control::{ControlReply, call as control_call, call_with as control_call_with};
pub use runner::{
    ForwardConfig, RunnerConfig, SNAPSHOT_FILES, STATE_FILE, ShareConfig, adopt_macos_template,
    clone_file, find_runner, ip_file, read_guest_ip, snapshot_dir,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend},
    config::Config,
    model::{AppleGuest, BackendKind, CreateVmRequest, VmRecord},
};
use std::time::Duration;

/// How long `launch` waits for the runner to report a running guest.
const START_TIMEOUT: Duration = Duration::from_secs(120);

pub struct AppleBackend;

#[async_trait]
impl VmBackend for AppleBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vz
    }

    async fn launch(
        &self,
        _cfg: &Config,
        req: &CreateVmRequest,
        ctx: &LaunchContext,
    ) -> Result<LaunchResult> {
        // `loadvm_tag` is how the scheduler asks for a restore; creation still rejects it (see `validate_request`).
        validate_request(&CreateVmRequest {
            loadvm_tag: None,
            ..req.clone()
        })?;
        if let Some(tag) = &req.loadvm_tag {
            restore_files(&ctx.workspace, &ctx.disk, tag)?;
        }
        let guest = req.apple.as_ref().map(|a| a.guest_os).unwrap_or_default();
        if guest == AppleGuest::Macos
            && !ctx.workspace.join("hardware.bin").exists()
            && !adopt_macos_template(&req.image, &ctx.workspace)?
        {
            bail!(
                "a macOS guest needs a prepared template: set `image` to the disk.raw of an installed guest (its hardware.bin and auxiliary.bin must sit beside it). Installing one from an IPSW is not available through the API yet"
            );
        }
        let runner = find_runner()?;
        let conf = RunnerConfig::for_launch(req, ctx)?;
        let conf_path = conf.write(&ctx.workspace)?;
        // A restarted VM must not report the previous boot's address.
        // (A restore keeps it: the restored guest does not announce its address again.)
        if req.loadvm_tag.is_none() {
            let _ = std::fs::remove_file(ip_file(&ctx.workspace));
        }
        let log = runner::open_runner_log(&ctx.workspace)?;
        let mut cmd = tokio::process::Command::new(&runner);
        cmd.args(["run", "--config"]).arg(&conf_path);
        cmd.stdin(std::process::Stdio::null())
            .stdout(log.try_clone().context("cloning the runner log")?)
            .stderr(log)
            .process_group(0);
        let mut child = cmd
            .spawn()
            .with_context(|| format!("starting {}", runner.display()))?;
        let pid = child.id().context("runner exited immediately")?;

        // Ready = the control socket answers `status` with a running guest. A runner that exits first has failed.
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                bail!(
                    "the Apple runner exited ({status}): {}",
                    runner::tail_runner_log(&ctx.workspace)
                );
            }
            if let Ok(reply) = control_call(&conf.control_socket, "status").await
                && reply.state() == Some("running")
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = child.start_kill();
                bail!(
                    "the Apple runner did not report a running guest within {}s: {}",
                    START_TIMEOUT.as_secs(),
                    runner::tail_runner_log(&ctx.workspace)
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        // Reap the runner in the background; it outlives this call and is stopped through its control socket or SIGTERM.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        Ok(LaunchResult {
            pid,
            control_socket: Some(conf.control_socket.clone()),
            jail_path: None,
            vsock_socket: conf.vsock_socket.clone(),
            virtiofsd_pids: Vec::new(),
            swtpm_pid: None,
        })
    }

    async fn pause(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        send(vm, "pause").await
    }

    async fn resume(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        send(vm, "resume").await
    }

    async fn graceful_shutdown(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        send(vm, "shutdown").await
    }
}

async fn send(vm: &VmRecord, cmd: &str) -> Result<()> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let reply = control_call(sock, cmd)
        .await
        .with_context(|| format!("runner `{cmd}`"))?;
    if reply.ok() {
        Ok(())
    } else {
        bail!(
            "runner refused `{cmd}`: {}",
            reply.error().unwrap_or("unknown error")
        )
    }
}

/// Puts the disk and EFI variables from snapshot `tag` back in place, ahead of resuming the saved state.
fn restore_files(workspace: &std::path::Path, disk: &std::path::Path, tag: &str) -> Result<()> {
    let dir = snapshot_dir(workspace, tag);
    if !dir.join(STATE_FILE).is_file() {
        bail!("snapshot {tag:?} has no saved state at {}", dir.display());
    }
    for name in SNAPSHOT_FILES {
        let src = dir.join(name);
        let dst = if *name == "disk.raw" {
            disk.to_path_buf()
        } else {
            workspace.join(name)
        };
        if src.is_file() {
            clone_file(&src, &dst)?;
        }
    }
    Ok(())
}

/// Saves the running guest's memory and device state plus a matching copy of its disk under
/// `<workspace>/snapshots/<tag>/`. The guest is paused while both are taken, then continues if it was running.
pub async fn snapshot_save(vm: &VmRecord, tag: &str) -> Result<()> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let dir = snapshot_dir(&vm.workspace, tag);
    if dir.exists() {
        bail!("snapshot {tag:?} already exists for this VM");
    }
    std::fs::create_dir_all(&dir)?;
    let reply = control_call_with(
        sock,
        serde_json::json!({"cmd": "save", "path": dir.join(STATE_FILE)}),
    )
    .await
    .context("runner `save`");
    let was_running = reply.as_ref().is_ok_and(|r| r.ok() && r.was_running());
    let outcome: Result<()> = (|| {
        let reply = reply?;
        if !reply.ok() {
            bail!(
                "the runner could not save the VM: {}",
                reply.error().unwrap_or("unknown error")
            );
        }
        // The guest is paused, so these files match the saved memory exactly.
        clone_file(&vm.disk, &dir.join("disk.raw"))?;
        let efi = vm.workspace.join("efi.bin");
        if efi.is_file() {
            clone_file(&efi, &dir.join("efi.bin"))?;
        }
        Ok(())
    })();
    if was_running {
        // Even after a failure, the guest must not be left paused.
        let _ = send(vm, "resume").await;
    }
    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    outcome
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn restore_puts_the_snapshot_disk_and_efi_back() {
        let ws = tempfile::tempdir().unwrap();
        let dir = snapshot_dir(ws.path(), "s1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(STATE_FILE), b"state").unwrap();
        std::fs::write(dir.join("disk.raw"), b"disk at snapshot").unwrap();
        std::fs::write(dir.join("efi.bin"), b"efi at snapshot").unwrap();
        let disk = ws.path().join("disk.raw");
        std::fs::write(&disk, b"disk now").unwrap();
        std::fs::write(ws.path().join("efi.bin"), b"efi now").unwrap();
        restore_files(ws.path(), &disk, "s1").unwrap();
        assert_eq!(std::fs::read(&disk).unwrap(), b"disk at snapshot");
        assert_eq!(
            std::fs::read(ws.path().join("efi.bin")).unwrap(),
            b"efi at snapshot"
        );
    }

    #[test]
    fn restore_refuses_a_tag_without_saved_state() {
        let ws = tempfile::tempdir().unwrap();
        let err = restore_files(ws.path(), &ws.path().join("disk.raw"), "nope").unwrap_err();
        assert!(err.to_string().contains("no saved state"), "{err}");
    }
}
