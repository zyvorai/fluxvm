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

pub use capability::{
    CAPABILITIES, Capability, validate_request, with_guest_reporting, with_shared_folder_mounts,
};
pub use control::{ControlReply, call as control_call};
pub use runner::{ForwardConfig, RunnerConfig, ShareConfig, find_runner, ip_file, read_guest_ip};

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
        validate_request(req)?;
        let guest = req.apple.as_ref().map(|a| a.guest_os).unwrap_or_default();
        if guest == AppleGuest::Macos && !ctx.workspace.join("hardware.bin").exists() {
            bail!(
                "macOS guests must be installed from an IPSW before their first boot (`fluxvm-apple` install step); this VM has no hardware identity yet"
            );
        }
        let runner = find_runner()?;
        let conf = RunnerConfig::for_launch(req, ctx)?;
        let conf_path = conf.write(&ctx.workspace)?;
        // A restarted VM must not report the previous boot's address.
        let _ = std::fs::remove_file(ip_file(&ctx.workspace));
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
