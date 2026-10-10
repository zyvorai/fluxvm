// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Apple Virtualization.framework backend for FluxVM (`backend: "vz"`).
//!
//! The daemon never links Virtualization.framework. Each VM is run by a small signed helper,
//! `fluxvm-vz-runner` (see `runner/Runner.swift`), which the backend supervises over a unix control
//! socket (one JSON line per request). See `docs/macos.md` for the contract and the capability matrix.

mod capability;
mod control;
mod host_caps;
pub mod macos_install;
mod runner;
pub mod ssh;
mod usb_passthrough;
pub mod vz27;
pub mod vznet;

pub use capability::{
    CAPABILITIES, Capability, validate_disk, validate_request, with_egress_forwarder,
    with_guest_reporting, with_shared_folder_mounts,
};
pub use control::{ControlReply, call as control_call, call_with as control_call_with};
pub use host_caps::{AppleHostCapabilities, host_capabilities};
pub use runner::{
    EGRESS_PORT, ForwardConfig, OneShotVm, RunnerConfig, SNAPSHOT_FILES, STATE_FILE, ShareConfig,
    adopt_macos_template, clone_file, console_port_socket, find_runner, ip_file, oci_meta_dir,
    read_guest_ip, release_mac, snapshot_dir, write_oci_meta_as,
};
pub use usb_passthrough::{physical_usb_attach, physical_usb_list};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend},
    config::Config,
    model::{AppleGuest, BackendKind, CreateVmRequest, VmRecord},
};
use serde::Deserialize;
use std::time::Duration;

/// Whether Rosetta is installed on this Mac (`softwareupdate --install-rosetta`); `apple.rosetta` fails without it.
pub fn rosetta_installed() -> bool {
    std::path::Path::new("/Library/Apple/usr/libexec/oah/libRosettaRuntime").exists()
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppleBalloonStatus {
    pub memory_mib: u64,
    pub target_mib: u64,
    pub actual_mib: u64,
}

pub async fn balloon_control(
    vm: &VmRecord,
    balloon_mib: Option<u64>,
) -> Result<AppleBalloonStatus> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let mut body = serde_json::json!({"cmd": "balloon"});
    if let Some(v) = balloon_mib {
        body["balloon_mib"] = serde_json::json!(v);
    }
    let reply = control_call_with(sock, body)
        .await
        .context("runner `balloon`")?;
    if !reply.ok() {
        bail!(
            "runner refused `balloon`: {}",
            reply.error().unwrap_or("unknown error")
        );
    }
    serde_json::from_value(reply.0).context("decoding Apple balloon response")
}

pub async fn usb_attach(vm: &VmRecord, path: &std::path::Path, read_only: bool) -> Result<String> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let reply = control_call_with(
        sock,
        serde_json::json!({"cmd":"usb-attach","path":path,"read_only":read_only}),
    )
    .await?;
    if !reply.ok() {
        bail!(
            "runner refused usb-attach: {}",
            reply.error().unwrap_or("unknown error")
        );
    }
    reply
        .0
        .get("uuid")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .context("usb-attach reply had no uuid")
}

pub async fn usb_detach(vm: &VmRecord, uuid: &str) -> Result<()> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let reply =
        control_call_with(sock, serde_json::json!({"cmd":"usb-detach","uuid":uuid})).await?;
    if reply.ok() {
        Ok(())
    } else {
        bail!(
            "runner refused usb-detach: {}",
            reply.error().unwrap_or("unknown error")
        )
    }
}

/// Points the running VM's virtiofs share `tag` at `path`.
pub async fn share_set(
    vm: &VmRecord,
    tag: &str,
    path: &std::path::Path,
    read_only: bool,
) -> Result<()> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let reply = control_call_with(
        sock,
        serde_json::json!({"cmd":"share-set","tag":tag,"path":path,"read_only":read_only}),
    )
    .await?;
    if reply.ok() {
        Ok(())
    } else {
        bail!(
            "runner refused share-set: {}",
            reply.error().unwrap_or("unknown error")
        )
    }
}

/// Hands a waiting warm-pool guest its [`Claim`](fluxvm_oci_init::config::Claim) over the runner's vsock proxy.
pub async fn warm_claim(
    vm: &VmRecord,
    port: u32,
    claim: &fluxvm_oci_init::config::Claim,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    claim.validate()?;
    let sock = vm
        .vsock_socket
        .as_deref()
        .context("VM has no vsock socket recorded")?;
    let talk = async {
        let s = tokio::net::UnixStream::connect(sock)
            .await
            .with_context(|| format!("connecting to {}", sock.display()))?;
        let mut s = BufReader::new(s);
        s.get_mut()
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .await?;
        let mut line = String::new();
        s.read_line(&mut line).await?;
        if !line.starts_with("OK") {
            bail!(
                "the guest is not listening on vsock port {port}: {}",
                line.trim()
            );
        }
        let mut body = serde_json::to_vec(claim)?;
        body.push(b'\n');
        s.get_mut().write_all(&body).await?;
        line.clear();
        s.read_line(&mut line).await?;
        match line.trim() {
            "ok" => Ok(()),
            "" => bail!("the guest closed the claim without answering"),
            other => bail!("the guest refused the claim: {other}"),
        }
    };
    tokio::time::timeout(Duration::from_secs(20), talk)
        .await
        .context("the guest did not answer the claim in 20s")?
}

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
        cfg: &Config,
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
        let installs_itself = macos_install::is_macos_install(req);
        let install =
            installs_itself && !ctx.workspace.join(macos_install::INSTALLED_MARKER).exists();
        if guest == AppleGuest::Macos
            && !installs_itself
            && !ctx.workspace.join("hardware.bin").exists()
            && !adopt_macos_template(&req.image, &ctx.workspace)?
        {
            bail!(
                "a macOS guest needs a prepared template (set `image` to the disk.raw of an installed guest, with its hardware.bin and auxiliary.bin beside it) or `apple.install: true` with an IPSW"
            );
        }
        if let Some(fb) = req.apple.as_ref().and_then(|a| a.firstboot.as_ref()) {
            macos_install::write_firstboot(&ctx.workspace, fb)?;
        }
        runner::write_oci_meta(req, &ctx.workspace)?;
        let runner = find_runner()?;
        let mut conf = RunnerConfig::for_launch(req, ctx)?;
        conf.serial_log_max_bytes = Some(cfg.apple.serial_log_max_mib.max(1) << 20);
        for net in &mut conf.networks {
            net.socket = vznet::ensure_switch(&net.name).await?;
            net.switch_bin = vznet::find_switch()?;
        }
        let conf_path = conf.write(&ctx.workspace)?;
        if install {
            macos_install::run_install(&runner, &conf_path, &ctx.workspace).await?;
        }
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

/// Clones the disk and every other present `SNAPSHOT_FILES` entry from the workspace into snapshot `dir`.
fn save_files(
    workspace: &std::path::Path,
    disk: &std::path::Path,
    dir: &std::path::Path,
) -> Result<()> {
    for name in SNAPSHOT_FILES {
        let src = if *name == "disk.raw" {
            disk.to_path_buf()
        } else {
            workspace.join(name)
        };
        if *name == "disk.raw" || src.is_file() {
            clone_file(&src, &dir.join(name))?;
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
        save_files(&vm.workspace, &vm.disk, &dir)
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
    fn restore_brings_back_the_asif_overlay_too() {
        let ws = tempfile::tempdir().unwrap();
        let dir = snapshot_dir(ws.path(), "s1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(STATE_FILE), b"state").unwrap();
        std::fs::write(dir.join("disk-overlay.asif"), b"overlay at snapshot").unwrap();
        std::fs::write(ws.path().join("disk-overlay.asif"), b"overlay now").unwrap();
        restore_files(ws.path(), &ws.path().join("disk.raw"), "s1").unwrap();
        assert_eq!(
            std::fs::read(ws.path().join("disk-overlay.asif")).unwrap(),
            b"overlay at snapshot"
        );
    }

    #[test]
    fn runner_balloon_reply_decodes() {
        let reply = ControlReply(serde_json::json!({
            "ok": true, "memory_mib": 8192, "target_mib": 2048, "actual_mib": 2048
        }));
        let s: AppleBalloonStatus = serde_json::from_value(reply.0).unwrap();
        assert_eq!(
            (s.memory_mib, s.target_mib, s.actual_mib),
            (8192, 2048, 2048)
        );
    }

    #[test]
    fn restore_refuses_a_tag_without_saved_state() {
        let ws = tempfile::tempdir().unwrap();
        let err = restore_files(ws.path(), &ws.path().join("disk.raw"), "nope").unwrap_err();
        assert!(err.to_string().contains("no saved state"), "{err}");
    }
}
