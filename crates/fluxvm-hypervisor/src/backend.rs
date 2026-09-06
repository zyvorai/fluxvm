// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::{ApiRequest, BootConfig};
use crate::control;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend},
    config::{Config, FluxVmEngine},
    model::{BackendKind, CreateVmRequest, NetworkSpec, VmRecord},
    process::{netns_wrap, spawn_logged_with_env},
};
use std::{fs, path::Path, time::Duration};

const API_TIMEOUT: Duration = Duration::from_secs(15);

pub struct FluxVmBackend;

#[async_trait]
impl VmBackend for FluxVmBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::FluxVm
    }

    async fn launch(
        &self,
        cfg: &Config,
        req: &CreateVmRequest,
        ctx: &LaunchContext,
    ) -> Result<LaunchResult> {
        let kernel = req
            .kernel
            .as_ref()
            .or(cfg.fluxvm_kernel.as_ref())
            .or(cfg.firecracker_kernel.as_ref())
            .context("FluxVm requires a Linux kernel via request.kernel, config.fluxvm_kernel, or config.firecracker_kernel")?;

        let api = ctx.workspace.join("fluxvm.sock");
        let _ = fs::remove_file(&api);

        let boot = BootConfig {
            kernel: kernel.clone(),
            rootfs: ctx.disk.clone(),
            initrd: None,
            seed: ctx.seed_disk.clone(),
            memory_mib: req.memory_mib,
            vcpus: req.vcpus,
            kernel_args: req
                .kernel_args
                .clone()
                .or_else(|| Some("console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw".into())),
            tap: match &ctx.network.spec {
                NetworkSpec::Tap {
                    tap_name: Some(t), ..
                } => Some(t.clone()),
                NetworkSpec::None => None,
                NetworkSpec::Tap { tap_name: None, .. } => bail!("tap network was not prepared"),
                NetworkSpec::Macvtap { .. } => bail!(
                    "FluxVm backend does not support macvtap yet; use network.mode=tap or none"
                ),
                NetworkSpec::User { .. } => {
                    bail!("FluxVm backend requires network.mode=none or tap")
                }
            },
            mac: match &ctx.network.spec {
                NetworkSpec::Tap { mac, .. } => mac.clone(),
                _ => None,
            },
            vsock_cid: ctx.guest_cid,
            vsock_uds: ctx.vsock_socket.clone(),
            // Firecracker applies its own seccomp to the guest VMM. A process-wide
            // KillProcess filter on the FluxVM control plane races with tokio and
            // prevents the API from answering Ping after boot starts.
            seccomp: matches!(cfg.fluxvm_engine, FluxVmEngine::Kvm),
            engine: match cfg.fluxvm_engine {
                FluxVmEngine::Firecracker => crate::api::FluxVmEngine::Firecracker,
                FluxVmEngine::Kvm => crate::api::FluxVmEngine::Kvm,
            },
        };

        let boot_path = ctx.workspace.join("fluxvm-boot.json");
        fs::write(&boot_path, serde_json::to_vec_pretty(&boot)?)?;

        let args = vec![
            "--api-sock".into(),
            api.display().to_string(),
            "--boot-config".into(),
            boot_path.display().to_string(),
        ];
        let (program, args) = netns_wrap(
            ctx.network.netns.as_deref(),
            &cfg.fluxvm_hypervisor_binary,
            &args,
        );
        let child = spawn_logged_with_env(
            &program,
            &args,
            &ctx.log_path,
            &[
                ("FLUXVM_FIRECRACKER_BINARY", cfg.firecracker_binary.as_str()),
                (
                    "FLUXVM_ENGINE",
                    match cfg.fluxvm_engine {
                        FluxVmEngine::Firecracker => "firecracker",
                        FluxVmEngine::Kvm => "kvm",
                    },
                ),
            ],
        )
        .await?;
        let pid = child
            .id()
            .context("fluxvm-hypervisor exited before PID was available")?;

        // Wait until the API answers Ping (boot may be in progress).
        let deadline = tokio::time::Instant::now() + API_TIMEOUT;
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("fluxvm-hypervisor API did not become ready within {API_TIMEOUT:?}");
            }
            match control::request(&api, &ApiRequest::Ping).await {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }

        Ok(LaunchResult {
            pid,
            control_socket: Some(api),
            jail_path: None,
            vsock_socket: ctx.vsock_socket.clone(),
            virtiofsd_pids: Vec::new(),
        })
    }

    async fn pause(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        let sock = control_socket(vm)?;
        let resp = control::request(sock, &ApiRequest::Pause).await?;
        match resp {
            crate::api::ApiResponse::State { .. } | crate::api::ApiResponse::Ok { .. } => Ok(()),
            crate::api::ApiResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected pause response: {other:?}"),
        }
    }

    async fn resume(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        let sock = control_socket(vm)?;
        let resp = control::request(sock, &ApiRequest::Resume).await?;
        match resp {
            crate::api::ApiResponse::State { .. } | crate::api::ApiResponse::Ok { .. } => Ok(()),
            crate::api::ApiResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected resume response: {other:?}"),
        }
    }

    async fn graceful_shutdown(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        let sock = control_socket(vm)?;
        let _ = control::request(sock, &ApiRequest::Shutdown).await?;
        Ok(())
    }
}

fn control_socket(vm: &VmRecord) -> Result<&Path> {
    vm.control_socket
        .as_deref()
        .context("FluxVm VM has no control socket recorded")
}
