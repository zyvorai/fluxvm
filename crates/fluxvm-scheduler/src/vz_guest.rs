// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Sandbox exec and file access for `vz` guests, over SSH instead of the vsock guest agent (see `fluxvm_apple::ssh`).

use crate::VmManager;
use anyhow::{Context, Result, bail};
use base64::Engine;
use fluxvm_apple::ssh::{self, GuestSsh};
use fluxvm_core::model::VmRecord;
use fluxvm_guest_protocol::{AgentResponse, ExecPolicy};
use std::time::Duration;

/// Login user for sandbox VMs created without a `cloud_init.user` of their own.
pub const DEFAULT_SANDBOX_USER: &str = "sandbox";

impl VmManager {
    /// The daemon's SSH key, created on first use; its public half is authorised in sandbox VMs by cloud-init.
    pub(crate) fn sandbox_ssh_key(&self) -> Result<(String, std::path::PathBuf)> {
        ssh::ensure_key(&self.cfg.state_dir)
    }

    pub(crate) fn vz_guest(&self, vm: &VmRecord) -> Result<GuestSsh> {
        let ip = vm
            .guest_ip
            .clone()
            .context("the VM has not reported an address yet")?;
        let user = vm
            .request
            .cloud_init
            .as_ref()
            .and_then(|c| c.user.clone())
            .unwrap_or_else(|| DEFAULT_SANDBOX_USER.into());
        let (_, key) = self.sandbox_ssh_key()?;
        Ok(GuestSsh { ip, user, key })
    }

    pub(crate) async fn vz_exec(
        &self,
        vm: &VmRecord,
        command: String,
        timeout_seconds: Option<u64>,
        policy: Option<ExecPolicy>,
    ) -> Result<AgentResponse> {
        if policy.is_some() {
            bail!("a per-exec policy needs the vsock guest agent, which vz guests do not run");
        }
        let secs = timeout_seconds.unwrap_or(fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS);
        let out = ssh::exec(&self.vz_guest(vm)?, &command, Duration::from_secs(secs)).await?;
        Ok(AgentResponse::Exec {
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
            enforcement: None,
        })
    }

    pub(crate) async fn vz_get_file(&self, vm: &VmRecord, path: String) -> Result<AgentResponse> {
        let (data, mode) = ssh::read_file(&self.vz_guest(vm)?, &path).await?;
        Ok(AgentResponse::FileContent {
            content_base64: base64::engine::general_purpose::STANDARD.encode(data),
            mode,
        })
    }

    pub(crate) async fn vz_put_file(
        &self,
        vm: &VmRecord,
        path: String,
        content_base64: String,
        mode: Option<u32>,
    ) -> Result<AgentResponse> {
        let data = base64::engine::general_purpose::STANDARD
            .decode(content_base64.as_bytes())
            .context("content_base64 is not valid base64")?;
        ssh::write_file(&self.vz_guest(vm)?, &path, &data, mode.unwrap_or(0o644)).await?;
        Ok(AgentResponse::FileWritten)
    }
}
