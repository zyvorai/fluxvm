// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Sandbox exec and file access for `vz` guests. A guest with the agent enabled (the `agent-micro` image, or a spec that asks
//! for it) is reached over vsock through the runner's `CONNECT` proxy first; when the agent does not answer, and always for
//! other guests, over SSH (see `fluxvm_apple::ssh`).

use crate::VmManager;
use anyhow::{Context, Result, bail};
use base64::Engine;
use fluxvm_apple::ssh::{self, GuestSsh};
use fluxvm_core::model::{AgentSpec, CreateVmRequest, VmRecord};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse, ExecPolicy};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Login user for sandbox VMs created without a `cloud_init.user` of their own.
pub const DEFAULT_SANDBOX_USER: &str = "sandbox";

/// The image that ships the guest agent (see `docs/agent-micro.md`).
pub const AGENT_MICRO_IMAGE: &str = "agent-micro";

/// How long a request waits on the agent beyond its own timeout before falling back.
const AGENT_GRACE: Duration = Duration::from_secs(5);

static AGENT_CALLS: AtomicU64 = AtomicU64::new(0);
static SSH_FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// vz sandbox requests answered by the guest agent, and those that fell back to SSH because it did not answer.
pub fn agent_counters() -> (u64, u64) {
    (
        AGENT_CALLS.load(Ordering::Relaxed),
        SSH_FALLBACKS.load(Ordering::Relaxed),
    )
}

/// The agent a vz sandbox gets: the caller's, when the spec enabled one; the default one on `agent-micro`; otherwise none.
pub(crate) fn vz_sandbox_agent(create: &CreateVmRequest) -> Option<AgentSpec> {
    match &create.agent {
        Some(a) if a.enabled => Some(a.clone()),
        _ if create.image.as_os_str() == AGENT_MICRO_IMAGE => Some(AgentSpec {
            enabled: true,
            ..AgentSpec::default()
        }),
        _ => None,
    }
}

fn agent_enabled(vm: &VmRecord) -> bool {
    vm.request.agent.as_ref().is_some_and(|a| a.enabled)
}

/// Any answer from the agent, including an error it reports (a missing file), is final; only a transport failure (no
/// listener, refused, timed out) falls back.
fn agent_answered(r: &Result<AgentResponse>) -> bool {
    r.is_ok()
}

impl VmManager {
    /// The daemon's SSH key, created on first use; its public half is authorised in sandbox VMs by cloud-init.
    pub(crate) fn sandbox_ssh_key(&self) -> Result<(String, std::path::PathBuf)> {
        ssh::ensure_key(&self.cfg.state_dir)
    }

    pub(crate) fn vz_guest(&self, vm: &VmRecord) -> Result<GuestSsh> {
        let user = vm
            .request
            .cloud_init
            .as_ref()
            .and_then(|c| c.user.clone())
            .unwrap_or_else(|| DEFAULT_SANDBOX_USER.into());
        let (_, key) = self.sandbox_ssh_key()?;
        // A guest with no network card is reached through the runner's vsock proxy; the others by address.
        if matches!(vm.request.network, fluxvm_core::model::NetworkSpec::None) {
            let sock = vm
                .vsock_socket
                .clone()
                .context("the VM has no vsock socket recorded")?;
            return Ok(GuestSsh {
                ip: "vsock".into(),
                user,
                key,
                vsock: Some(sock),
            });
        }
        let ip = vm
            .guest_ip
            .clone()
            .context("the VM has not reported an address yet")?;
        Ok(GuestSsh {
            ip,
            user,
            key,
            vsock: None,
        })
    }

    /// Asks the guest agent; `None` means "use SSH".
    async fn vz_agent(
        &self,
        vm: &VmRecord,
        request: AgentRequest,
        timeout: Duration,
    ) -> Option<AgentResponse> {
        if !agent_enabled(vm) {
            return None;
        }
        let r = fluxvm_vsock_client::call(vm, request, timeout + AGENT_GRACE).await;
        if agent_answered(&r) {
            AGENT_CALLS.fetch_add(1, Ordering::Relaxed);
            return r.ok();
        }
        SSH_FALLBACKS.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = r {
            tracing::debug!(vm = %vm.id, error = %format!("{e:#}"), "guest agent did not answer; using SSH");
        }
        None
    }

    pub(crate) async fn vz_exec(
        &self,
        vm: &VmRecord,
        command: String,
        timeout_seconds: Option<u64>,
        policy: Option<ExecPolicy>,
    ) -> Result<AgentResponse> {
        let secs = timeout_seconds.unwrap_or(fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS);
        let request = AgentRequest::Exec {
            command: command.clone(),
            timeout_seconds: Some(secs),
            policy: policy.clone(),
            process: None,
        };
        if let Some(r) = self.vz_agent(vm, request, Duration::from_secs(secs)).await {
            return Ok(r);
        }
        if policy.is_some() {
            bail!("a per-exec policy needs the vsock guest agent, which this guest does not run");
        }
        let out = ssh::exec(&self.vz_guest(vm)?, &command, Duration::from_secs(secs)).await?;
        Ok(AgentResponse::Exec {
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
            enforcement: None,
        })
    }

    pub(crate) async fn vz_get_file(&self, vm: &VmRecord, path: String) -> Result<AgentResponse> {
        let request = AgentRequest::GetFile { path: path.clone() };
        if let Some(r) = self
            .vz_agent(vm, request, fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT)
            .await
        {
            return Ok(r);
        }
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
        let request = AgentRequest::PutFile {
            path: path.clone(),
            content_base64,
            mode,
        };
        if let Some(r) = self
            .vz_agent(vm, request, fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT)
            .await
        {
            return Ok(r);
        }
        ssh::write_file(&self.vz_guest(vm)?, &path, &data, mode.unwrap_or(0o644)).await?;
        Ok(AgentResponse::FileWritten)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(image: &str, agent: Option<AgentSpec>) -> CreateVmRequest {
        let mut r: CreateVmRequest = serde_json::from_value(serde_json::json!({
            "name": "s", "backend": "vz", "image": image, "vcpus": 1, "memory_mib": 512,
        }))
        .unwrap();
        r.agent = agent;
        r
    }

    #[test]
    fn agent_micro_and_explicit_specs_get_the_agent() {
        assert!(vz_sandbox_agent(&create("debian-13", None)).is_none());
        let a = vz_sandbox_agent(&create(AGENT_MICRO_IMAGE, None)).unwrap();
        assert!(a.enabled && a.port == fluxvm_guest_protocol::DEFAULT_PORT && a.token.is_none());
        let own = AgentSpec {
            enabled: true,
            port: 2000,
            token: None,
        };
        assert_eq!(
            vz_sandbox_agent(&create("/my.raw", Some(own)))
                .unwrap()
                .port,
            2000
        );
        let off = AgentSpec {
            enabled: false,
            ..AgentSpec::default()
        };
        assert!(vz_sandbox_agent(&create("/my.raw", Some(off))).is_none());
    }

    #[test]
    fn only_a_transport_failure_falls_back() {
        assert!(agent_answered(&Ok(AgentResponse::Error {
            message: "no such file".into()
        })));
        assert!(!agent_answered(&Err(anyhow::anyhow!("connection refused"))));
    }
}
