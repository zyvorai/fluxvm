// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `exec` with an optional per-request guest confinement policy (Landlock +
//! seccomp, applied inside the guest by the agent through `fluxvm-procbox`).

use crate::{VmManager, procbox_sandbox};
use anyhow::{Result, bail};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse, ExecPolicy};
use uuid::Uuid;

/// Parse a JSON exec policy (the `fluxvm-procbox` policy shape). Unknown
/// fields are ignored; missing ones take the safe defaults (no network).
pub fn parse_exec_policy(json: &str) -> Result<ExecPolicy> {
    Ok(serde_json::from_str(json)?)
}

impl VmManager {
    /// Like [`VmManager::exec`], confined by `policy` when given. The
    /// response's `enforcement` reports what the guest actually enforced.
    pub async fn exec_with_policy(
        &self,
        id: Uuid,
        command: String,
        timeout_seconds: Option<u64>,
        policy: Option<ExecPolicy>,
    ) -> Result<AgentResponse> {
        let vm = self.get(id).await?;
        if let Some(spec) = procbox_sandbox::load_spec(&vm)? {
            if policy.is_some() {
                bail!(
                    "a per-exec policy is not supported on procbox sandboxes (they are already confined by their own spec)"
                );
            }
            return self.procbox_exec(&vm, spec, command, timeout_seconds).await;
        }
        if vm.backend == fluxvm_core::model::BackendKind::Vz {
            return self.vz_exec(&vm, command, timeout_seconds, policy).await;
        }
        let wait = std::time::Duration::from_secs(
            timeout_seconds.unwrap_or(fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS) + 5,
        );
        fluxvm_vsock_client::call(
            &vm,
            AgentRequest::Exec {
                command,
                timeout_seconds,
                policy,
                process: None,
            },
            wait,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_guest_protocol::ExecTcpRule;

    #[test]
    fn parses_a_procbox_shaped_policy_with_safe_defaults() {
        let p = parse_exec_policy(r#"{"read":["/usr","/bin"],"max_abi":3}"#).unwrap();
        assert_eq!(p.read.len(), 2);
        assert_eq!(p.tcp_connect, ExecTcpRule::Deny);
        assert!(parse_exec_policy("not json").is_err());
    }
}
