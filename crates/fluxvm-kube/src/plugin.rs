// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `kubectl-fluxvm` resolves a DisposableVm or MicroVM to the node-local
//! `fluxctl` API. It does not speak virtctl and does not open a second
//! control plane. `delete` removes the custom resource; the operator
//! finalizes the VM.

use anyhow::{Result, bail};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginCommand {
    Fluxctl(Vec<String>),
    KubectlDelete {
        kind: String,
        name: String,
        namespace: String,
    },
}

pub fn vm_id_from_status(kind: &str, status: &Value) -> Result<String> {
    let id = match kind {
        "disposablevm" | "dvm" => status.get("vmId").and_then(Value::as_str),
        "microvm" | "mvm" => status.pointer("/runtime/uuid").and_then(Value::as_str),
        other => bail!("unsupported kind {other} (use disposablevm or microvm)"),
    };
    id.filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("status has no VM id yet"))
}

/// Node names become `ssh` destinations. Reject OpenSSH option tokens
/// (`-oProxyCommand=…`) and anything that is not a plain host identifier.
pub fn validate_ssh_node(node: &str) -> Result<&str> {
    if node.is_empty() || node.starts_with('-') {
        bail!("invalid node hostname for ssh: {node:?}");
    }
    if !node
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
    {
        bail!("invalid node hostname for ssh: {node:?}");
    }
    Ok(node)
}

pub fn command_for(
    verb: &str,
    kind: &str,
    name: &str,
    namespace: &str,
    status: &Value,
    exec_args: &[String],
) -> Result<PluginCommand> {
    if verb == "delete" {
        return Ok(PluginCommand::KubectlDelete {
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: namespace.to_string(),
        });
    }
    let status_doc = status
        .get("status")
        .filter(|value| value.is_object())
        .unwrap_or(status);
    let id = vm_id_from_status(kind, status_doc)?;
    // Placement is the Kubernetes node that runs fluxctl, never the guest IP.
    let node = match kind {
        "disposablevm" | "dvm" => status.pointer("/spec/node").and_then(Value::as_str),
        "microvm" | "mvm" => status
            .pointer("/status/runtime/node")
            .or_else(|| status.pointer("/runtime/node"))
            .and_then(Value::as_str),
        _ => None,
    }
    .filter(|value| !value.is_empty());
    let mut argv = match verb {
        "console" => vec!["fluxctl".into(), "console".into(), id],
        "pause" => vec!["fluxctl".into(), "pause".into(), id],
        "resume" => vec!["fluxctl".into(), "resume".into(), id],
        "exec" => {
            let mut argv = vec!["fluxctl".into(), "exec".into(), id, "--".into()];
            if exec_args.is_empty() {
                bail!("exec requires a command after --");
            }
            argv.extend(exec_args.iter().cloned());
            argv
        }
        other => bail!("unsupported verb {other} (console, exec, pause, resume, delete)"),
    };
    if let Some(node) = node {
        let node = validate_ssh_node(node)?;
        // `ssh -- host -- …` so a leading `-` cannot be parsed as an option
        // even if validation is later loosened.
        let mut remote = vec!["ssh".into(), "--".into(), node.to_string(), "--".into()];
        remote.extend(argv);
        argv = remote;
    }
    Ok(PluginCommand::Fluxctl(argv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn disposablevm_console_and_microvm_exec_use_fluxctl() {
        let dvm = json!({"vmId": "11111111-2222-4333-8444-555555555555", "phase": "Running"});
        let cmd = command_for("console", "disposablevm", "job", "default", &dvm, &[]).unwrap();
        assert_eq!(
            cmd,
            PluginCommand::Fluxctl(vec![
                "fluxctl".into(),
                "console".into(),
                "11111111-2222-4333-8444-555555555555".into()
            ])
        );
        let mvm = json!({"phase": "Running", "runtime": {"uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}});
        let cmd = command_for("exec", "microvm", "job", "ci", &mvm, &["hostname".into()]).unwrap();
        match cmd {
            PluginCommand::Fluxctl(argv) => {
                assert_eq!(argv[0], "fluxctl");
                assert_eq!(argv[1], "exec");
                assert_eq!(argv[3], "--");
                assert_eq!(argv[4], "hostname");
            }
            PluginCommand::KubectlDelete { .. } => panic!("exec must not delete the CR"),
        }
    }

    #[test]
    fn node_placement_uses_ssh_and_not_the_guest_ip() {
        let dvm = json!({
            "spec": {"node": "worker-a"},
            "status": {
                "vmId": "11111111-2222-4333-8444-555555555555",
                "guestIp": "10.0.0.8",
                "phase": "Running"
            }
        });
        let cmd = command_for("pause", "disposablevm", "job", "default", &dvm, &[]).unwrap();
        assert_eq!(
            cmd,
            PluginCommand::Fluxctl(vec![
                "ssh".into(),
                "--".into(),
                "worker-a".into(),
                "--".into(),
                "fluxctl".into(),
                "pause".into(),
                "11111111-2222-4333-8444-555555555555".into()
            ])
        );
    }

    #[test]
    fn ssh_node_rejects_openssh_option_injection() {
        let dvm = json!({
            "spec": {"node": "-oProxyCommand=touch /tmp/pwned"},
            "status": {
                "vmId": "11111111-2222-4333-8444-555555555555",
                "phase": "Running"
            }
        });
        let err = command_for("pause", "disposablevm", "job", "default", &dvm, &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("invalid node hostname"),
            "expected hostname rejection, got {err}"
        );
    }

    #[test]
    fn delete_targets_the_custom_resource() {
        let status = json!({});
        let cmd = command_for("delete", "disposablevm", "job", "default", &status, &[]).unwrap();
        assert_eq!(
            cmd,
            PluginCommand::KubectlDelete {
                kind: "disposablevm".into(),
                name: "job".into(),
                namespace: "default".into(),
            }
        );
    }
}
