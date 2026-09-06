// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Offline Windows disk customization via GuestKit (plans + agent-inject).
//!
//! Linux `build-image` customization uses guestkit chroot; Windows uses
//! registry plans (`PlanApplicator`) and `inject_windows_agent` instead.

use anyhow::{Context, Result, bail};
use guestkit::cli::plan::types::FileWrite;
use guestkit::cli::plan::{
    FixPlan, Operation, OperationType, PlanApplicator, PlanGenerator, Priority, RegistryEdit,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

const FW_RULES_KEY: &str =
    r"HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
const RUNONCE_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";

/// Offline Windows customization block for `BuildImageRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsCustomize {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub enable_rdp: bool,
    #[serde(default)]
    pub enable_winrm: bool,
    #[serde(default)]
    pub firewall_open: Vec<FirewallPort>,
    #[serde(default)]
    pub firewall_close: Vec<FirewallPort>,
    /// Scripts written into the guest and staged via RunOnce for first boot.
    #[serde(default)]
    pub scripts: Vec<WindowsScript>,
    /// Extra RunOnce registry values (`name` → `command`).
    #[serde(default)]
    pub run_once: Vec<RunOnceEntry>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub agent: Option<WindowsAgentSpec>,
    /// Host path to an `unattend.xml` copied into the guest as
    /// `C:\Windows\Panther\unattend.xml` before first boot.
    #[serde(default)]
    pub unattend_path: Option<PathBuf>,
    /// When true, stage `sysprep /generalize /oobe /shutdown` via RunOnce
    /// for a sealed, first-boot-ready image.
    #[serde(default)]
    pub sysprep: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPort {
    /// Windows firewall rule display / registry value name (also used live).
    pub name: String,
    pub port: u16,
    #[serde(default = "default_tcp")]
    pub protocol: String,
}
fn default_tcp() -> String {
    "tcp".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsScript {
    /// Basename used for the guest file and RunOnce value (no path separators).
    pub name: String,
    pub content: String,
    /// When true (default), run with `powershell.exe -File`; otherwise `cmd.exe /c`.
    #[serde(default = "default_true")]
    pub powershell: bool,
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOnceEntry {
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsAgentSpec {
    /// Path to `guestkitd.exe` (or Zyvor Windows guest agent) on the host.
    pub binary: PathBuf,
    /// Optional virtio-serial (`vioser`) driver directory from virtio-win.
    #[serde(default)]
    pub virtio_serial_driver: Option<PathBuf>,
}

/// Apply every Windows customization step to `image` (blocking; call via spawn_blocking).
pub fn customize_windows_blocking(image: &Path, win: &WindowsCustomize) -> Result<()> {
    let image_s = image.display().to_string();
    let planner = PlanGenerator::new(image_s.clone());

    if let Some(hostname) = &win.hostname {
        apply_plan(
            image,
            &planner
                .windows_hostname_plan(hostname)
                .context("building windows hostname plan")?,
        )?;
    }
    if win.enable_rdp {
        apply_plan(image, &planner.windows_rdp_enable_plan())?;
    }
    if win.enable_winrm {
        apply_plan(image, &planner.windows_winrm_enable_plan())?;
    }

    let mut extras = FixPlan::new(image_s.clone(), "fluxvm-windows".into());
    extras.version = "1".into();
    extras.overall_risk = "low".into();
    extras.estimated_duration = "seconds".into();
    extras.metadata.author = "fluxvm".into();
    extras.metadata.review_required = false;
    extras.metadata.reversible = true;
    extras.metadata.description = Some("FluxVM Windows firewall / RunOnce / scripts".into());
    extras.metadata.tags = vec!["windows".into(), "fluxvm".into()];

    for rule in &win.firewall_open {
        extras.add_operation(firewall_op(rule, true)?);
    }
    for rule in &win.firewall_close {
        extras.add_operation(firewall_op(rule, false)?);
    }
    for (i, script) in win.scripts.iter().enumerate() {
        add_script_ops(&mut extras, script, i)?;
    }
    for entry in &win.run_once {
        extras.add_operation(runonce_op(&entry.name, &entry.command));
    }
    if let Some(password) = &win.password {
        let user = win.user.as_deref().unwrap_or("Administrator");
        let cmd = guestkit::guestfs::sam_password::runonce_net_user_command(user, password);
        extras.add_operation(runonce_op("FluxVMSetPassword", &cmd));
    }

    if !extras.operations.is_empty() {
        apply_plan(image, &extras)?;
    }

    if let Some(agent) = &win.agent {
        guestkit::agent::inject::inject_windows_agent(
            image,
            &agent.binary,
            agent.virtio_serial_driver.as_deref(),
            false,
            true,
        )
        .context("injecting Zyvor/GuestKit Windows agent")?;
    }

    if let Some(unattend) = &win.unattend_path {
        inject_unattend(image, unattend)?;
    }
    if win.sysprep {
        apply_plan(image, &sysprep_runonce_plan(image.display().to_string())?)?;
    }

    Ok(())
}

fn inject_unattend(image: &Path, host_path: &Path) -> Result<()> {
    if !host_path.exists() {
        bail!("unattend_path does not exist: {}", host_path.display());
    }
    let content = std::fs::read_to_string(host_path)
        .with_context(|| format!("reading {}", host_path.display()))?;
    let mut plan = FixPlan::new(image.display().to_string(), "fluxvm-unattend".into());
    plan.version = "1".into();
    plan.overall_risk = "low".into();
    plan.estimated_duration = "seconds".into();
    plan.metadata.author = "fluxvm".into();
    plan.add_operation(Operation {
        id: "unattend-write".into(),
        op_type: OperationType::FileWrite(FileWrite {
            path: "/Windows/Panther/unattend.xml".into(),
            content,
            mode: None,
        }),
        priority: Priority::Medium,
        description: "Inject Windows unattend.xml".into(),
        risk: Priority::Low,
        reversible: true,
        depends_on: vec![],
        validation: None,
        undo: None,
    });
    apply_plan(image, &plan)
}

fn sysprep_runonce_plan(image: String) -> Result<FixPlan> {
    let mut plan = FixPlan::new(image, "fluxvm-sysprep".into());
    plan.version = "1".into();
    plan.overall_risk = "medium".into();
    plan.estimated_duration = "minutes".into();
    plan.metadata.author = "fluxvm".into();
    plan.metadata.description =
        Some("Stage sysprep /generalize /oobe /shutdown on first boot via RunOnce".into());
    plan.add_operation(runonce_op(
        "FluxVMSysprep",
        r#"C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /quiet"#,
    ));
    Ok(plan)
}

fn apply_plan(image: &Path, plan: &FixPlan) -> Result<()> {
    let result = PlanApplicator::new(image.display().to_string(), false)
        .skip_backup(true)
        .apply(plan)
        .with_context(|| format!("applying plan {} to {}", plan.profile, image.display()))?;
    if !result.success {
        bail!(
            "plan {} failed on {}: {}",
            plan.profile,
            image.display(),
            result.message
        );
    }
    Ok(())
}

fn protocol_number(proto: &str) -> Result<u8> {
    match proto.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        other => bail!("unsupported firewall protocol '{other}' (use tcp or udp)"),
    }
}

/// Build the Windows FirewallRules REG_SZ blob used by stock/offline plans.
pub fn firewall_rule_blob(name: &str, port: u16, protocol: &str, active: bool) -> Result<String> {
    let proto = protocol_number(protocol)?;
    let active_s = if active { "TRUE" } else { "FALSE" };
    Ok(format!(
        "v2.29|Action=Allow|Active={active_s}|Dir=In|Protocol={proto}|LPort={port}|\
Profile=Private,Domain,Public|Name={name}|Desc=FluxVM firewall rule|"
    ))
}

fn sanitize_rule_value(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("FluxVM-{cleaned}")
}

fn firewall_op(rule: &FirewallPort, open: bool) -> Result<Operation> {
    let value = sanitize_rule_value(&rule.name);
    let blob = firewall_rule_blob(&rule.name, rule.port, &rule.protocol, open)?;
    let id = if open {
        format!("fw-open-{}", rule.port)
    } else {
        format!("fw-close-{}", rule.port)
    };
    let desc = if open {
        format!(
            "Open inbound {}/{} ({})",
            rule.protocol, rule.port, rule.name
        )
    } else {
        format!(
            "Close inbound {}/{} ({})",
            rule.protocol, rule.port, rule.name
        )
    };
    Ok(Operation {
        id,
        op_type: OperationType::RegistryEdit(RegistryEdit {
            key: FW_RULES_KEY.into(),
            value,
            current_data: json!(""),
            new_data: json!(blob),
            data_type: "sz".into(),
        }),
        priority: Priority::High,
        description: desc,
        risk: Priority::Low,
        reversible: true,
        depends_on: vec![],
        validation: None,
        undo: None,
    })
}

fn runonce_op(name: &str, command: &str) -> Operation {
    Operation {
        id: format!("runonce-{name}"),
        op_type: OperationType::RegistryEdit(RegistryEdit {
            key: RUNONCE_KEY.into(),
            value: name.into(),
            current_data: json!(""),
            new_data: json!(command),
            data_type: "sz".into(),
        }),
        priority: Priority::Medium,
        description: format!("Stage RunOnce '{name}'"),
        risk: Priority::Low,
        reversible: true,
        depends_on: vec![],
        validation: None,
        undo: None,
    }
}

fn add_script_ops(plan: &mut FixPlan, script: &WindowsScript, index: usize) -> Result<()> {
    if script.name.contains('/') || script.name.contains('\\') || script.name.contains("..") {
        bail!(
            "script name must be a simple basename, got '{}'",
            script.name
        );
    }
    let ext = if script.powershell { "ps1" } else { "cmd" };
    let guest_path = format!("/Windows/Temp/fluxvm-{}.{}", script.name, ext);
    let win_path = format!(r"C:\Windows\Temp\fluxvm-{}.{}", script.name, ext);
    let write_id = format!("script-write-{index}");
    plan.add_operation(Operation {
        id: write_id.clone(),
        op_type: OperationType::FileWrite(FileWrite {
            path: guest_path,
            content: script.content.clone(),
            mode: None,
        }),
        priority: Priority::Medium,
        description: format!("Write first-boot script {}", script.name),
        risk: Priority::Low,
        reversible: true,
        depends_on: vec![],
        validation: None,
        undo: None,
    });

    let cmd = if script.powershell {
        format!(r#"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{win_path}""#)
    } else {
        format!(r#"cmd.exe /c "{win_path}""#)
    };
    let mut op = runonce_op(&format!("FluxVMScript{}", script.name), &cmd);
    op.depends_on = vec![write_id];
    plan.add_operation(op);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_blob_open_tcp() {
        let b = firewall_rule_blob("App", 8080, "tcp", true).unwrap();
        assert!(b.contains("Active=TRUE"));
        assert!(b.contains("LPort=8080"));
        assert!(b.contains("Protocol=6"));
        assert!(b.contains("Name=App"));
    }

    #[test]
    fn firewall_blob_close_udp() {
        let b = firewall_rule_blob("Dns", 53, "udp", false).unwrap();
        assert!(b.contains("Active=FALSE"));
        assert!(b.contains("Protocol=17"));
    }

    #[test]
    fn sanitize_rule_value_strips_junk() {
        assert_eq!(sanitize_rule_value("My App!"), "FluxVM-My_App_");
    }
}
