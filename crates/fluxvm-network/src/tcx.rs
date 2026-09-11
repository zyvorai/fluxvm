// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! TCX/BPF-link lifecycle adapter.
//!
//! FluxVM keeps libbpf out of the Rust daemon dependency graph. A tiny
//! `fluxvm-tcx` helper performs BPF_LINK_CREATE / BPF_LINK_UPDATE and emits
//! JSON. `FLUXVM_TCX=auto` is the default; `off` forces legacy clsact/tc and
//! `required` makes lack of TCX a fail-closed error.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    Off,
    Auto,
    Required,
}

impl Preference {
    pub fn from_env() -> Result<Self> {
        match std::env::var("FLUXVM_TCX")
            .unwrap_or_else(|_| "auto".into())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "0" | "false" | "off" | "legacy" => Ok(Self::Off),
            "" | "1" | "true" | "on" | "auto" | "prefer" => Ok(Self::Auto),
            "required" | "strict" => Ok(Self::Required),
            other => bail!("invalid FLUXVM_TCX={other:?}; use off, auto, or required"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub ifindex: Option<u32>,
    #[serde(default)]
    pub link_id: Option<u32>,
    #[serde(default)]
    pub prog_id: Option<u32>,
    #[serde(default)]
    pub revision: Option<u64>,
    #[serde(default)]
    pub program_count: Option<u32>,
    #[serde(default)]
    pub link_type: Option<u32>,
}

pub fn link_pin(vm_dir: &Path) -> std::path::PathBuf {
    vm_dir.join("links/tcx_ingress")
}

pub fn probe(iface: &str) -> Result<Status> {
    run_json(&["probe", iface])
}

pub fn attach(iface: &str, program_pin: &Path, link_pin: &Path) -> Result<Status> {
    let program_pin = program_pin
        .to_str()
        .context("TCX program pin path is not UTF-8")?;
    let link_pin = link_pin
        .to_str()
        .context("TCX link pin path is not UTF-8")?;
    run_json(&["attach", iface, program_pin, link_pin])
}

pub fn update(program_pin: &Path, link_pin: &Path, old_program_pin: Option<&Path>) -> Result<()> {
    let program_pin = program_pin
        .to_str()
        .context("TCX program pin path is not UTF-8")?;
    let link_pin = link_pin
        .to_str()
        .context("TCX link pin path is not UTF-8")?;
    let mut args = vec!["update", program_pin, link_pin];
    let old = old_program_pin
        .map(|p| p.to_str().context("old TCX program pin path is not UTF-8"))
        .transpose()?;
    if let Some(old) = old {
        args.push(old);
    }
    let _: serde_json::Value = run_json(&args)?;
    Ok(())
}

pub fn status(link_pin: &Path) -> Result<Status> {
    let link_pin_str = link_pin
        .to_str()
        .context("TCX link pin path is not UTF-8")?;
    match run_json(&["status", link_pin_str]) {
        Ok(status) => Ok(status),
        Err(helper_error) => {
            // Status remains observable even when the helper binary was
            // removed after a successful attach. bpftool can inspect a
            // pinned BPF link without knowing TCX-specific creation details.
            let out = Command::new("bpftool")
                .args(["-j", "link", "show", "pinned"])
                .arg(link_pin)
                .output()
                .with_context(|| {
                    format!("TCX helper failed ({helper_error:#}); running bpftool link show")
                })?;
            if !out.status.success() {
                bail!(
                    "TCX helper failed ({helper_error:#}); bpftool status failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            let value: serde_json::Value = serde_json::from_slice(&out.stdout)?;
            let value = value.as_array().and_then(|a| a.first()).unwrap_or(&value);
            Ok(Status {
                mode: "tcx".into(),
                ifindex: None,
                link_id: value
                    .get("id")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok()),
                prog_id: value
                    .get("prog_id")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok()),
                revision: None,
                program_count: None,
                link_type: value
                    .get("type")
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok()),
            })
        }
    }
}

pub fn detach(link_pin: &Path) -> Result<()> {
    let link_pin = link_pin
        .to_str()
        .context("TCX link pin path is not UTF-8")?;
    let _: serde_json::Value = run_json(&["detach", link_pin])?;
    Ok(())
}

fn helper() -> String {
    if let Ok(path) = std::env::var("FLUXVM_TCX_HELPER") {
        if !path.trim().is_empty() {
            return path;
        }
    }
    let installed = "/usr/libexec/fluxvm/fluxvm-tcx";
    if Path::new(installed).exists() {
        installed.into()
    } else {
        "fluxvm-tcx".into()
    }
}

fn run_json<T: for<'de> Deserialize<'de>>(args: &[&str]) -> Result<T> {
    let helper = helper();
    let out = Command::new(&helper)
        .args(args)
        .output()
        .with_context(|| format!("running TCX helper {helper}"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed: {}",
            helper,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout)
        .with_context(|| format!("parsing JSON from {} {}", helper, args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_pin_is_scoped_to_vm() {
        assert_eq!(
            link_pin(Path::new("/sys/fs/bpf/fluxvm/vms/abc")),
            Path::new("/sys/fs/bpf/fluxvm/vms/abc/links/tcx_ingress")
        );
    }
}
