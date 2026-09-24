// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! kubectl plugin: `kubectl fluxvm console <kind> <name>`.
//! Shells out to `fluxctl` for console/exec/pause/resume and to `kubectl`
//! delete for the custom resource.

use anyhow::{Context, Result, bail};
use fluxvm_kube::plugin::{PluginCommand, command_for};
use serde_json::Value;
use std::process::Command;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("fluxvm") {
        args.remove(0);
    }
    let mut namespace = "default".to_string();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-n" || args[i] == "--namespace" {
            namespace = args.get(i + 1).context("-n needs a namespace")?.clone();
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    let verb = rest
        .first()
        .context("usage: kubectl fluxvm <console|exec|pause|resume|delete> <kind> <name>")?
        .clone();
    let kind = rest.get(1).context("kind is required")?.clone();
    let name = rest.get(2).context("name is required")?.clone();
    let exec_args = if verb == "exec" {
        rest.iter().skip(3).cloned().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let status = fetch_status(&kind, &name, &namespace)?;
    match command_for(&verb, &kind, &name, &namespace, &status, &exec_args)? {
        PluginCommand::Fluxctl(argv) => run(&argv),
        PluginCommand::KubectlDelete {
            kind,
            name,
            namespace,
        } => run(&[
            "kubectl".into(),
            "delete".into(),
            kind,
            name,
            "-n".into(),
            namespace,
        ]),
    }
}

fn fetch_status(kind: &str, name: &str, namespace: &str) -> Result<Value> {
    let output = Command::new("kubectl")
        .args(["get", kind, name, "-n", namespace, "-o", "json"])
        .output()
        .context("running kubectl get")?;
    if !output.status.success() {
        bail!(
            "kubectl get failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let doc: Value = serde_json::from_slice(&output.stdout).context("parsing kubectl json")?;
    Ok(doc)
}

fn run(argv: &[String]) -> Result<()> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    let status = cmd
        .status()
        .with_context(|| format!("running {}", argv[0]))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{} exited {status}", argv[0])
    }
}
