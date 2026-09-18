// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Cilium-identical status panel for `fluxctl status`.
//!
//! Layout mirrors `cilium status`: colored ASCII logo on the left, component
//! rows on the right, then a tab-aligned summary block.

use anyhow::Result;
use fluxvm_core::{
    config::Config,
    model::VmStatus,
};
use fluxvm_scheduler::VmManager;
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";

fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("FORCE_COLOR").is_some() || std::env::var_os("CLICOLOR_FORCE").is_some() {
        return true;
    }
    io::stdout().is_terminal()
}

fn c(code: &str, text: &str, on: bool) -> String {
    if on {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

fn ok(on: bool) -> String {
    c(GREEN, "✅ OK", on)
}

fn warn(on: bool, msg: &str) -> String {
    c(YELLOW, &format!("⚠️  {msg}"), on)
}

fn err(on: bool, msg: &str) -> String {
    c(RED, &format!("❌ {msg}"), on)
}

fn disabled(on: bool) -> String {
    c(&(YELLOW.to_string() + BOLD), "⭘ disabled", on)
}

fn bin_ok(name: &str) -> bool {
    which(name).is_some()
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
        }
        None
    })
}

fn path_ok(p: Option<&Path>) -> bool {
    p.map(|p| p.exists()).unwrap_or(false)
}

/// Print the Cilium-style status panel to stdout.
///
/// `manager` may be `None` when the state dir is not readable (e.g. non-root
/// user) — host/config rows still render, matching `cilium status` partial
/// output when the cluster is unreachable.
pub async fn print_status(
    manager: Option<&VmManager>,
    cfg: &Config,
    verbose: bool,
) -> Result<()> {
    let on = color_enabled();
    let vms = if let Some(m) = manager {
        m.list().await
    } else {
        Vec::new()
    };
    let vms_readable = manager.is_some();

    let mut by_status: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_backend: BTreeMap<String, usize> = BTreeMap::new();
    for vm in &vms {
        let key = match vm.status {
            VmStatus::Creating => "creating",
            VmStatus::Running => "running",
            VmStatus::Paused => "paused",
            VmStatus::Stopped => "stopped",
            VmStatus::Failed => "failed",
        };
        *by_status.entry(key).or_default() += 1;
        *by_backend
            .entry(format!("{:?}", vm.backend).to_ascii_lowercase())
            .or_default() += 1;
    }
    let running = *by_status.get("running").unwrap_or(&0);
    let paused = *by_status.get("paused").unwrap_or(&0);
    let failed = *by_status.get("failed").unwrap_or(&0);
    let total = vms.len();

    let api_status = if cfg.listen.is_empty() {
        err(on, "listen unset")
    } else {
        format!("{} ({})", ok(on), cfg.listen)
    };

    let jailer_status = if cfg.jailer.enabled {
        if cfg.jailer_required() {
            format!("{} (enforce)", ok(on))
        } else {
            format!("{} (optional)", ok(on))
        }
    } else if cfg.jailer_required() {
        err(on, "required but disabled")
    } else {
        disabled(on)
    };

    let dataplane = format!("{:?}", cfg.sandbox.dataplane.mode).to_ascii_lowercase();
    let dataplane_status = match dataplane.as_str() {
        "off" | "none" => disabled(on),
        other => format!("{} ({other})", ok(on)),
    };

    let auth_status = if cfg.auth.has_credentials() {
        if cfg.auth.oidc_enabled() {
            format!("{} (tokens+oidc)", ok(on))
        } else {
            format!("{} (tokens)", ok(on))
        }
    } else if cfg.auth.must_authenticate(&cfg.listen) {
        err(on, "required but empty")
    } else {
        warn(on, "off (lab)")
    };

    let qemu = bin_ok("qemu-system-x86_64");
    let ch = bin_ok("cloud-hypervisor");
    let fc = bin_ok("firecracker");
    let hv = bin_ok("fluxvm-hypervisor") || bin_ok("fluxctl");
    let backends_status = {
        let mut parts = Vec::new();
        if qemu {
            parts.push("qemu");
        }
        if ch {
            parts.push("cloud-hypervisor");
        }
        if fc {
            parts.push("firecracker");
        }
        if hv {
            parts.push("flux-vm");
        }
        if parts.is_empty() {
            err(on, "none on PATH")
        } else {
            format!("{} ({})", ok(on), parts.join(", "))
        }
    };

    let kernel_status = if path_ok(cfg.firecracker_kernel.as_deref())
        || path_ok(cfg.fluxvm_kernel.as_deref())
    {
        ok(on)
    } else {
        warn(on, "no kernel configured")
    };

    let vm_line = if !vms_readable {
        warn(on, "state dir not readable")
    } else if failed > 0 {
        format!(
            "{}  {running} running / {paused} paused / {} failed ({total} total)",
            err(on, &format!("{failed} errors")),
            err(on, &failed.to_string()),
        )
    } else if total == 0 {
        format!("{}  0 VMs", warn(on, "idle"))
    } else {
        format!(
            "{}  {running} running / {paused} paused / {failed} failed ({total} total)",
            ok(on)
        )
    };

    // Logo block — same geometry as `cilium status`.
    let logo = if on {
        [
            format!("{YELLOW}    /¯¯\\{RESET}"),
            format!(
                "{CYAN} /¯¯{YELLOW}\\__/{GREEN}¯¯\\{RESET}    FluxVM:             {api}",
                api = api_status
            ),
            format!(
                "{CYAN} \\__{RED}/¯¯\\{GREEN}__/{RESET}    Jailer:             {j}",
                j = jailer_status
            ),
            format!(
                "{GREEN} /¯¯{RED}\\__/{MAGENTA}¯¯\\{RESET}    Dataplane:          {d}",
                d = dataplane_status
            ),
            format!(
                "{GREEN} \\__{BLUE}/¯¯\\{MAGENTA}__/{RESET}    Auth:               {a}",
                a = auth_status
            ),
            format!(
                "{BLUE}{BLUE}{BLUE}    \\__/{RESET}       Hypervisors:       {b}",
                b = backends_status
            ),
        ]
        .join("\n")
    } else {
        [
            "    /¯¯\\".to_string(),
            format!(" /¯¯\\__/¯¯\\    FluxVM:             {api_status}"),
            format!(" \\__/¯¯\\__/    Jailer:             {jailer_status}"),
            format!(" /¯¯\\__/¯¯\\    Dataplane:          {dataplane_status}"),
            format!(" \\__/¯¯\\__/    Auth:               {auth_status}"),
            format!("    \\__/       Hypervisors:       {backends_status}"),
        ]
        .join("\n")
    };

    let mut out = String::new();
    out.push_str(&logo);
    out.push('\n');
    out.push('\n');
    out.push_str(&format!("{:<22} {}\n", "VMs:", vm_line.trim_start()));
    out.push_str(&format!("{:<22} {}\n", "Kernels:", kernel_status));
    if !by_backend.is_empty() {
        let backends: Vec<_> = by_backend
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect();
        out.push_str(&format!(
            "{:<22} {}\n",
            "Backends in use:",
            backends.join(" ")
        ));
    }
    out.push_str(&format!(
        "{:<22} {}\n",
        "State dir:",
        cfg.state_dir.display()
    ));
    out.push_str(&format!(
        "{:<22} {}\n",
        "Config:",
        if verbose {
            format!("listen={}", cfg.listen)
        } else {
            "loaded".into()
        }
    ));

    if verbose {
        out.push('\n');
        out.push_str(&c(&(BOLD.to_string() + CYAN), "Host binaries:\n", on));
        for (name, present) in [
            ("qemu-system-x86_64", qemu),
            ("cloud-hypervisor", ch),
            ("firecracker", fc),
            ("jailer", bin_ok("jailer")),
            ("fluxvm-hypervisor", bin_ok("fluxvm-hypervisor")),
        ] {
            out.push_str(&format!(
                "  {:<22} {}\n",
                name,
                if present { ok(on) } else { disabled(on) }
            ));
        }
        if let Some(k) = cfg.firecracker_kernel.as_ref() {
            out.push_str(&format!(
                "  {:<22} {}\n",
                "firecracker_kernel",
                if k.exists() {
                    format!("{} ({})", ok(on), k.display())
                } else {
                    err(on, &format!("missing {}", k.display()))
                }
            ));
        }
        if let Some(k) = cfg.fluxvm_kernel.as_ref() {
            out.push_str(&format!(
                "  {:<22} {}\n",
                "fluxvm_kernel",
                if k.exists() {
                    format!("{} ({})", ok(on), k.display())
                } else {
                    err(on, &format!("missing {}", k.display()))
                }
            ));
        }
    }

    let mut stdout = io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()?;

    if failed > 0 && vms_readable {
        anyhow::bail!("status check failed: {failed} VM(s) in Failed state");
    }
    Ok(())
}
