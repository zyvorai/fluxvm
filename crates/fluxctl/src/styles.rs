// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Cilium-inspired clap styles + grouped help for `fluxctl --help`.

use clap::builder::styling::{AnsiColor, Effects, Styles};
use std::fmt::Write as _;
use std::io::{self, IsTerminal};

/// Matches the feel of `cilium --help`: bold yellow headers, cyan usage,
/// green literals — auto-disabled when stdout is not a TTY / `NO_COLOR` is set.
pub const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Green.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD));

/// Long help body mirrors `cilium --help`: blurb, then Examples, then Usage.
pub const LONG_ABOUT: &str = "\
🚀 CLI to install, manage, and troubleshoot FluxVM hosts.

FluxVM is a Rust-native VM control plane for QEMU, Cloud Hypervisor,
Firecracker, and the in-tree FluxVM hypervisor — with Network Fabric,
warm pools, and Hubble-lite observability.

Examples:
  # Start the control plane on this host
  $ fluxctl --config /etc/fluxvm.toml serve

  # Check status of FluxVM (Cilium-style panel)
  $ fluxctl status

  # Create a VM from a JSON spec
  $ fluxctl create --spec examples/qemu.json

  # Observe Hubble-lite flows
  $ fluxctl hubble observe
";

/// Clap's stock help cannot group subcommands (Cobra can). We replace the
/// auto Commands section with a Cilium-style grouped listing via `after_help`,
/// and use `{all-args}` for Options / Global Flags only (subcommands are
/// hidden at runtime before help is rendered).
pub const HELP_TEMPLATE: &str = "\
{about-with-newline}\
{usage-heading} {usage}

{after-help}
{all-args}
";

fn color_on() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var_os("FORCE_COLOR").is_some() || std::env::var_os("CLICOLOR_FORCE").is_some() {
        return true;
    }
    io::stdout().is_terminal()
}

/// Build the grouped Available Commands block (Cilium / kubectl style).
///
/// Uses clap/`anstyle` style markers (not raw CSI) so `wrap_help` preserves
/// colors the same way clap's own headers/literals do.
pub fn after_help() -> String {
    let on = color_on();
    let header = if on {
        AnsiColor::Yellow.on_default().effects(Effects::BOLD)
    } else {
        anstyle::Style::new()
    };
    let literal = if on {
        AnsiColor::Green.on_default().effects(Effects::BOLD)
    } else {
        anstyle::Style::new()
    };

    let mut out = String::new();
    let _ = write!(out, "{header}Available Commands:{header:#}");

    let groups: &[(&str, &[(&str, &str)])] = &[
        (
            "✨ Basic Commands:",
            &[
                ("serve", "Start the FluxVM control-plane daemon"),
                ("status", "Display status (Cilium-style panel)"),
            ],
        ),
        (
            "🔄 Lifecycle Commands:",
            &[
                ("create", "Create a VM from a JSON spec file"),
                ("list", "List VMs"),
                ("get", "Get a VM by id"),
                ("start", "Relaunch a Stopped VM from its existing disk"),
                ("stop", "Stop a VM"),
                ("pause", "Pause a VM"),
                ("resume", "Resume a paused VM"),
                ("delete", "Delete a VM"),
            ],
        ),
        (
            "🧊 Runtime Control:",
            &[
                ("freeze", "Freeze a VM via cgroup v2 freezer"),
                ("thaw", "Thaw a previously frozen VM"),
                ("frozen", "Report whether a VM's cgroup is frozen"),
                ("resources", "Apply cgroup v2 resource-control settings"),
            ],
        ),
        (
            "🖥️  Guest Access:",
            &[
                ("exec", "Run a command inside the guest over vsock"),
                ("ping", "Health-check the vsock guest agent"),
                ("copy-to", "Copy a local file into the guest"),
                ("copy-from", "Copy a file out of the guest"),
                ("qga", "QEMU guest-agent (virtio-serial) helpers"),
            ],
        ),
        (
            "📦 Images & Pools:",
            &[
                ("build-image", "Build a guest disk image"),
                ("catalog", "Manage the named/signed image catalog"),
                ("pool", "Manage warm VM pools"),
            ],
        ),
        (
            "🛡️  Network Policy:",
            &[
                ("group", "Security groups for the VM-edge dataplane"),
                ("cnp", "CNP documents compiled onto security groups"),
                ("identity", "Reserved + group numeric identities"),
                ("dataplane", "Dataplane health, ipcache, and FQDN refresh"),
            ],
        ),
        (
            "🔭 Observability:",
            &[
                ("diagnose", "Correlate Runtime Intelligence with VM-edge state"),
                ("trace", "Live VM Flight Recorder events"),
                ("observe", "Snapshot of identities, groups, CNPs, and VMs"),
                ("hubble", "Hubble-lite flows and CiliumEndpoint views"),
            ],
        ),
        (
            "🌐 Cluster:",
            &[
                ("migrate", "Live VM migration (QEMU / Cloud Hypervisor)"),
                ("fleet", "Manage a multi-host fleet via the central registry"),
            ],
        ),
    ];

    for (group, cmds) in groups {
        let _ = write!(out, "\n\n{header}{group}{header:#}\n");
        for (name, about) in *cmds {
            let pad = " ".repeat(14usize.saturating_sub(name.len()));
            let _ = write!(out, "  {literal}{name}{literal:#}{pad} {about}\n");
        }
    }

    out.push('\n');
    out.push_str("Use \"fluxctl [command] --help\" for more information about a command.");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_help_uses_emoji_sections() {
        assert!(LONG_ABOUT.contains('🚀'));
        let help = after_help();
        for marker in [
            "✨ Basic Commands:",
            "🔄 Lifecycle Commands:",
            "🧊 Runtime Control:",
            "🖥️",
            "📦 Images & Pools:",
            "🛡️",
            "🔭 Observability:",
            "🌐 Cluster:",
        ] {
            assert!(help.contains(marker), "grouped help missing {marker}");
        }
    }
}
