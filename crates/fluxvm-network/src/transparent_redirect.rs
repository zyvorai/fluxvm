// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! nftables redirect for the egress proxy's transparent mode.
//!
//! Guest traffic to ports 80/443 is redirected to the transparent listener
//! (`sandbox.egress_transparent_listen`) so the guest needs no proxy settings.
//! The rules live in their own table **inside a named network namespace**; there
//! is deliberately no API that touches the host's default namespace, and the
//! host's existing rules are never edited.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::process::{Command, Stdio};

/// The nftables table that holds the redirect (one per namespace).
pub const TABLE: &str = "fluxvm_egress_tp";

/// Where to install the redirect.
#[derive(Debug, Clone)]
pub struct RedirectSpec<'a> {
    /// Network namespace name (`ip netns list`). Required: never the default.
    pub netns: &'a str,
    /// Ingress interface inside that namespace (the guest-facing tap/veth).
    pub iface: &'a str,
    /// Destination TCP ports to redirect (typically 80 and 443).
    pub ports: &'a [u16],
    /// Local port of the transparent listener.
    pub proxy_port: u16,
}

fn valid_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

impl RedirectSpec<'_> {
    fn validate(&self) -> Result<()> {
        if !valid_name(self.netns, 64) {
            bail!("network namespace name must be 1-64 characters of [A-Za-z0-9_.-]");
        }
        if !valid_name(self.iface, 15) {
            bail!("interface name must be 1-15 characters of [A-Za-z0-9_.-]");
        }
        if self.ports.is_empty() || self.ports.contains(&0) {
            bail!("redirect needs at least one non-zero destination port");
        }
        if self.proxy_port == 0 {
            bail!("proxy port must be non-zero");
        }
        Ok(())
    }
}

/// The nft ruleset text: a prerouting NAT chain that redirects traffic arriving
/// on `iface` for `ports` to `proxy_port`. Pure; validates the names so nothing
/// but simple identifiers can reach the command.
pub fn snippet(spec: &RedirectSpec<'_>) -> Result<String> {
    spec.validate()?;
    let ports = spec
        .ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "table inet {TABLE} {{\n  chain prerouting {{\n    type nat hook prerouting priority dstnat; policy accept;\n    iifname \"{}\" tcp dport {{ {ports} }} redirect to :{}\n  }}\n}}\n",
        spec.iface, spec.proxy_port
    ))
}

/// Install the redirect inside `spec.netns` (replacing any earlier one).
pub fn apply(spec: &RedirectSpec<'_>) -> Result<()> {
    let text = snippet(spec)?;
    let _ = remove(spec.netns);
    let mut child = Command::new("ip")
        .args(["netns", "exec", spec.netns, "nft", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning `ip netns exec ... nft`")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(text.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "nft in namespace {} failed: {}",
            spec.netns,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Remove the redirect table from `netns` (no error if it is not there).
pub fn remove(netns: &str) -> Result<()> {
    if !valid_name(netns, 64) {
        bail!("network namespace name must be 1-64 characters of [A-Za-z0-9_.-]");
    }
    let _ = Command::new("ip")
        .args([
            "netns", "exec", netns, "nft", "delete", "table", "inet", TABLE,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(netns: &'a str, iface: &'a str, ports: &'a [u16]) -> RedirectSpec<'a> {
        RedirectSpec {
            netns,
            iface,
            ports,
            proxy_port: 18889,
        }
    }

    #[test]
    fn snippet_redirects_only_the_named_interface_and_ports() {
        let t = snippet(&spec("fvegress", "tap0", &[80, 443])).unwrap();
        assert!(t.starts_with("table inet fluxvm_egress_tp {"));
        assert!(t.contains("hook prerouting priority dstnat"));
        assert!(t.contains("iifname \"tap0\" tcp dport { 80, 443 } redirect to :18889"));
        assert!(!t.contains("output"), "never the host OUTPUT hook");
    }

    #[test]
    fn names_and_ports_are_validated() {
        assert!(
            snippet(&spec("", "tap0", &[80])).is_err(),
            "no default namespace"
        );
        assert!(snippet(&spec("ns; rm", "tap0", &[80])).is_err());
        assert!(snippet(&spec("ns", "tap\"0", &[80])).is_err());
        assert!(snippet(&spec("ns", "averyverylongifname", &[80])).is_err());
        assert!(snippet(&spec("ns", "tap0", &[])).is_err());
        assert!(snippet(&spec("ns", "tap0", &[0])).is_err());
        let mut s = spec("ns", "tap0", &[80]);
        s.proxy_port = 0;
        assert!(snippet(&s).is_err());
        assert!(remove("").is_err());
    }
}
