// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Egress allowlist + credential vault helpers for FluxVm sandboxes.

use crate::dataplane;
use fluxvm_core::config::{CredentialInject, SandboxConfig};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDecision {
    pub allow: bool,
    pub inject_authorization: Option<String>,
    pub reason: String,
}

/// Decide whether an outbound HTTP(S) request to `host` is allowed and whether
/// to inject a vault credential. Empty allowlist = allow all (no L7 filter).
pub fn decide(cfg: &SandboxConfig, host: &str) -> EgressDecision {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let inject = cfg
        .credential_vault
        .iter()
        .find(|c| host_matches(&c.host, &host))
        .map(|c| c.authorization.clone());

    if cfg.egress_allow_domains.is_empty() {
        return EgressDecision {
            allow: true,
            inject_authorization: inject,
            reason: "no allowlist configured".into(),
        };
    }
    let allowed = cfg
        .egress_allow_domains
        .iter()
        .any(|d| host_matches(d, &host));
    EgressDecision {
        allow: allowed,
        inject_authorization: if allowed { inject } else { None },
        reason: if allowed {
            "host matched allowlist".into()
        } else {
            format!("host {host} not in egress allowlist")
        },
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
    host == p || host.ends_with(&format!(".{p}"))
}

fn dns_lookup_name(domain: &str) -> String {
    domain.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// Best-effort DNS resolution of allowlist domains to /32 CIDR strings for
/// nftables `ip daddr` rules (dataplane does not accept domain literals).
pub async fn resolve_allow_cidrs(domains: &[String]) -> Vec<String> {
    let mut cidrs = Vec::new();
    for domain in domains {
        let name = dns_lookup_name(domain);
        if name.is_empty() {
            continue;
        }
        match tokio::net::lookup_host(format!("{name}:443")).await {
            Ok(addrs) => {
                for addr in addrs {
                    if let std::net::IpAddr::V4(v4) = addr.ip() {
                        cidrs.push(format!("{v4}/32"));
                    }
                }
            }
            Err(e) => {
                warn!(domain = %name, error = %e, "egress allow domain DNS lookup failed");
            }
        }
    }
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

/// Render nftables snippets that DNAT egress through a local L7 proxy port.
pub fn nftables_redirect_snippet(proxy_port: u16) -> String {
    format!(
        "table inet fluxvm_egress {{\n  chain output {{\n    type nat hook output priority -100;\n    meta skuid != 0 tcp dport {{ 80, 443 }} redirect to :{proxy_port}\n  }}\n}}\n"
    )
}

/// Install the host output-chain redirect from [`nftables_redirect_snippet`].
pub fn apply_egress_redirect(proxy_port: u16) -> anyhow::Result<()> {
    let table = "fluxvm_egress";
    let _ = dataplane::remove_nft_table(table);
    dataplane::run_nft(&["add", "table", "inet", table])?;
    dataplane::run_nft(&[
        "add", "chain", "inet", table, "output", "{", "type", "nat", "hook", "output", "priority",
        "-100;", "}",
    ])?;
    dataplane::run_nft(&[
        "add",
        "rule",
        "inet",
        table,
        "output",
        "meta",
        "skuid",
        "!=",
        "0",
        "tcp",
        "dport",
        "{",
        "80",
        ",",
        "443",
        "}",
        "redirect",
        "to",
        &format!(":{proxy_port}"),
    ])?;
    Ok(())
}

/// Evaluate vault entries for documentation / API.
pub fn vault_hosts(cfg: &SandboxConfig) -> Vec<&CredentialInject> {
    cfg.credential_vault.iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matches_suffix_and_exact() {
        assert!(host_matches(".github.com", "api.github.com"));
        assert!(host_matches("github.com", "github.com"));
        assert!(!host_matches("github.com", "gitlab.com"));
    }
}
