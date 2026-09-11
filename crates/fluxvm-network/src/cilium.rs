// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Safe Cilium coexistence boundary.
//!
//! FluxVM never writes Cilium's private BPF maps. Cilium owns Kubernetes
//! node/CNI networking; FluxVM owns only the VM-edge TAP/veth program and
//! pins its maps below `/sys/fs/bpf/fluxvm`.
//!
//! Phase 2b: when `mode=cilium`, FluxVM may **read** SecurityIdentity /
//! endpoint metadata from the Cilium agent Unix API (`/var/run/cilium/cilium.sock`)
//! to enrich CEP-*shaped* views. Soft-fail when the agent is absent.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const CILIUM_SOCK: &str = "/var/run/cilium/cilium.sock";

pub fn validate_host() -> Result<()> {
    let socket = Path::new(CILIUM_SOCK);
    if !socket.exists() {
        bail!(
            "Cilium coexistence requested but {} is not visible; install Cilium or mount /var/run/cilium into FluxVM",
            socket.display()
        );
    }
    let bpffs = Path::new("/sys/fs/bpf");
    if !bpffs.exists() {
        bail!("Cilium coexistence requires bpffs at /sys/fs/bpf");
    }
    std::fs::metadata(bpffs).with_context(|| format!("reading {} metadata", bpffs.display()))?;
    Ok(())
}

/// Identity returned by the Cilium agent (never allocated via private maps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub id: u32,
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CiliumIdentity {
    id: u64,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CiliumEndpoint {
    id: Option<u64>,
    #[serde(default, rename = "identity")]
    identity: Option<CiliumEndpointIdentity>,
    #[serde(default)]
    status: Option<CiliumEndpointStatus>,
}

#[derive(Debug, Deserialize)]
struct CiliumEndpointIdentity {
    id: Option<u64>,
    #[serde(default)]
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CiliumEndpointStatus {
    #[serde(default)]
    networking: Option<CiliumEndpointNetworking>,
}

#[derive(Debug, Deserialize)]
struct CiliumEndpointNetworking {
    #[serde(default)]
    addressing: Vec<CiliumAddr>,
}

#[derive(Debug, Deserialize)]
struct CiliumAddr {
    ipv4: Option<String>,
    ipv6: Option<String>,
}

/// Resolve a SecurityIdentity from the local Cilium agent.
///
/// Prefer matching an existing CEP by guest IPv4; otherwise look up identities
/// whose labels contain every FluxVM label. Returns `Ok(None)` when the agent
/// has no match (caller keeps the FluxVM hash identity).
pub fn resolve_identity(
    labels: &[String],
    guest_ip: Option<&str>,
) -> Result<Option<AgentIdentity>> {
    if !Path::new(CILIUM_SOCK).exists() {
        return Ok(None);
    }
    if let Some(ip) = guest_ip {
        let bare = ip.split('/').next().unwrap_or(ip);
        if let Some(found) = lookup_endpoint_by_ip(bare)? {
            return Ok(Some(found));
        }
    }
    if labels.is_empty() {
        return Ok(None);
    }
    lookup_identity_by_labels(labels)
}

fn lookup_endpoint_by_ip(ip: &str) -> Result<Option<AgentIdentity>> {
    let body = agent_get("/v1/endpoint")?;
    let eps: Vec<CiliumEndpoint> = serde_json::from_str(&body).unwrap_or_default();
    for ep in eps {
        let addrs = ep
            .status
            .as_ref()
            .and_then(|s| s.networking.as_ref())
            .map(|n| n.addressing.as_slice())
            .unwrap_or(&[]);
        let hit = addrs.iter().any(|a| {
            a.ipv4.as_deref() == Some(ip)
                || a.ipv6.as_deref() == Some(ip)
                || a.ipv4
                    .as_deref()
                    .map(|v| v.split('/').next() == Some(ip))
                    .unwrap_or(false)
        });
        if !hit {
            continue;
        }
        if let Some(ident) = ep.identity {
            if let Some(id) = ident.id {
                return Ok(Some(AgentIdentity {
                    id: id as u32,
                    labels: ident.labels,
                }));
            }
        }
        if let Some(id) = ep.id {
            return Ok(Some(AgentIdentity {
                id: id as u32,
                labels: vec![],
            }));
        }
    }
    Ok(None)
}

fn lookup_identity_by_labels(want: &[String]) -> Result<Option<AgentIdentity>> {
    let body = agent_get("/v1/identity")?;
    let ids: Vec<CiliumIdentity> = serde_json::from_str(&body).unwrap_or_default();
    for id in ids {
        if want
            .iter()
            .all(|w| id.labels.iter().any(|l| l == w || l.ends_with(w)))
        {
            return Ok(Some(AgentIdentity {
                id: id.id as u32,
                labels: id.labels,
            }));
        }
    }
    Ok(None)
}

fn agent_get(path: &str) -> Result<String> {
    let mut stream =
        UnixStream::connect(CILIUM_SOCK).with_context(|| format!("connecting to {CILIUM_SOCK}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .context("writing Cilium agent request")?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .context("reading Cilium agent response")?;
    let text = String::from_utf8_lossy(&raw);
    let Some(idx) = text.find("\r\n\r\n") else {
        bail!("malformed Cilium agent HTTP response");
    };
    let (header, body) = text.split_at(idx + 4);
    let status_ok = header
        .lines()
        .next()
        .map(|l| l.contains(" 200 "))
        .unwrap_or(false);
    if !status_ok {
        bail!(
            "Cilium agent HTTP error: {}",
            header.lines().next().unwrap_or("")
        );
    }
    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_without_socket_is_none() {
        // When the sock is absent, resolve must soft-succeed.
        if Path::new(CILIUM_SOCK).exists() {
            return;
        }
        let r = resolve_identity(&["k8s:app=web".into()], Some("10.0.0.5")).unwrap();
        assert!(r.is_none());
    }
}
