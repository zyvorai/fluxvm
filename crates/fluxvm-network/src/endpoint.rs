// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! CiliumEndpoint-shaped control-plane objects for FluxVM VMs.
//!
//! These are **not** written into Cilium's private BPF maps. They are FluxVM
//! state that Hubble-lite and `fluxvm hubble observe` can consume, and that
//! an operator can diff against `cilium endpoint list` on the same node.

use anyhow::Result;
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiliumEndpointView {
    pub id: u32,
    pub uuid: Uuid,
    pub identity: u32,
    /// `fluxvm-hash` (default) or `cilium-agent` when enriched from the agent API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_source: Option<String>,
    #[serde(rename = "identity-labels")]
    pub identity_labels: Vec<String>,
    pub networking: EndpointNetworking,
    pub state: String,
    pub policy: EndpointPolicyState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointNetworking {
    #[serde(rename = "addressing")]
    pub addressing: Vec<EndpointAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointAddr {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointPolicyState {
    pub ingress: String,
    pub egress: String,
    pub audit: bool,
}

fn dir(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-groups").join("endpoints")
}

pub fn upsert(cfg: &Config, ep: &CiliumEndpointView) -> Result<()> {
    let d = dir(cfg);
    fs::create_dir_all(&d)?;
    let path = d.join(format!("{}.json", ep.uuid));
    let tmp = path.with_extension("json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(serde_json::to_vec_pretty(ep)?.as_slice())?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn remove(cfg: &Config, id: Uuid) -> Result<()> {
    let path = dir(cfg).join(format!("{id}.json"));
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn list(cfg: &Config) -> Result<Vec<CiliumEndpointView>> {
    let d = dir(cfg);
    if !d.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in fs::read_dir(d)? {
        let ent = ent?;
        if !ent.file_name().to_string_lossy().ends_with(".json") {
            continue;
        }
        if let Ok(ep) = serde_json::from_str::<CiliumEndpointView>(&fs::read_to_string(ent.path())?)
        {
            out.push(ep);
        }
    }
    out.sort_by_key(|e| e.id);
    Ok(out)
}

pub fn from_vm(
    id: Uuid,
    labels: &[String],
    identity: u32,
    guest_ip: Option<&str>,
    default_allow: bool,
    audit: bool,
) -> CiliumEndpointView {
    let ipv4 = guest_ip
        .map(|s| s.split('/').next().unwrap_or(s).to_string())
        .filter(|s| s.contains('.'));
    let ipv6 = guest_ip
        .map(|s| s.split('/').next().unwrap_or(s).to_string())
        .filter(|s| s.contains(':'));
    CiliumEndpointView {
        id: identity,
        uuid: id,
        identity,
        identity_source: Some("fluxvm-hash".into()),
        identity_labels: labels.to_vec(),
        networking: EndpointNetworking {
            addressing: vec![EndpointAddr { ipv4, ipv6 }],
        },
        state: "ready".into(),
        policy: EndpointPolicyState {
            ingress: if default_allow { "allow" } else { "deny" }.into(),
            egress: if default_allow { "allow" } else { "deny" }.into(),
            audit,
        },
    }
}

/// Prefer a Cilium-agent SecurityIdentity when one is known for this VM.
/// Never writes Cilium private maps — agent HTTP GET only.
pub fn enrich_from_cilium_agent(ep: &mut CiliumEndpointView) {
    let guest_ip = ep
        .networking
        .addressing
        .first()
        .and_then(|a| a.ipv4.as_deref().or(a.ipv6.as_deref()));
    match crate::cilium::resolve_identity(&ep.identity_labels, guest_ip) {
        Ok(Some(agent)) => {
            ep.identity = agent.id.max(1);
            ep.id = ep.identity;
            if !agent.labels.is_empty() {
                ep.identity_labels = agent.labels;
            }
            ep.identity_source = Some("cilium-agent".into());
        }
        Ok(None) => {}
        Err(e) => {
            tracing::debug!(error = %e, "Cilium agent identity lookup failed; keeping fluxvm-hash");
        }
    }
}

/// Hubble v1 flow JSON (subset) so `hubble observe --output json` tooling
/// can consume FluxVM samples without speaking Hubble gRPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubbleFlow {
    pub time: String,
    pub verdict: String,
    #[serde(rename = "drop_reason_desc")]
    pub drop_reason_desc: Option<String>,
    pub ethernet: Option<serde_json::Value>,
    #[serde(rename = "IP")]
    pub ip: Option<serde_json::Value>,
    pub l4: Option<serde_json::Value>,
    pub source: HubbleEndpoint,
    pub destination: HubbleEndpoint,
    #[serde(rename = "Type")]
    pub flow_type: String,
    pub node_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hops: Option<Vec<crate::packetflow::PacketHop>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct HubbleEndpoint {
    pub identity: u32,
    pub labels: Vec<String>,
    pub pod_name: Option<String>,
}

pub fn hubble_flow_from_tuple(
    src_id: u32,
    dst: &str,
    proto: &str,
    verdict: &str,
    labels: &[String],
    vm_name: Option<&str>,
) -> HubbleFlow {
    HubbleFlow {
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".into()),
        verdict: verdict.to_string(),
        drop_reason_desc: if verdict == "DROPPED" {
            Some("POLICY_DENIED".into())
        } else {
            None
        },
        ethernet: None,
        ip: Some(serde_json::json!({"destination": dst, "ipVersion": "IPv4"})),
        l4: Some(serde_json::json!({"protocol": proto})),
        source: HubbleEndpoint {
            identity: src_id,
            labels: labels.to_vec(),
            pod_name: vm_name.map(str::to_string),
        },
        destination: HubbleEndpoint {
            identity: 2, // reserved:world
            labels: vec!["reserved:world".into()],
            pod_name: None,
        },
        flow_type: "L3_L4".into(),
        node_name: hostname(),
        traffic_direction: Some("EGRESS".into()),
        summary: None,
        packets: None,
        bytes: None,
        hops: None,
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "fluxvm".into())
}
