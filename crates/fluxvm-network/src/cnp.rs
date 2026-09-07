// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! CiliumNetworkPolicy-compatible documents compiled onto FluxVM groups.
//!
//! Supported spec subset:
//! endpointSelector.matchLabels, egress/egressDeny/ingress/ingressDeny,
//! toCIDR, toCIDRSet, toEntities, toFQDNs, toPorts, fromCIDR, fromEntities,
//! enableDefaultDeny, auditMode, description.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io::Write, path::PathBuf};

use crate::dataplane::VmNetworkPolicy;
use crate::groups::{SecurityGroup, upsert_group};
use crate::identity::{entity_cidrs, parse_entity};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiliumNetworkPolicy {
    #[serde(default = "default_api")]
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub metadata: CnpMetadata,
    pub spec: CnpSpec,
}

fn default_api() -> String {
    "cilium.io/v2".into()
}
fn default_kind() -> String {
    "CiliumNetworkPolicy".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CnpMetadata {
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CnpSpec {
    #[serde(default, rename = "endpointSelector")]
    pub endpoint_selector: Option<Selector>,
    #[serde(default)]
    pub egress: Vec<CnpRule>,
    #[serde(default, rename = "egressDeny")]
    pub egress_deny: Vec<CnpRule>,
    #[serde(default)]
    pub ingress: Vec<CnpRule>,
    #[serde(default, rename = "ingressDeny")]
    pub ingress_deny: Vec<CnpRule>,
    #[serde(default, rename = "enableDefaultDeny")]
    pub enable_default_deny: Option<DefaultDeny>,
    #[serde(default, rename = "auditMode")]
    pub audit_mode: bool,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DefaultDeny {
    #[serde(default)]
    pub egress: Option<bool>,
    #[serde(default)]
    pub ingress: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Selector {
    #[serde(default, rename = "matchLabels")]
    pub match_labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CnpRule {
    #[serde(default, rename = "toCIDR")]
    pub to_cidr: Vec<String>,
    #[serde(default, rename = "toCIDRSet")]
    pub to_cidr_set: Vec<CidrSet>,
    #[serde(default, rename = "fromCIDR")]
    pub from_cidr: Vec<String>,
    #[serde(default, rename = "toEntities")]
    pub to_entities: Vec<String>,
    #[serde(default, rename = "fromEntities")]
    pub from_entities: Vec<String>,
    #[serde(default, rename = "toFQDNs")]
    pub to_fqdns: Vec<FqdnMatch>,
    #[serde(default, rename = "toPorts")]
    pub to_ports: Vec<PortRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CidrSet {
    pub cidr: String,
    #[serde(default, rename = "except")]
    pub except: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FqdnMatch {
    #[serde(default, rename = "matchName")]
    pub match_name: Option<String>,
    #[serde(default, rename = "matchPattern")]
    pub match_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortRule {
    #[serde(default)]
    pub ports: Vec<PortProto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortProto {
    pub port: String,
    #[serde(default)]
    pub protocol: String,
}

fn store_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-groups").join("cnp.json")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CnpStore {
    policies: HashMap<String, CiliumNetworkPolicy>,
}

fn load_store(cfg: &Config) -> Result<CnpStore> {
    let path = store_path(cfg);
    if !path.exists() {
        return Ok(CnpStore::default());
    }
    Ok(serde_json::from_str(&fs::read_to_string(&path)?)?)
}

fn save_store(cfg: &Config, store: &CnpStore) -> Result<()> {
    let path = store_path(cfg);
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(serde_json::to_vec_pretty(store)?.as_slice())?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn list_cnp(cfg: &Config) -> Result<Vec<CiliumNetworkPolicy>> {
    let mut v: Vec<_> = load_store(cfg)?.policies.into_values().collect();
    v.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
    Ok(v)
}

pub fn get_cnp(cfg: &Config, name: &str) -> Result<CiliumNetworkPolicy> {
    load_store(cfg)?
        .policies
        .get(name)
        .cloned()
        .with_context(|| format!("CNP {name} not found"))
}

pub fn delete_cnp(cfg: &Config, name: &str) -> Result<()> {
    let mut store = load_store(cfg)?;
    if store.policies.remove(name).is_none() {
        bail!("CNP {name} not found");
    }
    save_store(cfg, &store)
}

pub fn apply_cnp(cfg: &Config, policy: CiliumNetworkPolicy) -> Result<SecurityGroup> {
    if policy.kind != "CiliumNetworkPolicy" && policy.kind != "CiliumClusterwideNetworkPolicy" {
        bail!("unsupported kind {}", policy.kind);
    }
    let group = compile(&policy)?;
    let group = upsert_group(cfg, group)?;
    let mut store = load_store(cfg)?;
    store
        .policies
        .insert(policy.metadata.name.clone(), policy);
    save_store(cfg, &store)?;
    Ok(group)
}

pub fn compile(policy: &CiliumNetworkPolicy) -> Result<SecurityGroup> {
    let mut labels = Vec::new();
    if let Some(sel) = &policy.spec.endpoint_selector {
        for (k, v) in &sel.match_labels {
            labels.push(format!("{k}={v}"));
        }
    }
    labels.sort();
    labels.dedup();

    let mut compiled = VmNetworkPolicy {
        default_allow: !policy
            .spec
            .enable_default_deny
            .as_ref()
            .and_then(|d| d.egress)
            .unwrap_or(true),
        audit_mode: policy.spec.audit_mode,
        ..VmNetworkPolicy::default()
    };
    if policy.spec.enable_default_deny.is_none()
        && (!policy.spec.egress.is_empty() || !policy.spec.egress_deny.is_empty())
    {
        compiled.default_allow = false;
    }

    fold_rules(&mut compiled, &policy.spec.egress, false)?;
    fold_rules(&mut compiled, &policy.spec.egress_deny, true)?;
    // Ingress rules apply at the same VM edge (host-visible iface) for
    // the FluxVM attach point; they widen the same maps.
    fold_rules(&mut compiled, &policy.spec.ingress, false)?;
    fold_rules(&mut compiled, &policy.spec.ingress_deny, true)?;

    compiled.allow_cidrs.sort();
    compiled.allow_cidrs.dedup();
    compiled.deny_cidrs.sort();
    compiled.deny_cidrs.dedup();
    compiled.allow_ports.sort();
    compiled.allow_ports.dedup();
    compiled.allow_fqdns.sort();
    compiled.allow_fqdns.dedup();

    crate::ebpf::validate_policy(&compiled)?;
    Ok(SecurityGroup {
        name: crate::groups::normalize_name(&policy.metadata.name)?,
        labels,
        policy: compiled,
        identity: 0,
        priority: 50,
        description: if policy.spec.description.is_empty() {
            format!("CNP {}", policy.metadata.name)
        } else {
            policy.spec.description.clone()
        },
    })
}

fn fold_rules(out: &mut VmNetworkPolicy, rules: &[CnpRule], deny: bool) -> Result<()> {
    for rule in rules {
        let mut cidrs = rule.to_cidr.clone();
        cidrs.extend(rule.from_cidr.iter().cloned());
        for set in &rule.to_cidr_set {
            cidrs.push(set.cidr.clone());
            if deny {
                out.deny_cidrs.extend(set.except.iter().cloned());
            } else {
                out.deny_cidrs.extend(set.except.iter().cloned());
            }
        }
        for ent in rule.to_entities.iter().chain(rule.from_entities.iter()) {
            let Some(name) = parse_entity(ent) else {
                bail!("unknown entity {ent:?}");
            };
            out.entities.push(ent.clone());
            cidrs.extend(entity_cidrs(name));
        }
        for fqdn in &rule.to_fqdns {
            if let Some(n) = &fqdn.match_name {
                out.allow_fqdns.push(n.to_ascii_lowercase());
            }
            if let Some(p) = &fqdn.match_pattern {
                out.allow_fqdns.push(p.to_ascii_lowercase());
            }
        }
        for pr in &rule.to_ports {
            for p in &pr.ports {
                for expanded in expand_port(&p.protocol, &p.port)? {
                    out.allow_ports.push(expanded);
                }
            }
        }
        if deny {
            out.deny_cidrs.extend(cidrs);
        } else {
            out.allow_cidrs.extend(cidrs);
        }
    }
    Ok(())
}

pub fn expand_port(protocol: &str, port: &str) -> Result<Vec<String>> {
    let proto = match protocol.trim().to_ascii_lowercase().as_str() {
        "" | "any" | "tcp" => "tcp",
        "udp" => "udp",
        "icmp" => "icmp",
        "icmpv6" | "icmp6" => "icmp6",
        other => bail!("unsupported CNP protocol {other:?}"),
    };
    if proto == "icmp" || proto == "icmp6" {
        return Ok(vec![format!("{proto}/0")]);
    }
    let port = port.trim();
    if let Some(named) = named_port(port) {
        return Ok(vec![format!("{proto}/{named}")]);
    }
    if let Some((a, b)) = port.split_once('-') {
        let start: u16 = a.parse().context("port range start")?;
        let end: u16 = b.parse().context("port range end")?;
        if start == 0 || end < start {
            bail!("invalid port range {port}");
        }
        if u32::from(end) - u32::from(start) > 256 {
            bail!("port range {port} expands to more than 256 ports");
        }
        return Ok((start..=end).map(|p| format!("{proto}/{p}")).collect());
    }
    let n: u16 = port.parse().with_context(|| format!("invalid port {port}"))?;
    if n == 0 {
        bail!("port must be 1..65535");
    }
    Ok(vec![format!("{proto}/{n}")])
}

fn named_port(name: &str) -> Option<u16> {
    match name.to_ascii_lowercase().as_str() {
        "http" => Some(80),
        "https" => Some(443),
        "dns" => Some(53),
        "ssh" => Some(22),
        "smtp" => Some(25),
        "ntp" => Some(123),
        "ldap" => Some(389),
        "ldaps" => Some(636),
        "mysql" => Some(3306),
        "postgres" | "postgresql" => Some(5432),
        "redis" => Some(6379),
        "kube-apiserver" => Some(6443),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_cilium_subset() {
        let raw = r#"{
          "apiVersion": "cilium.io/v2",
          "kind": "CiliumNetworkPolicy",
          "metadata": {"name": "web-egress"},
          "spec": {
            "endpointSelector": {"matchLabels": {"app": "web"}},
            "enableDefaultDeny": {"egress": true},
            "egress": [{
              "toCIDR": ["10.0.0.0/8"],
              "toEntities": ["world"],
              "toFQDNs": [{"matchName": "example.com"}],
              "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}, {"port": "8000-8002", "protocol": "TCP"}]}]
            }],
            "egressDeny": [{"toCIDRSet": [{"cidr": "10.66.0.0/16"}]}]
          }
        }"#;
        let cnp: CiliumNetworkPolicy = serde_json::from_str(raw).unwrap();
        let g = compile(&cnp).unwrap();
        assert_eq!(g.name, "web-egress");
        assert!(g.labels.iter().any(|l| l == "app=web"));
        assert!(g.policy.allow_cidrs.iter().any(|c| c == "10.0.0.0/8"));
        assert!(g.policy.allow_cidrs.iter().any(|c| c == "0.0.0.0/0"));
        assert!(g.policy.deny_cidrs.iter().any(|c| c == "10.66.0.0/16"));
        assert!(g.policy.allow_ports.iter().any(|p| p == "tcp/443"));
        assert!(g.policy.allow_ports.iter().any(|p| p == "tcp/8001"));
        assert!(g.policy.allow_fqdns.iter().any(|d| d == "example.com"));
        assert!(!g.policy.default_allow);
    }

    #[test]
    fn named_ports_expand() {
        assert_eq!(expand_port("TCP", "https").unwrap(), vec!["tcp/443".to_string()]);
        assert_eq!(expand_port("UDP", "dns").unwrap(), vec!["udp/53".to_string()]);
    }
}
