// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Cilium-style security groups for the FluxVM VM-edge dataplane.
//!
//! A group is a named set of labels plus an L3/L4 egress policy. Membership is
//! label-based (`app=web`) and/or explicit (`groups = ["web"]` on the VM
//! policy). The control plane allocates a stable numeric identity from the
//! sorted label set and folds group allow/deny lists into the VM's TC maps so
//! the kernel path stays per-VM-pin and Cilium-private maps stay untouched.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::Write,
    path::PathBuf,
};

use crate::dataplane::VmNetworkPolicy;

/// Identities `0x1 ..= 0xffff` stay reserved for per-VM hashes from
/// [`crate::ebpf::identity_for`]. Group identities live above that so flow
/// telemetry can tell a VM id from a shared group id.
pub const GROUP_IDENTITY_BASE: u32 = 0x1_0000;
pub const MAX_GROUP_IDENTITIES_PER_VM: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityGroup {
    pub name: String,
    /// Cilium-style `key=value` labels. Empty is allowed for name-only groups.
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub policy: VmNetworkPolicy,
    /// Stable dataplane identity. Assigned on create if omitted.
    #[serde(default)]
    pub identity: u32,
    /// Lower number wins when merging rate limits and deny-vs-allow ties.
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedMembership {
    pub vm_groups: Vec<String>,
    pub vm_labels: Vec<String>,
    pub matched: Vec<SecurityGroup>,
    pub identities: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GroupStore {
    groups: HashMap<String, SecurityGroup>,
}

fn store_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-groups").join("groups.json")
}

fn load_store(cfg: &Config) -> Result<GroupStore> {
    let path = store_path(cfg);
    if !path.exists() {
        return Ok(GroupStore::default());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading security groups {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing security groups {}", path.display()))
}

fn save_store(cfg: &Config, store: &GroupStore) -> Result<()> {
    let path = store_path(cfg);
    let parent = path.parent().context("group store has no parent")?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(store)?;
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn normalize_label(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("empty security-group label");
    }
    if s.len() > 128 {
        bail!("security-group label longer than 128 bytes");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '=' | '/' | '.' | '-' | '_' | ':'))
    {
        bail!("invalid security-group label {s:?}");
    }
    Ok(s.to_string())
}

pub fn normalize_name(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("security group name is required");
    }
    if s.len() > 64 {
        bail!("security group name longer than 64 bytes");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        bail!("invalid security group name {s:?}");
    }
    Ok(s.to_string())
}

/// FNV-1a fold of sorted labels, forced into the group identity range.
pub fn identity_for_labels(labels: &[String]) -> u32 {
    let mut set = BTreeSet::new();
    for l in labels {
        if let Ok(n) = normalize_label(l) {
            set.insert(n);
        }
    }
    let mut hash = 0xcbf29ce484222325u64;
    for l in set {
        for b in l.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    GROUP_IDENTITY_BASE.saturating_add((hash as u32) & 0x7fff_ffff)
}

pub fn list_groups(cfg: &Config) -> Result<Vec<SecurityGroup>> {
    let store = load_store(cfg)?;
    let mut out: Vec<_> = store.groups.into_values().collect();
    out.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.name.cmp(&b.name)));
    Ok(out)
}

pub fn get_group(cfg: &Config, name: &str) -> Result<SecurityGroup> {
    let name = normalize_name(name)?;
    load_store(cfg)?
        .groups
        .get(&name)
        .cloned()
        .with_context(|| format!("security group {name} not found"))
}

pub fn upsert_group(cfg: &Config, mut group: SecurityGroup) -> Result<SecurityGroup> {
    group.name = normalize_name(&group.name)?;
    let mut labels = Vec::new();
    for l in group.labels {
        labels.push(normalize_label(&l)?);
    }
    labels.sort();
    labels.dedup();
    group.labels = labels;
    crate::ebpf::validate_policy(&group.policy)?;
    if group.identity < GROUP_IDENTITY_BASE {
        group.identity = if group.labels.is_empty() {
            identity_for_labels(&[format!("name={}", group.name)])
        } else {
            identity_for_labels(&group.labels)
        };
    }
    let mut store = load_store(cfg)?;
    store.groups.insert(group.name.clone(), group.clone());
    save_store(cfg, &store)?;
    Ok(group)
}

pub fn delete_group(cfg: &Config, name: &str) -> Result<()> {
    let name = normalize_name(name)?;
    let mut store = load_store(cfg)?;
    if store.groups.remove(&name).is_none() {
        bail!("security group {name} not found");
    }
    save_store(cfg, &store)
}

/// Groups that apply to a VM: explicit names on the VM policy plus any group
/// whose label set is a subset of the VM labels.
pub fn resolve_groups(cfg: &Config, policy: &VmNetworkPolicy) -> Result<Vec<SecurityGroup>> {
    Ok(resolve_membership(cfg, policy)?.matched)
}

pub fn resolve_membership(cfg: &Config, policy: &VmNetworkPolicy) -> Result<ResolvedMembership> {
    let store = load_store(cfg)?;
    let explicit: BTreeSet<String> = policy
        .groups
        .iter()
        .filter_map(|n| normalize_name(n).ok())
        .collect();
    let vm_labels: BTreeSet<String> = policy
        .labels
        .iter()
        .filter_map(|l| normalize_label(l).ok())
        .collect();

    let mut out = Vec::new();
    for g in store.groups.values() {
        let named = explicit.contains(&g.name);
        let label_match = !g.labels.is_empty() && g.labels.iter().all(|l| vm_labels.contains(l));
        if named || label_match {
            out.push(g.clone());
        }
    }
    out.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.name.cmp(&b.name)));
    if out.len() > MAX_GROUP_IDENTITIES_PER_VM {
        out.truncate(MAX_GROUP_IDENTITIES_PER_VM);
    }
    let identities: Vec<u32> = out.iter().map(|g| g.identity).collect();
    Ok(ResolvedMembership {
        vm_groups: explicit.into_iter().collect(),
        vm_labels: vm_labels.into_iter().collect(),
        matched: out,
        identities,
    })
}

/// Union VM policy with every matching group. Group CIDRs/ports widen the
/// allowlist; deny CIDRs are also unioned; the tightest configured rate
/// limit wins; sampling uses max; `default_allow` becomes false if any
/// member fails closed.
pub fn merge_group_policy(
    cfg: &Config,
    mut policy: VmNetworkPolicy,
) -> Result<(VmNetworkPolicy, Vec<u32>)> {
    let membership = resolve_membership(cfg, &policy)?;
    for g in &membership.matched {
        policy.allow_cidrs.extend(g.policy.allow_cidrs.iter().cloned());
        policy.deny_cidrs.extend(g.policy.deny_cidrs.iter().cloned());
        policy.allow_ports.extend(g.policy.allow_ports.iter().cloned());
        if !g.policy.default_allow {
            policy.default_allow = false;
        }
        if g.policy.allow_icmp {
            policy.allow_icmp = true;
        }
        policy.max_egress_mbps = min_opt(policy.max_egress_mbps, g.policy.max_egress_mbps);
        policy.max_egress_pps = min_opt(policy.max_egress_pps, g.policy.max_egress_pps);
        policy.sample_rate = policy.sample_rate.max(g.policy.sample_rate);
    }
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();
    policy.deny_cidrs.sort();
    policy.deny_cidrs.dedup();
    policy.allow_ports.sort();
    policy.allow_ports.dedup();
    Ok((policy, membership.identities))
}

fn min_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::config::Config;

    fn cfg() -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.state_dir = dir.path().to_path_buf();
        (c, dir)
    }

    fn group(name: &str, labels: &[&str], cidrs: &[&str], deny: &[&str]) -> SecurityGroup {
        SecurityGroup {
            name: name.into(),
            labels: labels.iter().map(|s| (*s).to_string()).collect(),
            policy: VmNetworkPolicy {
                default_allow: false,
                allow_cidrs: cidrs.iter().map(|s| (*s).to_string()).collect(),
                deny_cidrs: deny.iter().map(|s| (*s).to_string()).collect(),
                allow_ports: vec!["tcp/443".into()],
                allow_icmp: true,
                ..VmNetworkPolicy::default()
            },
            identity: 0,
            priority: 10,
            description: "test".into(),
        }
    }

    #[test]
    fn identity_is_stable_and_in_group_range() {
        let a = identity_for_labels(&["app=web".into(), "env=prod".into()]);
        let b = identity_for_labels(&["env=prod".into(), "app=web".into()]);
        assert_eq!(a, b);
        assert!(a >= GROUP_IDENTITY_BASE);
        let named = identity_for_labels(&["name=web".into()]);
        assert_ne!(a, named);
    }

    #[test]
    fn rejects_bad_names_and_labels() {
        assert!(normalize_name("").is_err());
        assert!(normalize_name("has space").is_err());
        assert!(normalize_label("").is_err());
        assert!(normalize_label("no spaces allowed").is_err());
        assert!(normalize_label("app=web").is_ok());
        assert!(normalize_name("web-front").is_ok());
    }

    #[test]
    fn label_subset_selects_group() {
        let (cfg, _dir) = cfg();
        upsert_group(&cfg, group("web", &["app=web"], &["10.0.0.0/8"], &[])).unwrap();
        let vm = VmNetworkPolicy {
            labels: vec!["app=web".into(), "tier=front".into()],
            ..VmNetworkPolicy::default()
        };
        let groups = resolve_groups(&cfg, &vm).unwrap();
        assert_eq!(groups.len(), 1);
        let (merged, ids) = merge_group_policy(&cfg, vm).unwrap();
        assert!(merged.allow_cidrs.iter().any(|c| c == "10.0.0.0/8"));
        assert!(merged.allow_ports.iter().any(|p| p == "tcp/443"));
        assert!(merged.allow_icmp);
        assert!(!merged.default_allow);
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn explicit_name_selects_group_without_labels() {
        let (cfg, _dir) = cfg();
        upsert_group(&cfg, group("egress", &[], &["1.1.1.1/32"], &["0.0.0.0/0"])).unwrap();
        let vm = VmNetworkPolicy {
            groups: vec!["egress".into()],
            ..VmNetworkPolicy::default()
        };
        let (merged, _) = merge_group_policy(&cfg, vm).unwrap();
        assert!(merged.deny_cidrs.iter().any(|c| c == "0.0.0.0/0"));
        assert!(merged.allow_cidrs.iter().any(|c| c == "1.1.1.1/32"));
    }

    #[test]
    fn rate_limits_take_the_minimum() {
        let (cfg, _dir) = cfg();
        let mut g = group("slow", &["app=db"], &["10.1.0.0/16"], &[]);
        g.policy.max_egress_mbps = Some(50);
        g.policy.max_egress_pps = Some(1000);
        upsert_group(&cfg, g).unwrap();
        let vm = VmNetworkPolicy {
            labels: vec!["app=db".into()],
            max_egress_mbps: Some(250),
            max_egress_pps: Some(80),
            ..VmNetworkPolicy::default()
        };
        let (merged, _) = merge_group_policy(&cfg, vm).unwrap();
        assert_eq!(merged.max_egress_mbps, Some(50));
        assert_eq!(merged.max_egress_pps, Some(80));
    }

    #[test]
    fn upsert_is_idempotent_and_delete_removes() {
        let (cfg, _dir) = cfg();
        let a = upsert_group(&cfg, group("web", &["app=web"], &["10.0.0.0/8"], &[])).unwrap();
        let b = upsert_group(&cfg, group("web", &["app=web"], &["10.0.0.0/8"], &[])).unwrap();
        assert_eq!(a.identity, b.identity);
        assert_eq!(list_groups(&cfg).unwrap().len(), 1);
        delete_group(&cfg, "web").unwrap();
        assert!(get_group(&cfg, "web").is_err());
        assert!(delete_group(&cfg, "web").is_err());
    }

    #[test]
    fn priority_orders_resolution() {
        let (cfg, _dir) = cfg();
        let mut high = group("a", &["app=x"], &["10.0.0.0/8"], &[]);
        high.priority = 1;
        let mut low = group("b", &["app=x"], &["11.0.0.0/8"], &[]);
        low.priority = 99;
        upsert_group(&cfg, low).unwrap();
        upsert_group(&cfg, high).unwrap();
        let vm = VmNetworkPolicy {
            labels: vec!["app=x".into()],
            ..VmNetworkPolicy::default()
        };
        let names: Vec<_> = resolve_groups(&cfg, &vm)
            .unwrap()
            .into_iter()
            .map(|g| g.name)
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
