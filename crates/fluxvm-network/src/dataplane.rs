// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! VM dataplane dispatch, policy persistence, and observability.
//!
//! `legacy` keeps nftables. `ebpf` uses FluxVM-owned TC programs/maps.
//! `cilium` keeps Cilium as the node/Kubernetes dataplane while FluxVM owns
//! only the VM-edge TC program and its private `/sys/fs/bpf/fluxvm` pins.

use anyhow::{Context, Result};
use fluxvm_core::config::{Config, DataplaneMode};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf, process::Command};
use tracing::{info, warn};
use uuid::Uuid;

pub use crate::ebpf::{DataplaneStats, FlowRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct VmNetworkPolicy {
    /// Action when no CIDR/L4 allowlist is configured. Once either allowlist
    /// is non-empty it becomes an explicit allowlist and unmatched traffic
    /// is denied, regardless of this value.
    pub default_allow: bool,
    /// IPv4 and IPv6 destination CIDRs. IPv6 requires native eBPF mode;
    /// legacy nftables fallback intentionally refuses mixed-family policy.
    pub allow_cidrs: Vec<String>,
    /// Entries are `tcp/443`, `udp/53`, etc. If CIDRs and ports are both
    /// configured, a packet must match both dimensions.
    pub allow_ports: Vec<String>,
    /// Optional fixed-window egress bandwidth ceiling. Native eBPF only.
    /// `1` means 1 megabit/second (125,000 bytes/second).
    pub max_egress_mbps: Option<u32>,
    /// Optional fixed-window packet-rate ceiling. Native eBPF only.
    pub max_egress_pps: Option<u32>,
    /// 0 disables allow-event sampling. N emits about 1/N allowed packets
    /// to the BPF ring buffer; drop flows are always represented in maps.
    pub sample_rate: u32,
}

impl Default for VmNetworkPolicy {
    fn default() -> Self {
        Self {
            default_allow: true,
            allow_cidrs: Vec::new(),
            allow_ports: Vec::new(),
            max_egress_mbps: None,
            max_egress_pps: None,
            sample_rate: 0,
        }
    }
}

pub fn default_policy(cfg: &Config) -> VmNetworkPolicy {
    let dp = &cfg.sandbox.dataplane;
    VmNetworkPolicy {
        default_allow: dp.default_allow,
        allow_cidrs: dp.allow_cidrs.clone(),
        allow_ports: dp.allow_ports.clone(),
        max_egress_mbps: dp.max_egress_mbps,
        max_egress_pps: dp.max_egress_pps,
        sample_rate: dp.sample_rate,
    }
}

pub fn effective_policy(cfg: &Config, id: Uuid) -> Result<VmNetworkPolicy> {
    Ok(load_policy(cfg, id)?.unwrap_or_else(|| default_policy(cfg)))
}

pub fn load_policy(cfg: &Config, id: Uuid) -> Result<Option<VmNetworkPolicy>> {
    let path = policy_path(cfg, id);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading VM network policy {}", path.display()))?;
    let policy: VmNetworkPolicy = serde_json::from_str(&raw)
        .with_context(|| format!("parsing VM network policy {}", path.display()))?;
    crate::ebpf::validate_policy(&policy)?;
    Ok(Some(policy))
}

pub fn save_policy(cfg: &Config, id: Uuid, policy: &VmNetworkPolicy) -> Result<()> {
    crate::ebpf::validate_policy(policy)?;
    let path = policy_path(cfg, id);
    let parent = path.parent().context("network policy path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating network policy directory {}", parent.display()))?;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(policy)?;
    {
        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("creating temporary network policy {}", tmp.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("writing temporary network policy {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing temporary network policy {}", tmp.display()))?;
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("committing network policy {}", path.display()))?;
    // Make the rename durable as well as atomic. This matters because policy
    // is a security control and the VMM may intentionally outlive the daemon.
    fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing network policy directory {}", parent.display()))?;
    Ok(())
}

pub fn delete_policy(cfg: &Config, id: Uuid) -> Result<()> {
    let path = policy_path(cfg, id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting network policy {}", path.display())),
    }
}

fn policy_path(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.state_dir
        .join("network-policy")
        .join(format!("{id}.json"))
}

/// Stable dependency-free fingerprint of the durable policy. Transient
/// DNS-resolved extra CIDRs are intentionally excluded: this marker answers
/// whether the persisted control-plane generation reached the kernel, not
/// whether DNS answers changed since the last resolution.
pub fn policy_fingerprint(policy: &VmNetworkPolicy) -> Result<u64> {
    let bytes = serde_json::to_vec(policy)?;
    let mut hash = 0xcbf29ce484222325u64; // FNV-1a 64-bit offset basis
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(hash)
}

pub fn apply_sandbox_policy(
    cfg: &Config,
    id: Uuid,
    iface: Option<&str>,
    guest_cidr: Option<&str>,
    extra_allow_cidrs: &[String],
) -> Result<()> {
    let dp = &cfg.sandbox.dataplane;
    let base_policy = effective_policy(cfg, id)?;
    let base_fingerprint = policy_fingerprint(&base_policy)?;
    let mut policy = base_policy;
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();

    match dp.mode {
        DataplaneMode::Legacy => match guest_cidr {
            Some(cidr) => apply_nftables(id, cidr, &policy),
            None => Ok(()),
        },
        DataplaneMode::Ebpf | DataplaneMode::Cilium => {
            // GA semantics: `required = true` fail-closes when a host-visible
            // VM edge exists but attach fails. network.mode=none / user NAT
            // have no edge — always soft-skip (even when required).
            let Some(iface) = iface else {
                tracing::debug!(
                    %id,
                    "skipping dataplane attach: no host-visible VM interface"
                );
                return Ok(());
            };

            let native = (|| -> Result<()> {
                if dp.mode == DataplaneMode::Cilium {
                    crate::cilium::validate_host()?;
                }
                crate::ebpf::apply(dp, &policy, id, iface)
            })();

            match native {
                Ok(()) => {
                    crate::ebpf::commit_policy_fingerprint(id, base_fingerprint)?;
                    Ok(())
                }
                Err(e) if dp.required || policy_uses_native_only_features(&policy) => Err(e),
                Err(e) => {
                    tracing::debug!(
                        %id,
                        error = %e,
                        "native eBPF dataplane unavailable; considering nftables fallback"
                    );
                    match guest_cidr {
                        Some(cidr) => {
                            warn!(
                                %id,
                                error = %e,
                                "native eBPF dataplane unavailable; falling back to nftables"
                            );
                            apply_nftables(id, cidr, &policy)
                        }
                        None => {
                            tracing::debug!(
                                %id,
                                "skipping dataplane attach: native failed and no guest CIDR for nftables"
                            );
                            Ok(())
                        }
                    }
                }
            }
        }
    }
}

/// Update policy for a running VM. Native eBPF updates maps in-place while
/// leaving the TC program attached; the kernel is switched to deny-all while
/// maps are being replaced so the update cannot create an allow-all gap.
pub fn reconfigure_sandbox_policy(
    cfg: &Config,
    id: Uuid,
    iface: Option<&str>,
    guest_cidr: Option<&str>,
    extra_allow_cidrs: &[String],
) -> Result<()> {
    let dp = &cfg.sandbox.dataplane;
    let base_policy = effective_policy(cfg, id)?;
    let base_fingerprint = policy_fingerprint(&base_policy)?;
    let mut policy = base_policy;
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();

    match dp.mode {
        DataplaneMode::Legacy => {
            let cidr = guest_cidr.context(
                "legacy nftables policy update requires a FluxVM-known guest CIDR",
            )?;
            apply_nftables(id, cidr, &policy)
        },
        DataplaneMode::Ebpf | DataplaneMode::Cilium => {
            if dp.mode == DataplaneMode::Cilium {
                crate::cilium::validate_host()?;
            }
            let status = crate::ebpf::attachment_status(dp, id)?;
            if status.attached {
                crate::ebpf::reconfigure(dp, &policy, id)?;
            } else {
                let iface = iface.context(
                    "native policy update needs a host-visible VM interface to repair attachment",
                )?;
                crate::ebpf::apply(dp, &policy, id, iface)?;
            }
            crate::ebpf::commit_policy_fingerprint(id, base_fingerprint)?;
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataplaneStatus {
    pub mode: String,
    pub required: bool,
    pub attached: bool,
    pub interface: Option<String>,
    pub identity: u32,
    pub pin_dir: Option<String>,
    pub schema_version: Option<u32>,
    pub schema_compatible: bool,
    /// True only when the durable policy generation is known to have been
    /// fully committed to the currently attached kernel maps.
    pub policy_synced: bool,
    pub policy: VmNetworkPolicy,
}

pub fn status(cfg: &Config, id: Uuid) -> Result<DataplaneStatus> {
    let dp = &cfg.sandbox.dataplane;
    let policy = effective_policy(cfg, id)?;
    let desired_fingerprint = policy_fingerprint(&policy)?;
    let mode = match dp.mode {
        DataplaneMode::Legacy => "legacy",
        DataplaneMode::Ebpf => "ebpf",
        DataplaneMode::Cilium => "cilium",
    }
    .to_string();

    if dp.mode == DataplaneMode::Legacy {
        return Ok(DataplaneStatus {
            mode,
            required: dp.required,
            attached: false,
            interface: None,
            identity: crate::ebpf::identity_for(id),
            pin_dir: None,
            schema_version: None,
            schema_compatible: true,
            policy_synced: true,
            policy,
        });
    }

    let native = crate::ebpf::attachment_status(dp, id)?;
    Ok(DataplaneStatus {
        mode,
        required: dp.required,
        attached: native.attached,
        interface: native.interface,
        identity: native.identity,
        pin_dir: Some(native.pin_dir),
        schema_version: native.schema_version,
        schema_compatible: native.schema_compatible,
        policy_synced: native.policy_fingerprint == Some(desired_fingerprint),
        policy,
    })
}

fn policy_uses_native_only_features(policy: &VmNetworkPolicy) -> bool {
    policy.max_egress_mbps.is_some()
        || policy.max_egress_pps.is_some()
        || crate::ebpf::policy_contains_ipv6(policy)
}

/// Heal a missing/stale native TC attachment without disturbing a healthy
/// one. Called by scheduler reconciliation for running FluxVm VMs.
pub fn ensure_sandbox_policy(
    cfg: &Config,
    id: Uuid,
    iface: Option<&str>,
    extra_allow_cidrs: &[String],
) -> Result<bool> {
    let dp = &cfg.sandbox.dataplane;
    if dp.mode == DataplaneMode::Legacy {
        return Ok(false);
    }
    if dp.mode == DataplaneMode::Cilium {
        crate::cilium::validate_host()?;
    }
    let iface = iface.context("eBPF reconcile needs a host-visible VM interface")?;
    let base_policy = effective_policy(cfg, id)?;
    let desired_fingerprint = policy_fingerprint(&base_policy)?;
    let mut policy = base_policy;
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();

    let status = crate::ebpf::attachment_status(dp, id)?;
    if status.attached
        && status.interface.as_deref() == Some(iface)
        && status.policy_fingerprint == Some(desired_fingerprint)
    {
        return Ok(false);
    }
    crate::ebpf::apply(dp, &policy, id, iface)?;
    crate::ebpf::commit_policy_fingerprint(id, desired_fingerprint)?;
    Ok(true)
}

pub fn reconcile_orphan_pins(cfg: &Config, live_ids: &[Uuid]) -> Result<usize> {
    if cfg.sandbox.dataplane.mode == DataplaneMode::Legacy {
        return Ok(0);
    }
    crate::ebpf::reconcile_orphan_pins(&cfg.sandbox.dataplane, live_ids)
}

pub fn remove_sandbox_policy(cfg: &Config, id: Uuid) -> Result<()> {
    remove_nftables(id);
    if let Err(e) = crate::ebpf::remove(&cfg.sandbox.dataplane, id) {
        warn!(%id, error = %e, "eBPF dataplane cleanup failed");
    }
    Ok(())
}

/// Used by low-level network teardown which historically has no Config
/// argument. Scheduler paths perform config-aware cleanup first.
pub fn remove_sandbox_policy_best_effort(id: Uuid) -> Result<()> {
    remove_nftables(id);
    let _ = crate::ebpf::remove_best_effort(id);
    Ok(())
}

pub fn stats(cfg: &Config, id: Uuid) -> Result<DataplaneStats> {
    ensure_native_mode(cfg)?;
    crate::ebpf::stats(&cfg.sandbox.dataplane, id)
}

pub fn flows(cfg: &Config, id: Uuid, limit: usize) -> Result<Vec<FlowRecord>> {
    ensure_native_mode(cfg)?;
    crate::ebpf::flows(&cfg.sandbox.dataplane, id, limit)
}

fn ensure_native_mode(cfg: &Config) -> Result<()> {
    if cfg.sandbox.dataplane.mode == DataplaneMode::Legacy {
        anyhow::bail!("network stats/flows require sandbox.dataplane.mode=ebpf or cilium");
    }
    Ok(())
}

/// Install POSTROUTING masquerade for a source subnet. Kept public because
/// `netns.rs` uses it for the namespace transport NAT table independently
/// of the per-VM security policy table.
pub fn apply_subnet_masquerade(table: &str, source_cidr: &str) -> Result<()> {
    let _ = run_nft(&["delete", "table", "inet", table]);
    run_nft(&["add", "table", "inet", table])?;
    run_nft(&[
        "add", "chain", "inet", table, "postrouting", "{", "type", "nat", "hook",
        "postrouting", "priority", "srcnat;", "}",
    ])?;
    run_nft(&[
        "add", "rule", "inet", table, "postrouting", "ip", "saddr", source_cidr,
        "masquerade",
    ])?;
    Ok(())
}

fn apply_nftables(id: Uuid, guest_cidr: &str, policy: &VmNetworkPolicy) -> Result<()> {
    if policy_uses_native_only_features(policy) {
        anyhow::bail!(
            "IPv6 CIDR and egress rate-limit policy require sandbox.dataplane.mode=ebpf or cilium"
        );
    }
    let table = format!("fluxvm_{}", id.simple());
    apply_subnet_masquerade(&table, guest_cidr)?;

    let has_cidrs = !policy.allow_cidrs.is_empty();
    let has_ports = !policy.allow_ports.is_empty();
    let enforce = has_cidrs || has_ports || !policy.default_allow;
    if enforce {
        run_nft(&[
            "add", "chain", "inet", &table, "forward", "{", "type", "filter", "hook", "forward",
            "priority", "filter;", "policy", "drop;", "}",
        ])?;

        match (has_cidrs, has_ports) {
            (true, true) => {
                for cidr in &policy.allow_cidrs {
                    for rule in &policy.allow_ports {
                        let (proto, port) = parse_nft_port_rule(rule)?;
                        let port = port.to_string();
                        run_nft(&[
                            "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr,
                            "ip", "daddr", cidr, proto, "dport", &port, "accept",
                        ])?;
                    }
                }
            }
            (true, false) => {
                for cidr in &policy.allow_cidrs {
                    run_nft(&[
                        "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr,
                        "ip", "daddr", cidr, "accept",
                    ])?;
                }
            }
            (false, true) => {
                for rule in &policy.allow_ports {
                    let (proto, port) = parse_nft_port_rule(rule)?;
                    let port = port.to_string();
                    run_nft(&[
                        "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr,
                        proto, "dport", &port, "accept",
                    ])?;
                }
            }
            (false, false) => {}
        }

        if has_cidrs || has_ports {
            run_nft(&[
                "add", "rule", "inet", &table, "forward", "ct", "state",
                "established,related", "accept",
            ])?;
        }
    }

    info!(
        %id,
        %guest_cidr,
        cidrs = policy.allow_cidrs.len(),
        ports = policy.allow_ports.len(),
        max_egress_mbps = ?policy.max_egress_mbps,
        max_egress_pps = ?policy.max_egress_pps,
        default_allow = policy.default_allow,
        "applied nftables sandbox policy"
    );
    Ok(())
}

fn parse_nft_port_rule(raw: &str) -> Result<(&'static str, u16)> {
    let (proto, port) = raw
        .split_once('/')
        .with_context(|| format!("port rule {raw:?} must be tcp/PORT or udp/PORT"))?;
    let proto = match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        other => anyhow::bail!("unsupported L4 protocol {other:?}; use tcp or udp"),
    };
    let port: u16 = port.trim().parse()?;
    if port == 0 {
        anyhow::bail!("port must be 1..65535");
    }
    Ok((proto, port))
}

fn remove_nftables(id: Uuid) {
    let table = format!("fluxvm_{}", id.simple());
    let _ = remove_nft_table(&table);
}

pub fn remove_nft_table(table: &str) -> Result<()> {
    match run_nft(&["delete", "table", "inet", table]) {
        Ok(()) => Ok(()),
        Err(e) => {
            warn!(%table, error = %e, "nftables table delete (may not exist)");
            Ok(())
        }
    }
}

pub fn run_nft(args: &[&str]) -> Result<()> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .context("running nft (install nftables)")?;
    if !out.status.success() {
        anyhow::bail!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_permissive() {
        let p = VmNetworkPolicy::default();
        assert!(p.default_allow);
        assert!(p.allow_cidrs.is_empty());
        assert!(p.allow_ports.is_empty());
    }

    #[test]
    fn policy_round_trip_is_atomic_and_validated() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = VmNetworkPolicy {
            default_allow: false,
            allow_cidrs: vec!["10.0.0.0/8".into()],
            allow_ports: vec!["tcp/443".into()],
            max_egress_mbps: Some(100),
            max_egress_pps: Some(50_000),
            sample_rate: 10,
        };
        save_policy(&cfg, id, &policy).unwrap();
        assert_eq!(load_policy(&cfg, id).unwrap(), Some(policy.clone()));
        delete_policy(&cfg, id).unwrap();
        assert_eq!(load_policy(&cfg, id).unwrap(), None);
    }

    #[test]
    fn bad_l4_policy_is_rejected_before_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = VmNetworkPolicy {
            allow_ports: vec!["sctp/443".into()],
            ..VmNetworkPolicy::default()
        };
        assert!(save_policy(&cfg, id, &policy).is_err());
        assert!(!policy_path(&cfg, id).exists());
    }
    #[test]
    fn ipv6_policy_requires_native_dataplane() {
        let p = VmNetworkPolicy {
            allow_cidrs: vec!["2001:db8::/32".into()],
            ..VmNetworkPolicy::default()
        };
        assert!(policy_uses_native_only_features(&p));
    }

    #[test]
    fn policy_fingerprint_changes_with_security_semantics() {
        let base = VmNetworkPolicy::default();
        let mut changed = base.clone();
        changed.default_allow = false;
        assert_ne!(policy_fingerprint(&base).unwrap(), policy_fingerprint(&changed).unwrap());
        assert_eq!(policy_fingerprint(&base).unwrap(), policy_fingerprint(&base).unwrap());
    }

}
