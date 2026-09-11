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
use std::{fs, io::Write, net::IpAddr, path::PathBuf, process::Command};
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
    /// Destination CIDRs that drop even if an allow CIDR would match.
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    /// Allow ICMP / ICMPv6 echo and errors through L4 enforcement.
    #[serde(default)]
    pub allow_icmp: bool,
    /// Explicit security-group names. Combined with `labels`.
    #[serde(default)]
    pub groups: Vec<String>,
    /// `key=value` labels. A group matches when every group label is present.
    #[serde(default)]
    pub labels: Vec<String>,
    /// FQDN names/patterns from CNP `toFQDNs`; resolved at apply time.
    #[serde(default)]
    pub allow_fqdns: Vec<String>,
    /// Policy entities (`world`, `host`, `cluster`, …).
    #[serde(default)]
    pub entities: Vec<String>,
    /// Log-and-allow instead of drop (CNP audit mode).
    #[serde(default)]
    pub audit_mode: bool,
    /// Filled by group merge; not persisted as operator input.
    #[serde(default, skip_serializing)]
    pub compiled_group_ids: Vec<u32>,
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
            deny_cidrs: Vec::new(),
            allow_icmp: false,
            groups: Vec::new(),
            labels: Vec::new(),
            allow_fqdns: Vec::new(),
            entities: Vec::new(),
            audit_mode: false,
            compiled_group_ids: Vec::new(),
        }
    }
}

/// Set 14 directional Kubernetes-Pod policy. The Set 6S exact-address and
/// Set 13 exact peer+port fields remain wire-compatible for rolling upgrades;
/// schema_version=2 activates CIDR/L4 tuple rules and independent
/// ingress/egress isolation, replacing Set 6S/13's single flat
/// allow/deny-address model with a unified rule union checked by
/// `bpf/fluxvm_pod_policy.bpf.h`'s `fluxvm_prules` map. See
/// `crate::ebpf::validate_pod_policy` for the wire-shape invariants this
/// type does not enforce on its own.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PodPolicyProtocol {
    Tcp,
    Udp,
}

impl PodPolicyProtocol {
    /// Raw `IPPROTO_*` value as seen by the eBPF verdict functions.
    pub fn ip_protocol_number(self) -> u8 {
        match self {
            PodPolicyProtocol::Tcp => 6,
            PodPolicyProtocol::Udp => 17,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PodPeerPortRule {
    pub address: IpAddr,
    pub protocol: PodPolicyProtocol,
    pub port: u16,
}

/// Set 14: one OR-clause in the Kubernetes allow union. Rules are ORed
/// against each other; the fields inside one rule are ANDed. An empty
/// `protocol` with `port_start == port_end == 0` means "all L4
/// protocols/ports" for that peer CIDR. `direction` is `"ingress"` or
/// `"egress"` (validated by `crate::ebpf::validate_pod_policy`, not by
/// this type -- it's a plain wire/storage shape, matching `PodPeerPortRule`'s
/// own convention from Set 13).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodPolicyRule {
    pub direction: String,
    pub cidr: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub port_start: u16,
    #[serde(default)]
    pub port_end: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodNetworkPolicy {
    /// 0/1 (or omitted): legacy Set 6S/13 exact-address/port ABI, unchanged.
    /// >=2: this policy's `rules` are authoritative and the legacy
    /// `allow_addresses`/`allow_port_rules` fields are ignored by
    /// `configure_pod_maps`, even if still present for a rolling-upgrade
    /// reader.
    #[serde(default)]
    pub schema_version: u32,
    /// A peer with no explicit allow entry is denied when true. Set
    /// unconditionally whenever either direction is isolated (see
    /// `Compile()`'s own comment in the Go controller): an older Set 6S/13
    /// dataplane that doesn't understand `rules` at all still over-denies
    /// on a schema_version=2 policy instead of silently treating an
    /// ingress-only isolation as "no policy, allow all".
    #[serde(default)]
    pub default_deny: bool,
    /// Log-and-allow instead of drop, same semantics as
    /// `VmNetworkPolicy::audit_mode`.
    #[serde(default)]
    pub audit_mode: bool,
    #[serde(default)]
    pub allow_addresses: Vec<IpAddr>,
    #[serde(default)]
    pub deny_addresses: Vec<IpAddr>,
    /// Set 13 compatibility field, superseded by `rules` at
    /// schema_version>=2 -- kept so an older controller's wire format still
    /// parses.
    #[serde(default)]
    pub allow_port_rules: Vec<PodPeerPortRule>,
    #[serde(default)]
    pub egress_isolated: bool,
    #[serde(default)]
    pub ingress_isolated: bool,
    /// Set 14: the directional CIDR/L4 rule union. Only meaningful at
    /// schema_version>=2. Bounded by
    /// `crate::ebpf::MAX_POD_RULES`/`bpf/fluxvm_pod_policy.bpf.h`'s
    /// `FLUXVM_MAX_POD_RULE`.
    #[serde(default)]
    pub rules: Vec<PodPolicyRule>,
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
        deny_cidrs: Vec::new(),
        allow_icmp: false,
        groups: Vec::new(),
        labels: Vec::new(),
        allow_fqdns: Vec::new(),
        entities: Vec::new(),
        audit_mode: false,
        compiled_group_ids: Vec::new(),
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

/// Set 6S: persisted so a VM restart/reconcile re-applies whatever Pod
/// policy was last set instead of `apply()`'s fresh-attach path silently
/// resetting it to unconfigured every time. Keyed by VM id like
/// `policy_path`, not by `pod_id` -- each Secure Containers VM has at most
/// one Pod, so this needs no separate key space.
pub fn load_pod_policy(cfg: &Config, id: Uuid) -> Result<Option<PodNetworkPolicy>> {
    let path = pod_policy_path(cfg, id);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading Pod network policy {}", path.display()))?;
    let policy: PodNetworkPolicy = serde_json::from_str(&raw)
        .with_context(|| format!("parsing Pod network policy {}", path.display()))?;
    crate::ebpf::validate_pod_policy(&policy)?;
    Ok(Some(policy))
}

pub fn save_pod_policy(cfg: &Config, id: Uuid, policy: &PodNetworkPolicy) -> Result<()> {
    crate::ebpf::validate_pod_policy(policy)?;
    let path = pod_policy_path(cfg, id);
    let parent = path
        .parent()
        .context("Pod network policy path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating Pod network policy directory {}", parent.display()))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(policy)?)
        .with_context(|| format!("writing Pod network policy {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("committing Pod network policy {}", path.display()))
}

pub fn delete_pod_policy(cfg: &Config, id: Uuid) -> Result<()> {
    let path = pod_policy_path(cfg, id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting Pod network policy {}", path.display())),
    }
}

fn pod_policy_path(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.state_dir
        .join("network-pod-policy")
        .join(format!("{id}.json"))
}

fn policy_path(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.state_dir
        .join("network-policy")
        .join(format!("{id}.json"))
}

/// VM ids that have a persisted network policy file.
pub fn list_policy_vm_ids(cfg: &Config) -> Result<Vec<Uuid>> {
    let dir = cfg.state_dir.join("network-policy");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for ent in fs::read_dir(&dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if let Ok(id) = stem.parse::<Uuid>() {
            out.push(id);
        }
    }
    out.sort();
    Ok(out)
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
    pod_uid: Option<&str>,
) -> Result<()> {
    // Set 6S: mint (or recall) a stable Pod identity when the caller knows
    // this VM belongs to a Kubernetes Pod (Secure Containers). `0` means "no
    // Pod-scoped policy" throughout the eBPF layer, matching every other
    // sandbox that never supplies a pod_uid.
    let pod_id = match pod_uid {
        Some(uid) => crate::pod_identity::pod_id_for(cfg, uid)?,
        None => 0,
    };
    let pod_policy = if pod_id != 0 {
        load_pod_policy(cfg, id)?
    } else {
        None
    };
    let dp = &cfg.sandbox.dataplane;
    let base_policy = effective_policy(cfg, id)?;
    let base_fingerprint = policy_fingerprint(&base_policy)?;
    let (mut policy, _group_ids) = crate::groups::merge_group_policy(cfg, base_policy)?;
    if !policy.allow_fqdns.is_empty() {
        policy
            .allow_cidrs
            .extend(crate::egress::resolve_allow_cidrs_sync(&policy.allow_fqdns));
    }
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();
    if let Some(cidr) = guest_cidr {
        let hash_id = crate::ebpf::identity_for(id);
        let _ = crate::ipcache::upsert(cfg, cidr, hash_id, id);
        let mut ep = crate::endpoint::from_vm(
            id,
            &policy.labels,
            hash_id,
            Some(cidr),
            policy.default_allow,
            policy.audit_mode,
        );
        if dp.mode == DataplaneMode::Cilium {
            crate::endpoint::enrich_from_cilium_agent(&mut ep);
        }
        let _ = crate::endpoint::upsert(cfg, &ep);
    }

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
                crate::ebpf::apply(dp, &policy, id, iface, pod_id, pod_policy.as_ref())
            })();

            match native {
                Ok(()) => {
                    crate::ebpf::commit_policy_fingerprint(id, base_fingerprint)?;
                    crate::service::ensure_for_vm(cfg, id, iface)?;
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
    let (mut policy, _group_ids) = crate::groups::merge_group_policy(cfg, base_policy)?;
    if !policy.allow_fqdns.is_empty() {
        policy
            .allow_cidrs
            .extend(crate::egress::resolve_allow_cidrs_sync(&policy.allow_fqdns));
    }
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();
    if let Some(cidr) = guest_cidr {
        let hash_id = crate::ebpf::identity_for(id);
        let _ = crate::ipcache::upsert(cfg, cidr, hash_id, id);
        let mut ep = crate::endpoint::from_vm(
            id,
            &policy.labels,
            hash_id,
            Some(cidr),
            policy.default_allow,
            policy.audit_mode,
        );
        if dp.mode == DataplaneMode::Cilium {
            crate::endpoint::enrich_from_cilium_agent(&mut ep);
        }
        let _ = crate::endpoint::upsert(cfg, &ep);
    }

    match dp.mode {
        DataplaneMode::Legacy => {
            let cidr = guest_cidr
                .context("legacy nftables policy update requires a FluxVM-known guest CIDR")?;
            apply_nftables(id, cidr, &policy)
        }
        DataplaneMode::Ebpf | DataplaneMode::Cilium => {
            if dp.mode == DataplaneMode::Cilium {
                crate::cilium::validate_host()?;
            }
            let status = crate::ebpf::attachment_status(dp, id)?;
            // Service attach and (when needed) TC repair both need an iface:
            // prefer the caller's edge, else the currently attached one.
            let iface = iface.or(status.interface.as_deref()).context(
                "native policy update needs a host-visible VM interface to repair attachment",
            )?;
            if status.attached {
                crate::ebpf::reconfigure(dp, &policy, id)?;
            } else {
                // No fresh pod_uid at this call site (this is a policy
                // update, not a create/restart) -- preserve whatever Pod
                // identity/policy `apply_sandbox_policy`/`set_pod_network_policy`
                // last associated with this VM instead of dropping it on a repair.
                let pod_id = crate::ebpf::read_pod_id(id);
                let pod_policy = if pod_id != 0 {
                    load_pod_policy(cfg, id)?
                } else {
                    None
                };
                crate::ebpf::apply(dp, &policy, id, iface, pod_id, pod_policy.as_ref())?;
            }
            crate::ebpf::commit_policy_fingerprint(id, base_fingerprint)?;
            crate::service::ensure_for_vm(cfg, id, iface)?;
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
        || !policy.deny_cidrs.is_empty()
        || policy.audit_mode
        || !policy.compiled_group_ids.is_empty()
        || !policy.allow_fqdns.is_empty()
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
    let (mut policy, _group_ids) = crate::groups::merge_group_policy(cfg, base_policy)?;
    if !policy.allow_fqdns.is_empty() {
        policy
            .allow_cidrs
            .extend(crate::egress::resolve_allow_cidrs_sync(&policy.allow_fqdns));
    }
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();

    let service_repaired = crate::service::ensure_for_vm(cfg, id, iface)?;
    let status = crate::ebpf::attachment_status(dp, id)?;
    if status.attached
        && status.interface.as_deref() == Some(iface)
        && status.policy_fingerprint == Some(desired_fingerprint)
    {
        return Ok(service_repaired);
    }
    // Reconcile/heal path: no fresh pod_uid, preserve the VM's existing
    // Pod association (see reconfigure_sandbox_policy's identical comment).
    let repair_pod_id = crate::ebpf::read_pod_id(id);
    let repair_pod_policy = if repair_pod_id != 0 {
        load_pod_policy(cfg, id)?
    } else {
        None
    };
    crate::ebpf::apply(
        dp,
        &policy,
        id,
        iface,
        repair_pod_id,
        repair_pod_policy.as_ref(),
    )?;
    crate::ebpf::commit_policy_fingerprint(id, desired_fingerprint)?;
    crate::service::ensure_for_vm(cfg, id, iface)?;
    Ok(true)
}

/// Set 6S: populate (`Some`) or clear (`None`) a VM's Pod-scoped network
/// policy. The VM must already be attached with a nonzero Pod identity (see
/// `apply_sandbox_policy`'s `pod_uid` argument) -- this does not itself
/// resolve a Kubernetes `NetworkPolicy` object into peer addresses; that
/// translation is expected to live in a separate controller/watcher that
/// calls this once it has resolved concrete peer IPs.
pub fn set_pod_network_policy(
    cfg: &Config,
    id: Uuid,
    policy: Option<PodNetworkPolicy>,
) -> Result<()> {
    let dp = &cfg.sandbox.dataplane;
    if dp.mode == DataplaneMode::Legacy {
        anyhow::bail!("Pod-scoped network policy requires native eBPF mode");
    }
    // Apply live before persisting: a failed apply (e.g. the VM is not
    // attached yet) must not leave a "confirmed" policy on disk that a
    // later restart would apply without ever having been validated live.
    crate::ebpf::configure_pod_policy(dp, id, policy.as_ref())?;
    match &policy {
        Some(p) => save_pod_policy(cfg, id, p),
        None => delete_pod_policy(cfg, id),
    }
}

pub fn reconcile_orphan_pins(cfg: &Config, live_ids: &[Uuid]) -> Result<usize> {
    if cfg.sandbox.dataplane.mode == DataplaneMode::Legacy {
        return Ok(0);
    }
    crate::ebpf::reconcile_orphan_pins(&cfg.sandbox.dataplane, live_ids)
}

pub fn remove_sandbox_policy(cfg: &Config, id: Uuid) -> Result<()> {
    remove_nftables(id);
    let _ = crate::ipcache::remove_vm(cfg, id);
    let _ = crate::endpoint::remove(cfg, id);
    if let Err(e) = crate::ebpf::remove(&cfg.sandbox.dataplane, id) {
        warn!(%id, error = %e, "eBPF dataplane cleanup failed");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataplaneHealth {
    pub mode: String,
    pub required: bool,
    pub default_allow: bool,
    pub bpf_object_present: bool,
    pub pin_root_present: bool,
    pub bpffs_present: bool,
    pub cilium_socket_present: bool,
    pub groups: usize,
    pub policies: usize,
    pub ipcache_entries: usize,
    pub ok: bool,
    pub notes: Vec<String>,
}

pub fn health(cfg: &Config) -> Result<DataplaneHealth> {
    let dp = &cfg.sandbox.dataplane;
    let mode = format!("{:?}", dp.mode).to_ascii_lowercase();
    let bpf_object_present = dp.bpf_object.exists();
    let pin_root_present = dp.pin_root.exists();
    let bpffs_present = std::path::Path::new("/sys/fs/bpf").exists();
    let cilium_socket_present = std::path::Path::new("/var/run/cilium/cilium.sock").exists();
    let groups = crate::groups::list_groups(cfg)
        .map(|g| g.len())
        .unwrap_or(0);
    let policies = crate::cnp::list_cnp(cfg).map(|g| g.len()).unwrap_or(0);
    let ipcache_entries = crate::ipcache::list(cfg).map(|e| e.len()).unwrap_or(0);
    let mut notes = Vec::new();
    if matches!(dp.mode, DataplaneMode::Ebpf | DataplaneMode::Cilium) && !bpf_object_present {
        notes.push(format!("missing BPF object {}", dp.bpf_object.display()));
    }
    if dp.mode == DataplaneMode::Cilium && !cilium_socket_present {
        notes.push("mode=cilium but cilium.sock is not visible".into());
    }
    if dp.required
        && matches!(dp.mode, DataplaneMode::Ebpf | DataplaneMode::Cilium)
        && !bpffs_present
    {
        notes.push("required native dataplane but /sys/fs/bpf is missing".into());
    }
    let ok = notes.is_empty();
    Ok(DataplaneHealth {
        mode,
        required: dp.required,
        default_allow: dp.default_allow,
        bpf_object_present,
        pin_root_present,
        bpffs_present,
        cilium_socket_present,
        groups,
        policies,
        ipcache_entries,
        ok,
        notes,
    })
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
        "add",
        "chain",
        "inet",
        table,
        "postrouting",
        "{",
        "type",
        "nat",
        "hook",
        "postrouting",
        "priority",
        "srcnat;",
        "}",
    ])?;
    run_nft(&[
        "add",
        "rule",
        "inet",
        table,
        "postrouting",
        "ip",
        "saddr",
        source_cidr,
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
                        "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr, "ip",
                        "daddr", cidr, "accept",
                    ])?;
                }
            }
            (false, true) => {
                for rule in &policy.allow_ports {
                    let (proto, port) = parse_nft_port_rule(rule)?;
                    let port = port.to_string();
                    run_nft(&[
                        "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr, proto,
                        "dport", &port, "accept",
                    ])?;
                }
            }
            (false, false) => {}
        }

        if has_cidrs || has_ports {
            run_nft(&[
                "add",
                "rule",
                "inet",
                &table,
                "forward",
                "ct",
                "state",
                "established,related",
                "accept",
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
            ..VmNetworkPolicy::default()
        };
        save_policy(&cfg, id, &policy).unwrap();
        assert_eq!(load_policy(&cfg, id).unwrap(), Some(policy.clone()));
        delete_policy(&cfg, id).unwrap();
        assert_eq!(load_policy(&cfg, id).unwrap(), None);
    }

    #[test]
    fn pod_policy_round_trip_includes_port_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = PodNetworkPolicy {
            default_deny: true,
            audit_mode: false,
            allow_addresses: vec!["10.0.0.20".parse().unwrap()],
            deny_addresses: Vec::new(),
            allow_port_rules: vec![PodPeerPortRule {
                address: "10.0.0.30".parse().unwrap(),
                protocol: PodPolicyProtocol::Tcp,
                port: 5432,
            }],
            ..Default::default()
        };
        save_pod_policy(&cfg, id, &policy).unwrap();
        assert_eq!(load_pod_policy(&cfg, id).unwrap(), Some(policy));
        delete_pod_policy(&cfg, id).unwrap();
        assert_eq!(load_pod_policy(&cfg, id).unwrap(), None);
    }

    #[test]
    fn pod_policy_without_port_rules_field_still_parses() {
        // Set 13 added `allow_port_rules` after Set 6S shipped; a policy
        // persisted (or POSTed) by an older build must still parse with an
        // empty list, not fail to deserialize.
        let json = r#"{"default_deny":true,"audit_mode":false,"allow_addresses":["10.0.0.20"],"deny_addresses":[]}"#;
        let policy: PodNetworkPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.allow_port_rules.is_empty());
        assert_eq!(policy.schema_version, 0);
        assert!(policy.rules.is_empty());
        assert!(!policy.ingress_isolated);
        assert!(!policy.egress_isolated);
    }

    #[test]
    fn pod_policy_round_trip_includes_schema_v2_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = PodNetworkPolicy {
            schema_version: 2,
            default_deny: true,
            ingress_isolated: true,
            egress_isolated: true,
            rules: vec![
                PodPolicyRule {
                    direction: "egress".into(),
                    cidr: "10.0.1.0/24".into(),
                    protocol: String::new(),
                    port_start: 0,
                    port_end: 0,
                },
                PodPolicyRule {
                    direction: "ingress".into(),
                    cidr: "10.0.0.30/32".into(),
                    protocol: "TCP".into(),
                    port_start: 8000,
                    port_end: 8010,
                },
            ],
            ..Default::default()
        };
        save_pod_policy(&cfg, id, &policy).unwrap();
        assert_eq!(load_pod_policy(&cfg, id).unwrap(), Some(policy));
    }

    #[test]
    fn pod_policy_rejects_invalid_rule_direction() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = PodNetworkPolicy {
            schema_version: 2,
            rules: vec![PodPolicyRule {
                direction: "sideways".into(),
                cidr: "10.0.0.0/24".into(),
                protocol: String::new(),
                port_start: 0,
                port_end: 0,
            }],
            ..Default::default()
        };
        assert!(save_pod_policy(&cfg, id, &policy).is_err());
        assert!(pod_policy_path(&cfg, id).exists().eq(&false));
    }

    #[test]
    fn bad_l4_policy_is_rejected_before_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = VmNetworkPolicy {
            // Set 16 legitimately added VM-level "sctp/PORT" support, so
            // that string is no longer a valid example of a rejected L4
            // rule -- "gre/443" (a real IP protocol FluxVM has never
            // supported here) exercises the same "unsupported protocol"
            // rejection path this test is actually about.
            allow_ports: vec!["gre/443".into()],
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
        assert_ne!(
            policy_fingerprint(&base).unwrap(),
            policy_fingerprint(&changed).unwrap()
        );
        assert_eq!(
            policy_fingerprint(&base).unwrap(),
            policy_fingerprint(&base).unwrap()
        );
    }
}
