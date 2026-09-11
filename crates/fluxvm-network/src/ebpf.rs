// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! FluxVM-owned TC/eBPF dataplane loader and observability reader.
//!
//! The kernel programs live in `bpf/`.  The daemon intentionally uses
//! `bpftool` + `tc` rather than linking libbpf into every FluxVM binary: the
//! normal Rust dependency graph stays small and distro packages provide the
//! privileged kernel plumbing.  Each VM gets its own pin directory.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::DataplaneConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::dataplane::{PodNetworkPolicy, PodPolicyProtocol, PodPolicyRule, VmNetworkPolicy};
use crate::tcx::{self, Preference as TcxPreference};

const TC_PRIORITY: &str = "49152";
const TC_HANDLE: &str = "1";
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_ICMPV6: u8 = 58;
/// Set 14: keep in lockstep with `FLUXVM_MAX_POD_RULE` in
/// `bpf/fluxvm_pod_policy.bpf.h` -- 64, not the kit's original 512, because
/// a 512-iteration non-unrolled scan in `fluxvm_pod_policy_rich_verdict`
/// blows the kernel verifier's `BPF_COMPLEXITY_LIMIT_JMP_SEQ` (8192 jumps)
/// when present in both the v4 and v6 paths of one program.
const MAX_POD_RULES: usize = 64;
pub const DATAPLANE_SCHEMA_VERSION: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRule {
    protocol: u8,
    port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataplaneStats {
    pub allowed_packets: u64,
    pub allowed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowRecord {
    pub identity: u32,
    pub family: u8,
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub verdict: String,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

/// Exact branch accounting emitted by dataplane schema v6. Unlike Set-2
/// policy inference, these records identify the kernel branch that rejected
/// (or audit-allowed) a tuple, including rate and migration gates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropReasonRecord {
    pub identity: u32,
    pub family: u8,
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub reason_code: u32,
    pub reason: String,
    pub action: String,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeAttachmentStatus {
    pub attached: bool,
    pub interface: Option<String>,
    pub identity: u32,
    pub pin_dir: String,
    pub schema_version: Option<u32>,
    pub schema_compatible: bool,
    /// Fingerprint of the durable control-plane policy that was last fully
    /// committed to the kernel maps. `None` means an update may have been
    /// interrupted and reconcile must repair it.
    pub policy_fingerprint: Option<u64>,
}

pub fn apply(
    cfg: &DataplaneConfig,
    policy: &VmNetworkPolicy,
    id: Uuid,
    iface: &str,
    pod_id: u32,
    pod_policy: Option<&PodNetworkPolicy>,
) -> Result<()> {
    if iface.is_empty() {
        bail!("cannot attach eBPF dataplane without a host-visible interface");
    }
    if !cfg.bpf_object.exists() {
        bail!(
            "FluxVM eBPF object does not exist at {}",
            cfg.bpf_object.display()
        );
    }
    require_bpftool()?;
    // TCX does not depend on the legacy `tc` userspace tool. Require `tc`
    // only if the TCX path is disabled/unavailable and we actually fall back.
    raise_memlock()?;

    validate_policy(policy)?;
    let _ = remove(cfg, id);

    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    let prog_dir = vm_dir.join("progs");
    let map_dir = vm_dir.join("maps");
    fs::create_dir_all(&prog_dir)
        .with_context(|| format!("creating eBPF program pin dir {}", prog_dir.display()))?;
    fs::create_dir_all(&map_dir)
        .with_context(|| format!("creating eBPF map pin dir {}", map_dir.display()))?;
    // bpffs only accepts BPF objects. Interface/schema sidecars live on the
    // normal runtime filesystem so cleanup metadata survives without trying
    // to create regular files inside bpffs.
    let meta_dir = vm_meta_dir(id);
    fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating eBPF meta dir {}", meta_dir.display()))?;
    fs::write(meta_dir.join("iface"), iface)
        .with_context(|| format!("recording eBPF interface {iface}"))?;
    fs::write(meta_dir.join("pod_id"), pod_id.to_string())
        .context("recording FluxVM eBPF Pod identity")?;

    let prog_pin = prog_dir.join("fluxvm_egress");
    // `fluxvm_tc.bpf.o` carries exactly one SEC("tc") program again under
    // Set 14 -- the separate Pod-ingress object (`fluxvm_pod_ingress.bpf.o`)
    // is loaded lazily by `sync_pod_ingress_attachment` only when a Pod's
    // policy actually isolates ingress, sharing this object's pinned maps.
    if let Err(e) = run(
        "bpftool",
        &[
            "prog".into(),
            "load".into(),
            cfg.bpf_object.display().to_string(),
            prog_pin.display().to_string(),
            "type".into(),
            "classifier".into(),
            "pinmaps".into(),
            map_dir.display().to_string(),
        ],
    ) {
        let _ = fs::remove_dir_all(&vm_dir);
        let _ = fs::remove_dir_all(&meta_dir);
        return Err(e).context("loading FluxVM TC program");
    }

    let owned_program_id = match pinned_program_id(&prog_pin) {
        Ok(id) => id,
        Err(e) => {
            let _ = fs::remove_dir_all(&vm_dir);
            let _ = fs::remove_dir_all(&meta_dir);
            return Err(e).context("reading newly loaded FluxVM TC program id");
        }
    };
    if let Err(e) = fs::write(meta_dir.join("prog_id"), owned_program_id.to_string()) {
        let _ = fs::remove_dir_all(&vm_dir);
        let _ = fs::remove_dir_all(&meta_dir);
        return Err(e).context("recording FluxVM TC program id");
    }

    let attach = (|| -> Result<()> {
        let ifindex = read_ifindex(iface)?;
        let identity = identity_for(id);

        // Configure every policy map before the program becomes reachable
        // from TC. v2 attached first and had a tiny initial allow window
        // while fluxvm_id was still empty; v3 closes that window entirely.
        configure_maps(&map_dir, ifindex, identity, pod_id, policy, false)?;
        // Re-apply whatever Pod-scoped policy the caller loaded (persisted
        // via `set_pod_network_policy`) so a restart/repair doesn't silently
        // reset it to unconfigured. `None` (no persisted policy yet) leaves
        // it as a safe/allow no-op, same as an unconfigured VM-level policy.
        configure_pod_maps(&map_dir, pod_id, pod_policy)?;
        fs::write(meta_dir.join("schema_version"), DATAPLANE_SCHEMA_VERSION.to_string())
            .context("recording FluxVM eBPF schema version")?;

        let tcx_preference = TcxPreference::from_env()?;
        if tcx_preference != TcxPreference::Off {
            let link_pin = tcx::link_pin(&vm_dir);
            match tcx::attach(iface, &prog_pin, &link_pin) {
                Ok(status) => {
                    fs::write(meta_dir.join("attach_mode"), "tcx")
                        .context("recording FluxVM TCX attachment mode")?;
                    if let Some(revision) = status.revision {
                        fs::write(meta_dir.join("tcx_revision"), revision.to_string())
                            .context("recording FluxVM TCX revision")?;
                    }
                    info!(
                        %id,
                        %iface,
                        identity,
                        link_id = ?status.link_id,
                        revision = ?status.revision,
                        "attached FluxVM VM edge with TCX/BPF link"
                    );
                    return Ok(());
                }
                Err(e) if tcx_preference == TcxPreference::Required => {
                    return Err(e).context("attaching required FluxVM TCX dataplane");
                }
                Err(e) => warn!(
                    %id,
                    %iface,
                    error = %e,
                    "TCX unavailable; falling back to legacy clsact/tc"
                ),
            }
        }

        require_tc()?;
        ensure_clsact(iface).context("installing clsact qdisc")?;
        // Prefer `add` so a foreign owner of this pref/handle fails closed.
        // If a prior FluxVM attach left a filter (common after prog_id drift),
        // reclaim our slot on this iface first — `remove()` above already ran
        // with the recorded iface when present.
        if tc_filter_program_id(iface).ok().flatten().is_some() {
            let _ = run(
                "tc",
                &[
                    "filter".into(),
                    "del".into(),
                    "dev".into(),
                    iface.into(),
                    "ingress".into(),
                    "pref".into(),
                    TC_PRIORITY.into(),
                    "handle".into(),
                    TC_HANDLE.into(),
                    "bpf".into(),
                ],
            );
        }
        run(
            "tc",
            &[
                "filter".into(),
                "add".into(),
                "dev".into(),
                iface.into(),
                "ingress".into(),
                "pref".into(),
                TC_PRIORITY.into(),
                "handle".into(),
                TC_HANDLE.into(),
                "bpf".into(),
                "da".into(),
                "pinned".into(),
                prog_pin.display().to_string(),
            ],
        )
        .context("attaching FluxVM TC program")?;
        fs::write(meta_dir.join("attach_mode"), "tc")
            .context("recording FluxVM legacy TC attachment mode")?;

        info!(
            %id,
            %iface,
            identity,
            default_allow = policy.default_allow,
            cidrs = policy.allow_cidrs.len(),
            ports = policy.allow_ports.len(),
            max_egress_mbps = ?policy.max_egress_mbps,
            max_egress_pps = ?policy.max_egress_pps,
            sample_rate = policy.sample_rate,
            "attached FluxVM native eBPF dataplane"
        );
        Ok(())
    })();

    if attach.is_err() {
        let _ = remove(cfg, id);
        return attach;
    }
    attach?;
    if let Err(e) = sync_pod_ingress_attachment(cfg, id, iface, &map_dir, pod_policy) {
        let _ = remove(cfg, id);
        return Err(e).context("attaching Set 14 Pod ingress policy");
    }
    Ok(())
}

pub fn remove(cfg: &DataplaneConfig, id: Uuid) -> Result<()> {
    detach_pod_ingress_filter(cfg, id);
    let pin = vm_pin_dir(&cfg.pin_root, id);
    let owned_program_id = read_owned_program_id(id)
        .or_else(|| pinned_program_id(&pin.join("progs/fluxvm_egress")).ok());
    detach_tc_filter(id, owned_program_id);
    if pin.exists() {
        fs::remove_dir_all(&pin)
            .with_context(|| format!("removing eBPF pin dir {}", pin.display()))?;
    }
    let meta = vm_meta_dir(id);
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

/// Update a running VM in place. The TC program stays attached for the whole
/// operation. We first switch its interface config to deny-all, then replace
/// policy maps, then publish the final config. A failed update therefore
/// creates at worst a short over-deny window, never an allow-all gap.
pub fn reconfigure(
    cfg: &DataplaneConfig,
    policy: &VmNetworkPolicy,
    id: Uuid,
) -> Result<()> {
    require_bpftool()?;
    // Reconfigure mutates pinned maps in place; it is independent of whether
    // the program is attached by TCX or the legacy clsact path.
    validate_policy(policy)?;
    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    let map_dir = vm_dir.join("maps");
    let prog_pin = vm_dir.join("progs/fluxvm_egress");
    if !prog_pin.exists() {
        bail!("FluxVM eBPF program is not attached for VM {id}");
    }
    let meta_dir = vm_meta_dir(id);
    let schema = read_schema_version(&meta_dir);
    if schema != Some(DATAPLANE_SCHEMA_VERSION) {
        bail!(
            "VM {id} uses eBPF schema {:?}, expected {}; reattach before reconfigure",
            schema, DATAPLANE_SCHEMA_VERSION
        );
    }
    let iface = fs::read_to_string(meta_dir.join("iface"))
        .with_context(|| format!("reading VM {id} eBPF interface marker"))?;
    let iface = iface.trim();
    if iface.is_empty() {
        bail!("FluxVM eBPF interface marker is empty for VM {id}");
    }
    let ifindex = read_ifindex(iface)?;
    let identity = identity_for(id);
    let pod_id = read_pod_id(id);
    // Clear the commit marker before touching any policy map. If the daemon
    // dies mid-update, the next reconcile sees an unsynchronized policy and
    // repairs it instead of trusting a stale marker.
    invalidate_policy_fingerprint(id)?;
    configure_maps(&map_dir, ifindex, identity, pod_id, policy, true)?;
    info!(
        %id,
        %iface,
        identity,
        cidrs = policy.allow_cidrs.len(),
        ports = policy.allow_ports.len(),
        max_egress_mbps = ?policy.max_egress_mbps,
        max_egress_pps = ?policy.max_egress_pps,
        "updated FluxVM eBPF policy in place"
    );
    Ok(())
}

/// Set 6S: populate (or clear, with `policy = None`) a VM's Pod-scoped
/// network policy without a full re-attach. Requires the VM to already have
/// a Pod identity (`apply()` was called with a nonzero `pod_id`) and to be
/// currently attached; both are operator/caller errors, not something to
/// silently no-op, since a caller asking to set Pod policy presumably wants
/// to know if it did not take effect.
pub fn configure_pod_policy(
    cfg: &DataplaneConfig,
    id: Uuid,
    policy: Option<&PodNetworkPolicy>,
) -> Result<()> {
    require_bpftool()?;
    let pod_id = read_pod_id(id);
    if pod_id == 0 {
        bail!("VM {id} has no associated Pod identity; nothing to configure");
    }
    let map_dir = vm_pin_dir(&cfg.pin_root, id).join("maps");
    if !map_dir.join("fluxvm_pspol").exists() {
        bail!("VM {id} eBPF dataplane is not attached (or predates Set 6S); attach before setting Pod policy");
    }
    configure_pod_maps(&map_dir, pod_id, policy)?;
    let iface = read_recorded_iface(id)
        .context("FluxVM eBPF interface marker is missing while setting Pod policy")?;
    sync_pod_ingress_attachment(cfg, id, &iface, &map_dir, policy)
}

pub fn attachment_status(cfg: &DataplaneConfig, id: Uuid) -> Result<NativeAttachmentStatus> {
    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    let iface = read_recorded_iface(id);
    let prog_pin = vm_dir.join("progs/fluxvm_egress");
    let meta_dir = vm_meta_dir(id);
    let schema_version = read_schema_version(&meta_dir);
    let schema_compatible = schema_version == Some(DATAPLANE_SCHEMA_VERSION);
    let policy_fingerprint = read_policy_fingerprint(&meta_dir);
    let owned_program_id = read_owned_program_id(id)
        .or_else(|| pinned_program_id(&prog_pin).ok());
    let tcx_link = tcx::link_pin(&vm_dir);
    let tcx_program_id = if tcx_link.exists() {
        tcx::status(&tcx_link).ok().and_then(|status| status.prog_id)
    } else {
        None
    };
    let attached = if let (Some(iface), Some(owned_program_id)) =
        (iface.as_deref(), owned_program_id)
    {
        schema_compatible
            && prog_pin.exists()
            && (tcx_program_id == Some(owned_program_id)
                || tc_filter_program_id(iface).ok().flatten() == Some(owned_program_id))
    } else {
        false
    };
    Ok(NativeAttachmentStatus {
        attached,
        interface: iface,
        identity: identity_for(id),
        pin_dir: vm_dir.display().to_string(),
        schema_version,
        schema_compatible,
        policy_fingerprint,
    })
}

/// Ensure a live VM has the current FluxVM TC schema attached. Returns true
/// when repair/re-attachment was necessary and false when the existing
/// attachment was already healthy.
pub fn ensure(
    cfg: &DataplaneConfig,
    policy: &VmNetworkPolicy,
    id: Uuid,
    iface: &str,
) -> Result<bool> {
    let status = attachment_status(cfg, id)?;
    if status.attached && status.interface.as_deref() == Some(iface) {
        return Ok(false);
    }
    // No fresh pod_uid at this call site; preserve the VM's existing Pod
    // association (see dataplane::reconfigure_sandbox_policy's comment).
    // Unreachable today (nothing in-tree calls `ensure`), and this narrower
    // `DataplaneConfig` has no access to the state_dir persisted Pod policy
    // lives under, so this cannot re-apply Pod-scoped policy content on its
    // own -- a real caller should prefer `dataplane::ensure_sandbox_policy`.
    apply(cfg, policy, id, iface, read_pod_id(id), None)?;
    Ok(true)
}

/// Remove stale per-VM pin directories left behind by a daemon crash after
/// the VM record itself disappeared. Only UUID-shaped directories below the
/// FluxVM-owned `vms/` root are considered; unrelated bpffs content is never
/// touched.
pub fn reconcile_orphan_pins(cfg: &DataplaneConfig, live_ids: &[Uuid]) -> Result<usize> {
    let pin_root = cfg.pin_root.join("vms");
    let meta_root = vm_meta_root();
    let mut candidates = Vec::new();
    for root in [&pin_root, &meta_root] {
        if !root.exists() {
            continue;
        }
        for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(id) = Uuid::parse_str(name) else { continue };
            if !live_ids.contains(&id) && !candidates.contains(&id) {
                candidates.push(id);
            }
        }
    }
    for id in &candidates {
        remove(cfg, *id)?;
    }
    Ok(candidates.len())
}

fn read_schema_version(meta_dir: &Path) -> Option<u32> {
    fs::read_to_string(meta_dir.join("schema_version"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Set 6S: the Pod identity `apply()` last associated with this VM, or `0`
/// (no Pod-scoped policy) for VMs attached before Set 6S or never given one.
/// Reconcile/update paths that don't have a fresh Pod UID to mint from read
/// this back rather than resetting a VM's Pod association on every repair.
pub fn read_pod_id(id: Uuid) -> u32 {
    fs::read_to_string(vm_meta_dir(id).join("pod_id"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn read_policy_fingerprint(meta_dir: &Path) -> Option<u64> {
    fs::read_to_string(meta_dir.join("policy_fingerprint"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Publish the durable-policy generation only after all kernel map updates
/// completed successfully. The control plane owns the fingerprint because it
/// deliberately excludes transient DNS-resolved extra CIDRs.
pub fn commit_policy_fingerprint(id: Uuid, fingerprint: u64) -> Result<()> {
    let meta_dir = vm_meta_dir(id);
    fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating eBPF meta dir {}", meta_dir.display()))?;
    let tmp = meta_dir.join("policy_fingerprint.tmp");
    fs::write(&tmp, fingerprint.to_string())
        .with_context(|| format!("writing policy fingerprint for VM {id}"))?;
    fs::rename(&tmp, meta_dir.join("policy_fingerprint"))
        .with_context(|| format!("committing policy fingerprint for VM {id}"))?;
    Ok(())
}

pub fn invalidate_policy_fingerprint(id: Uuid) -> Result<()> {
    let path = vm_meta_dir(id).join("policy_fingerprint");
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| {
            format!("invalidating policy fingerprint for VM {id}")
        }),
    }
}

/// Cleanup fallback for callers that do not have Config. Config-aware
/// scheduler paths call `remove()`; this catches the normal default and an
/// operator-supplied environment override after crashes/partial failures.
pub fn remove_best_effort(id: Uuid) -> Result<()> {
    let mut dirs = vec![vm_pin_dir(Path::new("/sys/fs/bpf/fluxvm"), id)];
    if let Ok(root) = std::env::var("FLUXVM_BPF_PIN_ROOT") {
        let p = vm_pin_dir(Path::new(&root), id);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    let owned_program_id = read_owned_program_id(id).or_else(|| {
        dirs.iter()
            .find_map(|d| pinned_program_id(&d.join("progs/fluxvm_egress")).ok())
    });
    for dir in &dirs {
        detach_pod_ingress_filter_in_vm_dir(id, dir);
    }
    detach_tc_filter(id, owned_program_id);
    for dir in dirs {
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
    }
    let meta = vm_meta_dir(id);
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

fn detach_tc_filter(id: Uuid, owned_program_id: Option<u32>) {
    let Some(iface) = read_recorded_iface(id) else { return };
    match tc_filter_program_id(&iface) {
        Ok(Some(current)) => {
            // The interface name is recorded for this VM's pin metadata, so the
            // FluxVM pref/handle on that iface is ours to reclaim — even when
            // prog_id drifted (failed reload left a new meta id and an old
            // kernel filter). Refuse only when we have no recorded iface.
            if let Some(owned) = owned_program_id {
                if current != owned {
                    tracing::warn!(
                        %id,
                        %iface,
                        owned_program_id = owned,
                        current_program_id = current,
                        "stale TC filter program id on recorded FluxVM iface; reclaiming pref/handle"
                    );
                }
            } else {
                tracing::warn!(
                    %id,
                    %iface,
                    current_program_id = current,
                    "missing FluxVM TC ownership marker; reclaiming pref/handle on recorded iface"
                );
            }
            let _ = run(
                "tc",
                &[
                    "filter".into(),
                    "del".into(),
                    "dev".into(),
                    iface,
                    "ingress".into(),
                    "pref".into(),
                    TC_PRIORITY.into(),
                    "handle".into(),
                    TC_HANDLE.into(),
                    "bpf".into(),
                ],
            );
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            %id,
            %iface,
            error = %e,
            "unable to verify TC filter; attempting reclaim of FluxVM pref/handle"
        ),
    }
}

fn read_owned_program_id(id: Uuid) -> Option<u32> {
    fs::read_to_string(vm_meta_dir(id).join("prog_id"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

fn read_recorded_iface(id: Uuid) -> Option<String> {
    let meta = vm_meta_dir(id).join("iface");
    if let Ok(iface) = fs::read_to_string(&meta) {
        let iface = iface.trim();
        if !iface.is_empty() {
            return Some(iface.to_string());
        }
    }
    // Compatibility with the earliest development builds that attempted a
    // regular-file sidecar under bpffs.
    for root in [
        PathBuf::from("/sys/fs/bpf/fluxvm"),
        std::env::var("FLUXVM_BPF_PIN_ROOT")
            .ok().map(PathBuf::from).unwrap_or_default(),
    ] {
        if root.as_os_str().is_empty() { continue; }
        if let Ok(iface) = fs::read_to_string(vm_pin_dir(&root, id).join("iface")) {
            let iface = iface.trim();
            if !iface.is_empty() { return Some(iface.to_string()); }
        }
    }
    None
}

fn vm_meta_root() -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root).join("vms");
    }
    PathBuf::from("/run/fluxvm/ebpf/vms")
}

fn vm_meta_dir(id: Uuid) -> PathBuf {
    vm_meta_root().join(id.simple().to_string())
}

pub fn stats(cfg: &DataplaneConfig, id: Uuid) -> Result<DataplaneStats> {
    let map = vm_pin_dir(&cfg.pin_root, id).join("maps/fluxvm_stats");
    let json = bpftool_json_dump(&map)?;
    parse_stats_json(&json)
}

pub fn flows(cfg: &DataplaneConfig, id: Uuid, limit: usize) -> Result<Vec<FlowRecord>> {
    let map = vm_pin_dir(&cfg.pin_root, id).join("maps/fluxvm_flows");
    let json = bpftool_json_dump(&map)?;
    let mut records = parse_flows_json(&json)?;
    records.sort_by(|a, b| b.last_seen_ns.cmp(&a.last_seen_ns));
    records.truncate(limit.clamp(1, 4096));
    Ok(records)
}

/// Kernel-native VM-edge branch reasons. Requires dataplane schema v6.
pub fn drop_reasons(
    cfg: &DataplaneConfig,
    id: Uuid,
    limit: usize,
) -> Result<Vec<DropReasonRecord>> {
    let map = vm_pin_dir(&cfg.pin_root, id).join("maps/fluxvm_drop_reasons");
    let json = bpftool_json_dump(&map)?;
    let mut records = parse_drop_reasons_json(&json)?;
    records.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| b.last_seen_ns.cmp(&a.last_seen_ns))
    });
    records.truncate(limit.clamp(1, 4096));
    Ok(records)
}

pub fn validate_policy(policy: &VmNetworkPolicy) -> Result<()> {
    for cidr in &policy.allow_cidrs {
        parse_ip_cidr(cidr)
            .with_context(|| format!("invalid eBPF allow CIDR {cidr:?}"))?;
    }
    for cidr in &policy.deny_cidrs {
        parse_ip_cidr(cidr)
            .with_context(|| format!("invalid eBPF deny CIDR {cidr:?}"))?;
    }
    for rule in &policy.allow_ports {
        parse_port_rule(rule)
            .with_context(|| format!("invalid eBPF L4 rule {rule:?}"))?;
    }
    if let Some(mbps) = policy.max_egress_mbps {
        let _ = mbps_to_bytes_per_second(mbps)?;
    }
    if policy.max_egress_pps == Some(0) {
        bail!("max_egress_pps must be greater than zero when set");
    }
    Ok(())
}

/// Set 14: validates a `schema_version >= 2` policy's rich rules before any
/// map write. A no-op for a legacy (`schema_version < 2`) policy, which is
/// validated by `save_pod_policy`/`load_pod_policy` in `dataplane.rs`
/// instead (exact-address/port fields there are already strongly typed).
pub fn validate_pod_policy(policy: &PodNetworkPolicy) -> Result<()> {
    if policy.schema_version < 2 {
        return Ok(());
    }
    if policy.rules.len() > MAX_POD_RULES {
        bail!(
            "Pod policy has {} rules; maximum is {}",
            policy.rules.len(),
            MAX_POD_RULES
        );
    }
    for (i, rule) in policy.rules.iter().enumerate() {
        match rule.direction.to_ascii_lowercase().as_str() {
            "ingress" | "egress" => {}
            _ => bail!("Pod rule {i} has invalid direction {:?}", rule.direction),
        }
        parse_ip_cidr(&rule.cidr)
            .with_context(|| format!("Pod rule {i} has invalid CIDR {:?}", rule.cidr))?;
        match rule.protocol.to_ascii_uppercase().as_str() {
            "" if rule.port_start == 0 && rule.port_end == 0 => {}
            "TCP" | "UDP" | "SCTP" => {
                if (rule.port_start == 0) != (rule.port_end == 0)
                    || (rule.port_start != 0 && rule.port_end < rule.port_start)
                {
                    bail!(
                        "Pod rule {i} has invalid port interval {}..{}",
                        rule.port_start, rule.port_end
                    );
                }
            }
            other => bail!("Pod rule {i} has invalid protocol {other:?}"),
        }
    }
    Ok(())
}

pub(crate) fn vm_pin_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join("vms").join(id.simple().to_string())
}

pub fn identity_for(id: Uuid) -> u32 {
    // Mix all 128 UUID bits down to a stable non-zero u32. Map state is
    // private per VM, so this identity is primarily useful in telemetry and
    // survives interface recreation without relying on ifindex/IP.
    let n = id.as_u128();
    let raw = (n as u32) ^ ((n >> 32) as u32) ^ ((n >> 64) as u32) ^ ((n >> 96) as u32);
    raw.max(1)
}

fn read_ifindex(iface: &str) -> Result<u32> {
    let raw = fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("reading ifindex for {iface}"))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("parsing ifindex for {iface}"))
}

fn configure_maps(
    map_dir: &Path,
    ifindex: u32,
    identity: u32,
    pod_id: u32,
    policy: &VmNetworkPolicy,
    fail_closed_first: bool,
) -> Result<()> {
    let id_map = map_dir.join("fluxvm_id");
    let cidr4_map = map_dir.join("fluxvm_v4");
    let cidr6_map = map_dir.join("fluxvm_v6");
    let deny4_map = map_dir.join("fluxvm_deny4");
    let deny6_map = map_dir.join("fluxvm_deny6");
    let l4_map = map_dir.join("fluxvm_l4");
    if fail_closed_first {
        // Publish deny-all first, before deleting any old allowlist keys.
        update_iface_config(
            &id_map, ifindex, identity, false, false, false, 0, false, 0, 0, pod_id,
        )?;
    }

    clear_map(&cidr4_map)?;
    clear_map(&cidr6_map)?;
    if deny4_map.exists() {
        let _ = clear_map(&deny4_map);
    }
    if deny6_map.exists() {
        let _ = clear_map(&deny6_map);
    }
    clear_map(&l4_map)?;

    for cidr in &policy.allow_cidrs {
        match parse_ip_cidr(cidr)? {
            IpCidr::V4(cidr) => update_ipv4_allow(&cidr4_map, identity, cidr)?,
            IpCidr::V6(cidr) => update_ipv6_allow(&cidr6_map, identity, cidr)?,
        }
    }
    for cidr in &policy.deny_cidrs {
        match parse_ip_cidr(cidr)? {
            IpCidr::V4(cidr) if deny4_map.exists() => {
                update_ipv4_allow(&deny4_map, identity, cidr)?
            }
            IpCidr::V6(cidr) if deny6_map.exists() => {
                update_ipv6_allow(&deny6_map, identity, cidr)?
            }
            _ => {}
        }
    }
    for rule in &policy.allow_ports {
        update_l4_allow(&l4_map, identity, parse_port_rule(rule)?)?;
    }

    let rate_bytes = policy
        .max_egress_mbps
        .map(mbps_to_bytes_per_second)
        .transpose()?
        .unwrap_or(0);
    let rate_packets = policy.max_egress_pps.map(u64::from).unwrap_or(0);
    let packed_sample = policy.sample_rate
        | if policy.audit_mode {
            1u32 << 31
        } else {
            0
        };

    let gid_map = map_dir.join("fluxvm_gid");
    if gid_map.exists() {
        let _ = write_group_ids(&gid_map, ifindex, &policy.compiled_group_ids);
    }

    update_iface_config(
        &id_map,
        ifindex,
        identity,
        policy.default_allow,
        !policy.allow_cidrs.is_empty(),
        !policy.allow_ports.is_empty(),
        packed_sample,
        policy.allow_icmp,
        rate_bytes,
        rate_packets,
        pod_id,
    )
}

/// Set 6S: populate the Pod-scoped identity ACL (`fluxvm_pspol`/
/// `fluxvm_pid4`/`fluxvm_pid6`), independent of the VM-level CIDR/L4 maps
/// `configure_maps` already owns. A no-op when `pod_id == 0` (VM has no
/// associated Pod, e.g. non-Secure-Containers sandboxes) or when `policy` is
/// `None` (Pod identity associated, but no Pod-scoped policy configured yet
/// -- `fluxvm_tc.bpf.c` treats a missing `fluxvm_pspol` entry as allow, so
/// this intentionally leaves the map empty rather than writing a
/// default-enabled-but-empty entry).
fn configure_pod_maps(map_dir: &Path, pod_id: u32, policy: Option<&PodNetworkPolicy>) -> Result<()> {
    if pod_id == 0 {
        return Ok(());
    }
    let pspol_map = map_dir.join("fluxvm_pspol");
    let pid4_map = map_dir.join("fluxvm_pid4");
    let pid6_map = map_dir.join("fluxvm_pid6");
    // Set 13: may be absent on a fluxvm_tc.bpf.o built before this Set --
    // port rules are then silently skipped rather than failing the whole
    // apply, same graceful-degradation shape as the `!pspol_map.exists()`
    // check below for Set 6S itself.
    let pid4_port_map = map_dir.join("fluxvm_pid4_port");
    let pid6_port_map = map_dir.join("fluxvm_pid6_port");
    // Set 14: the unified rich-rule map. Absent on a fluxvm_tc.bpf.o built
    // before this Set -- `schema_version >= 2` policy is then a hard error
    // (see `bail!` below) rather than a silent downgrade, since a caller
    // that asked for CIDR/L4 tuple rules presumably wants to know they did
    // not take effect.
    let prules_map = map_dir.join("fluxvm_prules");
    if !pspol_map.exists() {
        // Older fluxvm_tc.bpf.o predating Set 6S; nothing to configure.
        return Ok(());
    }

    let Some(policy) = policy else {
        let key = pod_id.to_ne_bytes();
        let _ = run(
            "bpftool",
            &[
                "map".into(), "delete".into(), "pinned".into(),
                pspol_map.display().to_string(), "key".into(), "hex".into(),
            ]
            .into_iter()
            .chain(hex_args(&key))
            .collect::<Vec<_>>(),
        );
        if prules_map.exists() {
            let _ = clear_map(&prules_map);
        }
        return Ok(());
    };
    validate_pod_policy(policy)?;

    // Fail-closed-first when the policy actually restricts traffic: publish
    // the flags before clearing old allow entries, mirroring
    // configure_maps's own ordering for the VM-level CIDR maps.
    const FLUXVM_PSPOL_ENABLED: u32 = 1 << 0;
    const FLUXVM_PSPOL_DEFAULT_DENY: u32 = 1 << 1;
    const FLUXVM_PSPOL_AUDIT: u32 = 1 << 2;
    // Set 14: RICH marks a `schema_version >= 2` policy so
    // `fluxvm_pod_policy_rich_verdict` scans `fluxvm_prules` instead of the
    // legacy exact-address/port maps; EGRESS_ISOLATED/INGRESS_ISOLATED are
    // independent per-direction default-deny switches, replacing the single
    // `default_deny` bit for rich policies.
    const FLUXVM_PSPOL_RICH: u32 = 1 << 3;
    const FLUXVM_PSPOL_EGRESS_ISOLATED: u32 = 1 << 4;
    const FLUXVM_PSPOL_INGRESS_ISOLATED: u32 = 1 << 5;
    let rich = policy.schema_version >= 2;
    let mut flags = FLUXVM_PSPOL_ENABLED;
    if policy.default_deny {
        flags |= FLUXVM_PSPOL_DEFAULT_DENY;
    }
    if policy.audit_mode {
        flags |= FLUXVM_PSPOL_AUDIT;
    }
    if rich {
        flags |= FLUXVM_PSPOL_RICH;
        if policy.egress_isolated {
            flags |= FLUXVM_PSPOL_EGRESS_ISOLATED;
        }
        if policy.ingress_isolated {
            flags |= FLUXVM_PSPOL_INGRESS_ISOLATED;
        }
    }

    let restrictive = if rich {
        policy.egress_isolated || policy.ingress_isolated
    } else {
        policy.default_deny
    };
    if restrictive {
        update_pod_policy(&pspol_map, pod_id, flags, 0, policy.schema_version)?;
    }

    clear_pod_scoped_map(&pid4_map, pod_id, 4)?;
    clear_pod_scoped_map(&pid6_map, pod_id, 16)?;
    if pid4_port_map.exists() {
        clear_pod_scoped_map(&pid4_port_map, pod_id, 4 + 1 + 1 + 2)?;
    }
    if pid6_port_map.exists() {
        clear_pod_scoped_map(&pid6_port_map, pod_id, 16 + 1 + 1 + 2)?;
    }
    if prules_map.exists() {
        clear_map(&prules_map)?;
    }

    if rich {
        if !prules_map.exists() {
            bail!("Set 14 Pod rule map is missing; rebuild/reattach fluxvm_tc.bpf.o");
        }
        for (slot, rule) in policy.rules.iter().enumerate() {
            update_pod_rule(&prules_map, slot as u32, pod_id, rule)?;
        }
        update_pod_policy(&pspol_map, pod_id, flags, policy.rules.len() as u32, policy.schema_version)
    } else {
        for addr in &policy.allow_addresses {
            update_pod_peer(&pid4_map, &pid6_map, pod_id, *addr, 1)?;
        }
        for addr in &policy.deny_addresses {
            update_pod_peer(&pid4_map, &pid6_map, pod_id, *addr, 2)?;
        }
        if pid4_port_map.exists() && pid6_port_map.exists() {
            for rule in &policy.allow_port_rules {
                update_pod_peer_port(&pid4_port_map, &pid6_port_map, pod_id, rule.address, rule.protocol, rule.port, 1)?;
            }
        }
        update_pod_policy(&pspol_map, pod_id, flags, 0, policy.schema_version)
    }
}

/// Set 14: writes one `struct fluxvm_pod_rule` (28-byte ABI: `pod_id,
/// direction, family, protocol, prefix_len, port_start, port_end, address`)
/// into `fluxvm_prules` at the given array slot. Key layout and byte order
/// must match `bpf/fluxvm_pod_policy.bpf.h` field-for-field.
fn update_pod_rule(map: &Path, slot: u32, pod_id: u32, rule: &PodPolicyRule) -> Result<()> {
    let cidr = parse_ip_cidr(&rule.cidr)?;
    let direction = match rule.direction.to_ascii_lowercase().as_str() {
        "egress" => 1u8,
        "ingress" => 2u8,
        other => bail!("invalid Pod policy direction {other:?}"),
    };
    let protocol = match rule.protocol.to_ascii_uppercase().as_str() {
        "" => 0u8,
        "TCP" => IPPROTO_TCP,
        "UDP" => IPPROTO_UDP,
        "SCTP" => IPPROTO_SCTP,
        other => bail!("invalid Pod policy protocol {other:?}"),
    };
    let (family, prefix, address) = match cidr {
        IpCidr::V4(v4) => {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&v4.network.octets());
            (4u8, v4.prefix, a)
        }
        IpCidr::V6(v6) => (6u8, v6.prefix, v6.network.octets()),
    };
    let mut value = Vec::with_capacity(28);
    value.extend_from_slice(&pod_id.to_ne_bytes());
    value.extend_from_slice(&[direction, family, protocol, prefix]);
    value.extend_from_slice(&rule.port_start.to_ne_bytes());
    value.extend_from_slice(&rule.port_end.to_ne_bytes());
    value.extend_from_slice(&address);
    bpftool_map_update(map, &slot.to_ne_bytes(), &value)
}

fn update_pod_policy(map: &Path, pod_id: u32, flags: u32, rule_count: u32, schema_version: u32) -> Result<()> {
    let key = pod_id.to_ne_bytes();
    let mut value = Vec::with_capacity(16);
    value.extend_from_slice(&flags.to_ne_bytes());
    value.extend_from_slice(&rule_count.to_ne_bytes());
    value.extend_from_slice(&schema_version.to_ne_bytes());
    value.extend_from_slice(&0u32.to_ne_bytes());
    bpftool_map_update(map, &key, &value)
}

fn update_pod_peer(
    pid4_map: &Path,
    pid6_map: &Path,
    pod_id: u32,
    addr: IpAddr,
    verdict: u32,
) -> Result<()> {
    match addr {
        IpAddr::V4(v4) => {
            let mut key = Vec::with_capacity(8);
            key.extend_from_slice(&pod_id.to_ne_bytes());
            key.extend_from_slice(&v4.octets());
            bpftool_map_update(pid4_map, &key, &verdict.to_ne_bytes())
        }
        IpAddr::V6(v6) => {
            let mut key = Vec::with_capacity(20);
            key.extend_from_slice(&pod_id.to_ne_bytes());
            key.extend_from_slice(&v6.octets());
            bpftool_map_update(pid6_map, &key, &verdict.to_ne_bytes())
        }
    }
}

/// Set 13: writes one exact protocol+port allow entry for a peer that has no
/// address-wide `fluxvm_pid4`/`fluxvm_pid6` entry. Key layout must match
/// `struct fluxvm_pid4_port_key`/`fluxvm_pid6_port_key` in
/// `bpf/fluxvm_pod_policy.bpf.h` field-for-field: pod_id, raw address octets,
/// protocol, one pad byte, then port in the host's native byte order (the
/// BPF side already normalizes the packet's port via `bpf_ntohs` before
/// comparing, so both sides agree on host order here, same as every other
/// native-endian map key in this file).
fn update_pod_peer_port(
    pid4_port_map: &Path,
    pid6_port_map: &Path,
    pod_id: u32,
    addr: IpAddr,
    protocol: PodPolicyProtocol,
    port: u16,
    verdict: u32,
) -> Result<()> {
    let proto = protocol.ip_protocol_number();
    match addr {
        IpAddr::V4(v4) => {
            let mut key = Vec::with_capacity(12);
            key.extend_from_slice(&pod_id.to_ne_bytes());
            key.extend_from_slice(&v4.octets());
            key.push(proto);
            key.push(0);
            key.extend_from_slice(&port.to_ne_bytes());
            bpftool_map_update(pid4_port_map, &key, &verdict.to_ne_bytes())
        }
        IpAddr::V6(v6) => {
            let mut key = Vec::with_capacity(24);
            key.extend_from_slice(&pod_id.to_ne_bytes());
            key.extend_from_slice(&v6.octets());
            key.push(proto);
            key.push(0);
            key.extend_from_slice(&port.to_ne_bytes());
            bpftool_map_update(pid6_port_map, &key, &verdict.to_ne_bytes())
        }
    }
}

/// Deletes only this `pod_id`'s entries from a shared `fluxvm_pid4`/
/// `fluxvm_pid6` map instance. Unlike `clear_map` (used for the VM-level
/// `fluxvm_v4`/`fluxvm_v6` maps, which are private per VM via `pinmaps`),
/// these entries are additionally namespaced by the `pod_id` prefix of the
/// key even though the map instance itself is also per-VM -- kept
/// pod_id-scoped for defense in depth if a future Set ever changes that.
fn clear_pod_scoped_map(map: &Path, pod_id: u32, addr_len: usize) -> Result<()> {
    if !map.exists() {
        return Ok(());
    }
    let root = bpftool_json_dump(map)?;
    let entries = root.as_array().context("bpftool map dump must be an array")?;
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        if key.len() != 4 + addr_len || key[..4] != pod_id.to_ne_bytes() {
            continue;
        }
        let mut args = vec![
            "map".into(), "delete".into(), "pinned".into(),
            map.display().to_string(), "key".into(), "hex".into(),
        ];
        args.extend(hex_args(&key));
        run("bpftool", &args)?;
    }
    Ok(())
}

fn write_group_ids(map: &Path, ifindex: u32, ids: &[u32]) -> Result<()> {
    let key = Vec::from(ifindex.to_ne_bytes());
    let mut value = Vec::with_capacity(36);
    let n = ids.len().min(8) as u32;
    value.extend_from_slice(&n.to_ne_bytes());
    for i in 0..8 {
        let id = ids.get(i).copied().unwrap_or(0);
        value.extend_from_slice(&id.to_ne_bytes());
    }
    bpftool_map_update(map, &key, &value)
}

fn update_iface_config(
    map: &Path,
    ifindex: u32,
    identity: u32,
    default_allow: bool,
    enforce_cidr: bool,
    enforce_l4: bool,
    sample_rate: u32,
    allow_icmp: bool,
    rate_bytes_per_sec: u64,
    rate_packets_per_sec: u64,
    pod_id: u32,
) -> Result<()> {
    let mut key = Vec::with_capacity(4);
    key.extend_from_slice(&ifindex.to_ne_bytes());

    // Must match struct iface_config in bpf/fluxvm_tc.bpf.c exactly:
    // 6 x u32, 2 x u64, then pod_id + explicit reserved padding (Set 6S) --
    // 48 bytes total, confirmed against the compiled object's BTF.
    let mut value = Vec::with_capacity(48);
    value.extend_from_slice(&identity.to_ne_bytes());
    value.extend_from_slice(&(default_allow as u32).to_ne_bytes());
    value.extend_from_slice(&(enforce_cidr as u32).to_ne_bytes());
    value.extend_from_slice(&(enforce_l4 as u32).to_ne_bytes());
    value.extend_from_slice(&sample_rate.to_ne_bytes());
    value.extend_from_slice(&(allow_icmp as u32).to_ne_bytes());
    value.extend_from_slice(&rate_bytes_per_sec.to_ne_bytes());
    value.extend_from_slice(&rate_packets_per_sec.to_ne_bytes());
    value.extend_from_slice(&pod_id.to_ne_bytes());
    value.extend_from_slice(&0u32.to_ne_bytes());
    bpftool_map_update(map, &key, &value)
}

fn mbps_to_bytes_per_second(mbps: u32) -> Result<u64> {
    if mbps == 0 {
        bail!("max_egress_mbps must be greater than zero when set");
    }
    u64::from(mbps)
        .checked_mul(1_000_000)
        .map(|bits| bits / 8)
        .context("max_egress_mbps is too large")
}

fn clear_map(map: &Path) -> Result<()> {
    let root = bpftool_json_dump(map)?;
    let entries = root.as_array().context("bpftool map dump must be an array")?;
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        let mut args = vec![
            "map".into(),
            "delete".into(),
            "pinned".into(),
            map.display().to_string(),
            "key".into(),
            "hex".into(),
        ];
        args.extend(hex_args(&key));
        run("bpftool", &args)?;
    }
    Ok(())
}

fn update_ipv4_allow(map: &Path, identity: u32, cidr: Ipv4Cidr) -> Result<()> {
    let lpm_prefix = 32u32 + u32::from(cidr.prefix);
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&lpm_prefix.to_ne_bytes());
    key.extend_from_slice(&identity.to_ne_bytes());
    // iph->daddr is network order in packet memory, so octets are the
    // correct map-key bytes regardless of host endianness.
    key.extend_from_slice(&cidr.network.octets());
    bpftool_map_update(map, &key, &1u32.to_ne_bytes())
}

fn update_ipv6_allow(map: &Path, identity: u32, cidr: Ipv6Cidr) -> Result<()> {
    let lpm_prefix = 32u32 + u32::from(cidr.prefix);
    let mut key = Vec::with_capacity(24);
    key.extend_from_slice(&lpm_prefix.to_ne_bytes());
    key.extend_from_slice(&identity.to_ne_bytes());
    key.extend_from_slice(&cidr.network.octets());
    bpftool_map_update(map, &key, &1u32.to_ne_bytes())
}

fn update_l4_allow(map: &Path, identity: u32, rule: PortRule) -> Result<()> {
    let mut key = Vec::with_capacity(8);
    key.extend_from_slice(&identity.to_ne_bytes());
    key.extend_from_slice(&rule.port.to_ne_bytes());
    key.push(rule.protocol);
    key.push(0);
    bpftool_map_update(map, &key, &1u32.to_ne_bytes())
}

pub(crate) fn bpftool_map_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".into(),
        "update".into(),
        "pinned".into(),
        map.display().to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(hex_args(key));
    args.push("value".into());
    args.push("hex".into());
    args.extend(hex_args(value));
    run("bpftool", &args)
}

fn bpftool_json_dump(map: &Path) -> Result<Value> {
    if !map.exists() {
        bail!("FluxVM eBPF map is not pinned at {}", map.display());
    }
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()
        .context("running bpftool map dump")?;
    if !out.status.success() {
        bail!(
            "bpftool map dump pinned {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("parsing bpftool JSON")
}

fn parse_stats_json(root: &Value) -> Result<DataplaneStats> {
    let entries = root.as_array().context("bpftool stats JSON must be an array")?;
    let mut out = DataplaneStats::default();
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        if key.len() < 8 {
            continue;
        }
        let verdict = u32::from_ne_bytes(key[4..8].try_into().unwrap());

        let mut packets = 0u64;
        let mut bytes = 0u64;
        if let Some(values) = entry.get("values").and_then(Value::as_array) {
            for cpu in values {
                let raw = json_bytes(&cpu["value"])?;
                if raw.len() >= 16 {
                    packets = packets.saturating_add(u64::from_ne_bytes(raw[0..8].try_into().unwrap()));
                    bytes = bytes.saturating_add(u64::from_ne_bytes(raw[8..16].try_into().unwrap()));
                }
            }
        } else if let Some(value) = entry.get("value") {
            let raw = json_bytes(value)?;
            if raw.len() >= 16 {
                packets = u64::from_ne_bytes(raw[0..8].try_into().unwrap());
                bytes = u64::from_ne_bytes(raw[8..16].try_into().unwrap());
            }
        }

        if verdict == 1 {
            out.allowed_packets = out.allowed_packets.saturating_add(packets);
            out.allowed_bytes = out.allowed_bytes.saturating_add(bytes);
        } else {
            out.dropped_packets = out.dropped_packets.saturating_add(packets);
            out.dropped_bytes = out.dropped_bytes.saturating_add(bytes);
        }
    }
    Ok(out)
}

fn parse_flows_json(root: &Value) -> Result<Vec<FlowRecord>> {
    let entries = root.as_array().context("bpftool flow JSON must be an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        let value = json_bytes(&entry["value"])?;
        if key.len() < 44 || value.len() < 24 {
            continue;
        }
        let identity = u32::from_ne_bytes(key[0..4].try_into().unwrap());
        let family = key[42];
        let source = decode_flow_ip(family, &key[4..20])?;
        let destination = decode_flow_ip(family, &key[20..36])?;
        let source_port = u16::from_ne_bytes(key[36..38].try_into().unwrap());
        let destination_port = u16::from_ne_bytes(key[38..40].try_into().unwrap());
        let protocol = key[40];
        let verdict = if key[41] == 1 { "allow" } else { "drop" }.to_string();
        let packets = u64::from_ne_bytes(value[0..8].try_into().unwrap());
        let bytes = u64::from_ne_bytes(value[8..16].try_into().unwrap());
        let last_seen_ns = u64::from_ne_bytes(value[16..24].try_into().unwrap());
        out.push(FlowRecord {
            identity, family, source, destination, source_port, destination_port,
            protocol, verdict, packets, bytes, last_seen_ns,
        });
    }
    Ok(out)
}

fn parse_drop_reasons_json(root: &Value) -> Result<Vec<DropReasonRecord>> {
    let entries = root
        .as_array()
        .context("bpftool drop-reason JSON must be an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        let value = json_bytes(&entry["value"])?;
        // struct drop_reason_key = 44-byte flow_key + u32 reason + u32 action.
        if key.len() < 52 || value.len() < 24 {
            continue;
        }
        let identity = u32::from_ne_bytes(key[0..4].try_into().unwrap());
        let family = key[42];
        let source = decode_flow_ip_allow_zero(family, &key[4..20])?;
        let destination = decode_flow_ip_allow_zero(family, &key[20..36])?;
        let source_port = u16::from_ne_bytes(key[36..38].try_into().unwrap());
        let destination_port = u16::from_ne_bytes(key[38..40].try_into().unwrap());
        let protocol = key[40];
        let reason_code = u32::from_ne_bytes(key[44..48].try_into().unwrap());
        let action_code = u32::from_ne_bytes(key[48..52].try_into().unwrap());
        let packets = u64::from_ne_bytes(value[0..8].try_into().unwrap());
        let bytes = u64::from_ne_bytes(value[8..16].try_into().unwrap());
        let last_seen_ns = u64::from_ne_bytes(value[16..24].try_into().unwrap());
        out.push(DropReasonRecord {
            identity,
            family,
            source,
            destination,
            source_port,
            destination_port,
            protocol,
            reason_code,
            reason: drop_reason_label(reason_code).to_string(),
            action: if action_code == 1 { "audit" } else { "drop" }.to_string(),
            packets,
            bytes,
            last_seen_ns,
        });
    }
    Ok(out)
}

fn drop_reason_label(reason: u32) -> &'static str {
    match reason {
        1 => "malformed-l4",
        2 => "fragmented-l4",
        3 => "explicit-cidr-deny",
        4 => "cidr-miss",
        5 => "l4-miss",
        6 => "pod-policy-deny",
        7 => "rate-limit",
        8 => "default-deny",
        9 => "migration-quiesce",
        10 => "migration-restoring",
        11 => "unsupported-ethertype",
        _ => "unknown",
    }
}

fn decode_flow_ip_allow_zero(family: u8, raw: &[u8]) -> Result<String> {
    if family == 0 {
        return Ok("0.0.0.0".into());
    }
    decode_flow_ip(family, raw)
}

fn decode_flow_ip(family: u8, raw: &[u8]) -> Result<String> {
    if raw.len() < 16 {
        bail!("flow address must contain 16 bytes");
    }
    match family {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])).to_string()),
        6 => Ok(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&raw[..16]).unwrap())).to_string()),
        other => bail!("unsupported flow address family {other}"),
    }
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    if let Some(a) = v.as_array() {
        return a
            .iter()
            .map(|x| {
                if let Some(n) = x.as_u64().filter(|n| *n <= 255) {
                    return Ok(n as u8);
                }
                if let Some(n) = x.as_i64().filter(|n| (0..=255).contains(n)) {
                    return Ok(n as u8);
                }
                if let Some(s) = x.as_str() {
                    let s = s.trim().trim_start_matches("0x");
                    return u8::from_str_radix(s, 16)
                        .with_context(|| format!("invalid bpftool hex byte {s:?}"));
                }
                bail!("bpftool JSON byte must be 0..255 or hex string, got {x}")
            })
            .collect();
    }
    if let Some(s) = v.as_str() {
        let normalized = s.replace(':', " ").replace(',', " ");
        return normalized
            .split_whitespace()
            .map(|x| u8::from_str_radix(x.trim_start_matches("0x"), 16).context("invalid hex byte"))
            .collect();
    }
    bail!("unsupported bpftool JSON byte representation: {v}")
}

pub(crate) fn hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_ip_cidr(raw: &str) -> Result<IpCidr> {
    let (ip, prefix) = raw
        .split_once('/')
        .with_context(|| format!("CIDR {raw:?} must include /prefix"))?;
    let ip: IpAddr = ip.parse().with_context(|| format!("invalid IP {ip:?}"))?;
    let prefix: u8 = prefix.parse().with_context(|| format!("invalid prefix in {raw:?}"))?;
    match ip {
        IpAddr::V4(ip) => Ok(IpCidr::V4(normalize_ipv4(ip, prefix)?)),
        IpAddr::V6(ip) => Ok(IpCidr::V6(normalize_ipv6(ip, prefix)?)),
    }
}

fn parse_ipv4_cidr(raw: &str) -> Result<Ipv4Cidr> {
    match parse_ip_cidr(raw)? {
        IpCidr::V4(cidr) => Ok(cidr),
        IpCidr::V6(_) => bail!("expected IPv4 CIDR, got {raw:?}"),
    }
}

fn normalize_ipv4(ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Cidr> {
    if prefix > 32 {
        bail!("IPv4 prefix must be <= 32, got {prefix}");
    }
    let raw_ip = u32::from(ip);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ok(Ipv4Cidr { network: Ipv4Addr::from(raw_ip & mask), prefix })
}

fn normalize_ipv6(ip: Ipv6Addr, prefix: u8) -> Result<Ipv6Cidr> {
    if prefix > 128 {
        bail!("IPv6 prefix must be <= 128, got {prefix}");
    }
    let raw = u128::from_be_bytes(ip.octets());
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    Ok(Ipv6Cidr { network: Ipv6Addr::from((raw & mask).to_be_bytes()), prefix })
}

fn parse_port_rule(raw: &str) -> Result<PortRule> {
    let (proto, port) = raw
        .split_once('/')
        .with_context(|| format!("port rule {raw:?} must be proto/PORT"))?;
    let protocol = match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        "icmp" => IPPROTO_ICMP,
        "icmp6" | "icmpv6" => IPPROTO_ICMPV6,
        other => bail!("unsupported L4 protocol {other:?}; use tcp, udp, icmp, or icmp6"),
    };
    let port: u16 = port
        .trim()
        .parse()
        .with_context(|| format!("invalid port in {raw:?}"))?;
    if port == 0 && protocol != IPPROTO_ICMP && protocol != IPPROTO_ICMPV6 {
        bail!("port must be 1..65535");
    }
    Ok(PortRule { protocol, port })
}

pub fn policy_contains_ipv6(policy: &VmNetworkPolicy) -> bool {
    policy
        .allow_cidrs
        .iter()
        .chain(policy.deny_cidrs.iter())
        .any(|cidr| matches!(parse_ip_cidr(cidr), Ok(IpCidr::V6(_))))
}

pub(crate) fn require_bpftool() -> Result<()> {
    require_version("bpftool", &["version"])
}

fn require_tc() -> Result<()> {
    require_version("tc", &["-V"])
}

fn require_version(name: &str, args: &[&str]) -> Result<()> {
    // Capture output: bpftool/tc print version banners on stdout, which would
    // otherwise pollute `fluxvm create` JSON on the CLI.
    let out = Command::new(name)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("{name} is required for the eBPF dataplane"))?;
    if out.success() {
        Ok(())
    } else {
        bail!("{} {} exited with {out}", name, args.join(" "))
    }
}

pub(crate) fn raise_memlock() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `limit` is a valid rlimit structure for the duration of the
    // call. CAP_SYS_RESOURCE is only necessary when the current hard limit
    // would otherwise prevent the raise; new kernels charge BPF memory to
    // memcg, but this keeps older kernels working too.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("raising RLIMIT_MEMLOCK for BPF");
    }
    Ok(())
}

fn ensure_clsact(iface: &str) -> Result<()> {
    let out = Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output()
        .context("querying tc qdisc")?;
    if !out.status.success() {
        bail!(
            "tc qdisc show dev {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .any(|token| token == "clsact")
    {
        return Ok(());
    }
    run(
        "tc",
        &[
            "qdisc".into(),
            "add".into(),
            "dev".into(),
            iface.into(),
            "clsact".into(),
        ],
    )
}

/// Set 14: lazily attaches (or detaches) the separate
/// `fluxvm_pod_ingress.bpf.o` object -- loaded only when a Pod's policy
/// actually isolates ingress, and bound at load time to this VM's
/// already-pinned maps (`fluxvm_id`, the Pod-scoped ACL maps, the unified
/// `fluxvm_prules` rule map, and the shared `fluxvm_ct` conntrack table) so
/// the ingress program's stateful return-traffic fast path reuses the exact
/// same flow entries `fluxvm_egress` already maintains.
fn sync_pod_ingress_attachment(
    cfg: &DataplaneConfig,
    id: Uuid,
    iface: &str,
    map_dir: &Path,
    policy: Option<&PodNetworkPolicy>,
) -> Result<()> {
    let needs_ingress = policy
        .map(|p| p.schema_version >= 2 && p.ingress_isolated)
        .unwrap_or(false);
    if !needs_ingress {
        detach_pod_ingress_filter(cfg, id);
        return Ok(());
    }
    require_tc()?;
    ensure_clsact(iface)?;
    let object = cfg.bpf_object.with_file_name("fluxvm_pod_ingress.bpf.o");
    if !object.exists() {
        bail!("Set 14 ingress object does not exist at {}", object.display());
    }
    let pin = vm_pin_dir(&cfg.pin_root, id).join("progs/fluxvm_pod_ingress");
    detach_pod_ingress_filter(cfg, id);
    let maps = [
        "fluxvm_id",
        "fluxvm_pspol",
        "fluxvm_pid4",
        "fluxvm_pid6",
        "fluxvm_pid4_port",
        "fluxvm_pid6_port",
        "fluxvm_prules",
        "fluxvm_ppstat",
        "fluxvm_ct",
    ];
    let mut args = vec![
        "prog".into(),
        "load".into(),
        object.display().to_string(),
        pin.display().to_string(),
        "type".into(),
        "classifier".into(),
    ];
    for name in maps {
        let path = map_dir.join(name);
        if !path.exists() {
            bail!("required Set 14 ingress shared map missing: {}", path.display());
        }
        args.extend([
            "map".into(),
            "name".into(),
            name.into(),
            "pinned".into(),
            path.display().to_string(),
        ]);
    }
    run("bpftool", &args).context("loading Set 14 Pod ingress program with shared maps")?;
    run(
        "tc",
        &[
            "filter".into(), "add".into(), "dev".into(), iface.into(), "egress".into(),
            "pref".into(), "49153".into(), "handle".into(), "2".into(), "bpf".into(),
            "da".into(), "pinned".into(), pin.display().to_string(),
        ],
    )
    .context("attaching Set 14 Pod ingress TC program")?;
    Ok(())
}

fn detach_pod_ingress_filter(cfg: &DataplaneConfig, id: Uuid) {
    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    detach_pod_ingress_filter_in_vm_dir(id, &vm_dir);
}

/// Best-effort like `detach_tc_filter`: an absent egress-direction filter
/// (this Pod never isolated ingress, or the object predates Set 14) is not
/// an error. Distinct pref/handle (49153/2) from the main program's
/// (49152/1) so the two coexist on the same interface without collision.
fn detach_pod_ingress_filter_in_vm_dir(id: Uuid, vm_dir: &Path) {
    let pin = vm_dir.join("progs/fluxvm_pod_ingress");
    if let Some(iface) = read_recorded_iface(id) {
        let owned = pinned_program_id(&pin).ok();
        let out = Command::new("tc")
            .args(["filter", "show", "dev", &iface, "egress", "pref", "49153"])
            .output();
        if let (Some(owned), Ok(out)) = (owned, out) {
            if out.status.success()
                && parse_tc_program_id_handle(&String::from_utf8_lossy(&out.stdout), 2) == Some(owned)
            {
                let _ = run(
                    "tc",
                    &[
                        "filter".into(), "del".into(), "dev".into(), iface,
                        "egress".into(), "pref".into(), "49153".into(),
                        "handle".into(), "2".into(), "bpf".into(),
                    ],
                );
            }
        }
    }
    // The pin lives under FluxVM's per-VM directory and is ours even if the
    // filter already disappeared. Unlink it so the next `bpftool prog load`
    // can create the same pin path again.
    let _ = fs::remove_file(&pin);
}

fn parse_tc_program_id_handle(text: &str, expected_handle: u64) -> Option<u32> {
    for line in text.lines() {
        if !line.contains("bpf") {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut handle_matches = false;
        let mut program_id = None;
        for pair in tokens.windows(2) {
            if pair[0] == "handle" {
                let (raw, radix) = pair[1]
                    .strip_prefix("0x")
                    .map(|x| (x, 16))
                    .unwrap_or((pair[1], 10));
                handle_matches = u64::from_str_radix(raw, radix).ok() == Some(expected_handle);
            } else if pair[0] == "id" {
                program_id = pair[1].parse::<u32>().ok();
            }
        }
        if handle_matches && program_id.is_some() {
            return program_id;
        }
    }
    None
}

pub(crate) fn pinned_program_id(path: &Path) -> Result<u32> {
    if !path.exists() {
        bail!("pinned BPF program does not exist at {}", path.display());
    }
    let out = Command::new("bpftool")
        .args(["-j", "prog", "show", "pinned"])
        .arg(path)
        .output()
        .context("querying pinned TC program")?;
    if !out.status.success() {
        bail!(
            "bpftool prog show pinned {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let value: Value = serde_json::from_slice(&out.stdout).context("parsing pinned program JSON")?;
    let object = value.as_array().and_then(|a| a.first()).unwrap_or(&value);
    let id = object.get("id").and_then(Value::as_u64).context("pinned program JSON missing id")?;
    u32::try_from(id).context("BPF program id does not fit u32")
}

/// Return the BPF program id occupying FluxVM's reserved TC preference and
/// handle. We deliberately require the handle match so another BPF filter at
/// the same preference is never mistaken for ours.
fn tc_filter_program_id(iface: &str) -> Result<Option<u32>> {
    let out = Command::new("tc")
        .args(["filter", "show", "dev", iface, "ingress", "pref", TC_PRIORITY])
        .output()
        .context("querying FluxVM TC filter")?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(parse_tc_program_id(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_tc_program_id(text: &str) -> Option<u32> {
    for line in text.lines() {
        if !line.contains("bpf") {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut handle_matches = false;
        let mut program_id = None;
        for pair in tokens.windows(2) {
            if pair[0] == "handle" {
                let (raw, radix) = if let Some(hex) = pair[1].strip_prefix("0x") {
                    (hex, 16)
                } else {
                    (pair[1], 10)
                };
                handle_matches = u64::from_str_radix(raw, radix).ok() == Some(1);
            } else if pair[0] == "id" {
                program_id = pair[1].parse::<u32>().ok();
            }
        }
        if handle_matches {
            if let Some(id) = program_id {
                return Some(id);
            }
        }
    }
    None
}

pub(crate) fn run(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cidr_is_network_normalized() {
        let c = parse_ipv4_cidr("10.20.30.99/24").unwrap();
        assert_eq!(c.network, Ipv4Addr::new(10, 20, 30, 0));
        assert_eq!(c.prefix, 24);
    }

    #[test]
    fn cidr_zero_prefix_is_supported() {
        let c = parse_ipv4_cidr("203.0.113.7/0").unwrap();
        assert_eq!(c.network, Ipv4Addr::UNSPECIFIED);
        assert_eq!(c.prefix, 0);
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        assert!(parse_ipv4_cidr("10.0.0.1/33").is_err());
    }

    #[test]
    fn l4_rules_parse() {
        assert_eq!(
            parse_port_rule("tcp/443").unwrap(),
            PortRule { protocol: 6, port: 443 }
        );
        assert_eq!(
            parse_port_rule("UDP/53").unwrap(),
            PortRule { protocol: 17, port: 53 }
        );
        assert_eq!(
            parse_port_rule("icmp/0").unwrap(),
            PortRule { protocol: IPPROTO_ICMP, port: 0 }
        );
        assert_eq!(
            parse_port_rule("icmp/8").unwrap(),
            PortRule { protocol: IPPROTO_ICMP, port: 8 }
        );
        assert!(parse_port_rule("tcp/0").is_err());
        assert!(parse_port_rule("sctp/443").is_err());
    }

    #[test]
    fn drop_reason_parser_decodes_schema_v6_key() {
        let identity = 42u32;
        let mut key = identity.to_ne_bytes().to_vec();
        key.extend([10, 0, 0, 2]); key.extend([0; 12]);
        key.extend([1, 1, 1, 1]); key.extend([0; 12]);
        key.extend(12345u16.to_ne_bytes());
        key.extend(443u16.to_ne_bytes());
        key.extend([6, 0, 4, 0]);
        key.extend(7u32.to_ne_bytes());
        key.extend(0u32.to_ne_bytes());
        let value = [3u64.to_ne_bytes(), 192u64.to_ne_bytes(), 99u64.to_ne_bytes()].concat();
        let parsed = parse_drop_reasons_json(&json!([{"key": key, "value": value}])).unwrap();
        assert_eq!(parsed[0].reason, "rate-limit");
        assert_eq!(parsed[0].action, "drop");
        assert_eq!(parsed[0].destination, "1.1.1.1");
    }

    #[test]
    fn bytes_are_bpftool_hex_tokens() {
        assert_eq!(hex_args(&[0, 1, 0xfe]), ["00", "01", "fe"]);
    }

    #[test]
    fn json_bytes_accepts_numeric_and_hex_string_arrays() {
        let numeric = serde_json::json!([205, 13, 100]);
        assert_eq!(json_bytes(&numeric).unwrap(), vec![205, 13, 100]);

        let hex = serde_json::json!(["0xcd", "0x0d", "0x64"]);
        assert_eq!(json_bytes(&hex).unwrap(), vec![0xcd, 0x0d, 0x64]);
    }

    #[test]
    fn mbps_rate_is_converted_to_bytes_per_second() {
        assert_eq!(mbps_to_bytes_per_second(1).unwrap(), 125_000);
        assert_eq!(mbps_to_bytes_per_second(100).unwrap(), 12_500_000);
        assert!(mbps_to_bytes_per_second(0).is_err());
    }

    #[test]
    fn zero_pps_is_rejected() {
        let policy = VmNetworkPolicy {
            max_egress_pps: Some(0),
            ..VmNetworkPolicy::default()
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn stats_parser_aggregates_per_cpu_values() {
        fn u32b(v: u32) -> Vec<u8> { v.to_ne_bytes().to_vec() }
        fn statv(packets: u64, bytes: u64) -> Vec<u8> {
            [packets.to_ne_bytes(), bytes.to_ne_bytes()].concat()
        }
        let mut allow_key = u32b(99);
        allow_key.extend(u32b(1));
        let mut drop_key = u32b(99);
        drop_key.extend(u32b(0));
        let doc = json!([
            {"key": allow_key, "values": [
                {"cpu":0,"value":statv(2,200)},
                {"cpu":1,"value":statv(3,300)}
            ]},
            {"key": drop_key, "values": [
                {"cpu":0,"value":statv(1,64)}
            ]}
        ]);
        let s = parse_stats_json(&doc).unwrap();
        assert_eq!(s.allowed_packets, 5);
        assert_eq!(s.allowed_bytes, 500);
        assert_eq!(s.dropped_packets, 1);
        assert_eq!(s.dropped_bytes, 64);
    }

    #[test]
    fn flow_parser_decodes_ipv4_and_ipv6_addresses() {
        let identity = 7u32;
        let mut key4 = identity.to_ne_bytes().to_vec();
        key4.extend([10, 0, 0, 2]);
        key4.extend([0; 12]);
        key4.extend([1, 1, 1, 1]);
        key4.extend([0; 12]);
        key4.extend(43210u16.to_ne_bytes());
        key4.extend(443u16.to_ne_bytes());
        key4.extend([6, 1, 4, 0]);
        let value = [4u64.to_ne_bytes(), 2048u64.to_ne_bytes(), 12345u64.to_ne_bytes()].concat();

        let src6: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let mut key6 = identity.to_ne_bytes().to_vec();
        key6.extend(src6.octets());
        key6.extend(dst6.octets());
        key6.extend(1234u16.to_ne_bytes());
        key6.extend(53u16.to_ne_bytes());
        key6.extend([17, 0, 6, 0]);

        let doc = json!([
            {"key":key4,"value":value.clone()},
            {"key":key6,"value":value}
        ]);
        let flows = parse_flows_json(&doc).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].family, 4);
        assert_eq!(flows[0].source, "10.0.0.2");
        assert_eq!(flows[0].destination, "1.1.1.1");
        assert_eq!(flows[0].destination_port, 443);
        assert_eq!(flows[1].family, 6);
        assert_eq!(flows[1].source, "2001:db8::10");
        assert_eq!(flows[1].destination, "2001:db8::20");
    }

    #[test]
    fn tc_ownership_parser_requires_reserved_handle() {
        let text = "filter protocol all pref 49152 bpf chain 0\n\
filter protocol all pref 49152 bpf chain 0 handle 0x1 direct-action not_in_hw id 191 tag deadbeef\n";
        assert_eq!(parse_tc_program_id(text), Some(191));
        let other = "filter protocol all pref 49152 bpf chain 0 handle 0x2 direct-action not_in_hw id 200";
        assert_eq!(parse_tc_program_id(other), None);
    }

    #[test]
    fn ipv6_cidr_is_network_normalized() {
        let c = match parse_ip_cidr("2001:db8:abcd:1234::99/64").unwrap() {
            IpCidr::V6(c) => c,
            _ => panic!("expected IPv6"),
        };
        assert_eq!(c.network, "2001:db8:abcd:1234::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(c.prefix, 64);
        assert!(parse_ip_cidr("2001:db8::1/129").is_err());
    }
}
