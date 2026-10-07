// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::collapsible_if)]
#![cfg_attr(test, allow(clippy::field_reassign_with_default))]

use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use fluxvm_core::{
    backend::{LaunchContext, VmBackend},
    config::Config,
    metrics,
    model::{
        BackendKind, ClaimOverrides, CloudInitSpec, CreateVmRequest, ExtraNic, MigrationPhase,
        MigrationTlsSpec, NetworkSpec, PoolRecord, PoolSpec, StorageBackend, VmRecord, VmStatus,
    },
    process,
};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse};
use fluxvm_storage::{PoolStore, Store};
use std::{collections::HashMap, fs, sync::Arc};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

pub mod backup;
pub mod changes;
pub mod confidential;
pub mod events;
pub mod fork;
pub mod live_migration;
mod migration_relay;
pub mod procbox_sandbox;
mod sandbox;
pub mod shared_disk;
pub mod templates;
pub mod vm_restore;
pub use events::{EventFilter, VmEvent};
pub use sandbox::{SandboxCreateRequest, TemplateInfo};

/// A bridge-less direct tap is forwarded ONLY by the eBPF redirect. Unlike an ordinary VM, whose
/// tap sits on a bridge and keeps working when the dataplane is missing, a failed attach must
/// never be downgraded to a warning: the VM would boot with no connectivity at all.
fn is_direct(spec: &NetworkSpec) -> bool {
    matches!(
        spec,
        NetworkSpec::Tap {
            direct: Some(_),
            ..
        }
    )
}

/// The orchestration behind [`VmManager::hotplug_direct_nic`], free of the manager and its store so
/// it can be exercised against a mock QEMU. On success the returned network is what the VM record
/// must hold; on any failure everything created here is removed again.
pub(crate) async fn plug_direct_nic(
    cfg: &Config,
    vm: &VmRecord,
    direct: fluxvm_core::model::DirectSpec,
    mac: Option<String>,
) -> Result<fluxvm_core::backend::PreparedNetwork> {
    let id = vm.id;
    if vm.backend != BackendKind::Qemu {
        bail!("NIC hotplug is supported for the QEMU backend only");
    }
    if !matches!(vm.request.network, NetworkSpec::None) {
        bail!(
            "direct NIC hotplug needs a VM booted with network.mode=none (a warm-pool template); \
             this VM already has a network"
        );
    }
    let index = nic_hotplug_index(&vm.request.network); // 0: the primary NIC
    let tap = format!("hn{index}{}", &id.simple().to_string()[..6]);
    let spec = NetworkSpec::Tap {
        tap_name: Some(tap.clone()),
        bridge: None,
        mac: mac.clone(),
        netns: false,
        extra: vec![],
        direct: Some(direct),
    };
    // prepare() validates the spec, refuses legacy dataplane mode, creates the tap and records the
    // wiring the loader needs.
    let prepared = fluxvm_network::prepare(cfg, id, &spec)
        .await
        .context("creating the direct hotplug TAP")?;
    let close_fd = |p: &fluxvm_core::backend::PreparedNetwork| {
        if let Some(fd) = p.tap_fd {
            fluxvm_core::process::close_fd(fd);
        }
    };
    // The dataplane goes on BEFORE QEMU sees the NIC: a direct tap has no bridge, so without the
    // redirect it carries nothing.
    if let Err(e) = fluxvm_network::dataplane::apply_sandbox_policy(
        cfg,
        id,
        prepared.tap_name.as_deref(),
        None,
        &[],
        vm.request.pod_uid.as_deref(),
    ) {
        close_fd(&prepared);
        let _ = fluxvm_network::cleanup(&cfg.state_dir, id, &prepared.spec, &tap, None).await;
        return Err(e).context("applying the VM dataplane for the hotplugged direct NIC");
    }
    let plugged = match prepared.tap_fd {
        Some(fd) => fluxvm_qemu::hotplug_nic_fd(vm, fd, mac.as_deref(), index).await,
        None => fluxvm_qemu::hotplug_nic(vm, &tap, mac.as_deref(), index).await,
    };
    // QEMU holds its own copy of the descriptor now (or the attempt failed); ours is done.
    close_fd(&prepared);
    if let Err(e) = plugged {
        let _ = fluxvm_network::cleanup(&cfg.state_dir, id, &prepared.spec, &tap, None).await;
        return Err(e);
    }
    Ok(prepared)
}

fn nic_hotplug_index(spec: &NetworkSpec) -> u8 {
    match spec {
        NetworkSpec::Tap {
            tap_name, extra, ..
        } => {
            if tap_name.is_some()
                && let Some(free) = extra.iter().position(is_free_nic_slot)
            {
                return (free + 1) as u8;
            }
            let primary = u8::from(tap_name.is_some());
            let extras = extra.iter().filter(|n| n.tap_name.is_some()).count() as u8;
            primary.saturating_add(extras)
        }
        _ => 0,
    }
}

/// [`nic_hotplug_index`] for `vm`, counting a primary tap the daemon created
/// at boot: its name lives on the record (`vm.tap_name`), not the request.
fn vm_nic_hotplug_index(vm: &VmRecord) -> u8 {
    match (&vm.request.network, &vm.tap_name) {
        (
            NetworkSpec::Tap {
                tap_name: None,
                extra,
                ..
            },
            Some(primary),
        ) => {
            let spec = NetworkSpec::Tap {
                tap_name: Some(primary.clone()),
                bridge: None,
                mac: None,
                netns: false,
                extra: extra.clone(),
                direct: None,
            };
            nic_hotplug_index(&spec)
        }
        (spec, _) => nic_hotplug_index(spec),
    }
}

/// An extra NIC slot left behind by an unplug: extra `i` is pinned to
/// `hotplug-pcie-{i+1}`, so removing one in the middle keeps its place.
fn is_free_nic_slot(n: &ExtraNic) -> bool {
    n.tap_name.is_none() && n.direct.is_none() && n.bridge.is_empty()
}

fn record_hotplugged_nic(vm: &mut VmRecord, tap: String, bridge: String, mac: Option<String>) {
    let spec = std::mem::replace(&mut vm.request.network, NetworkSpec::None);
    let boot_primary = vm.tap_name.is_some();
    vm.request.network = match spec {
        NetworkSpec::Tap {
            tap_name: None,
            netns,
            extra,
            ..
        } if extra.is_empty() && !boot_primary => NetworkSpec::Tap {
            tap_name: Some(tap),
            bridge: Some(bridge),
            mac,
            netns,
            extra,
            direct: None,
        },
        NetworkSpec::Tap {
            tap_name,
            bridge: existing_bridge,
            mac: existing_mac,
            netns,
            mut extra,
            direct,
        } => {
            let nic = ExtraNic {
                bridge,
                mac,
                tap_name: Some(tap),
                direct: None,
            };
            match extra.iter_mut().find(|n| is_free_nic_slot(n)) {
                Some(slot) => *slot = nic,
                None => extra.push(nic),
            }
            NetworkSpec::Tap {
                tap_name,
                bridge: existing_bridge,
                mac: existing_mac,
                netns,
                extra,
                direct,
            }
        }
        _ => NetworkSpec::Tap {
            tap_name: Some(tap),
            bridge: Some(bridge),
            mac,
            netns: false,
            extra: vec![],
            direct: None,
        },
    };
    // stop/delete tear the network down only for a VM whose record names its primary tap
    // (`vm.tap_name`); a warm-pool member is created with no NIC, so without this the first hotplugged tap
    // was never removed and leaked on every claimed VM.
    if vm.tap_name.is_none() {
        if let NetworkSpec::Tap {
            tap_name: Some(primary),
            ..
        } = &vm.request.network
        {
            vm.tap_name = Some(primary.clone());
        }
    }
}

/// Empties extra NIC `pos`, then drops trailing empty slots. With none left,
/// a fresh launch would put the primary NIC on a different PCIe bus than the
/// running VM has, so it is marked hot-plugged (no live migration until it
/// restarts).
fn free_nic_slot(vm: &mut VmRecord, pos: usize) {
    if let NetworkSpec::Tap { extra, .. } = &mut vm.request.network {
        if let Some(n) = extra.get_mut(pos) {
            *n = ExtraNic::default();
        }
        while extra.last().is_some_and(is_free_nic_slot) {
            extra.pop();
        }
        if extra.is_empty() {
            vm.labels
                .insert(live_migration::HOTPLUGGED_LABEL.into(), "true".into());
        }
    }
}

/// Linux reserves vsock CIDs 0–2 (hypervisor/local/host); guest CIDs start
/// at 3 and must be unique across the whole host.
const FIRST_GUEST_CID: u32 = 3;

const GRACEFUL_SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a VM may sit in `Creating` status before `reconcile()` assumes
/// its creating process crashed and reclaims it. Generous on purpose —
/// nothing in a normal `create()` should take anywhere near this long, even
/// under load (the slowest real path observed, a non-reflinkable Firecracker
/// raw-disk clone, took under a minute) — the cost of guessing wrong is a
/// legitimately-slow create getting cut off, so this errs long.
const STUCK_CREATING_GRACE: Duration = Duration::seconds(300);

pub fn backend(kind: BackendKind) -> Result<Box<dyn VmBackend>> {
    Ok(match kind {
        BackendKind::Qemu => Box::new(fluxvm_qemu::QemuBackend),
        BackendKind::CloudHypervisor => Box::new(fluxvm_cloud_hypervisor::CloudHypervisorBackend),
        BackendKind::Firecracker => Box::new(fluxvm_firecracker::FirecrackerBackend),
        BackendKind::FluxVm => Box::new(fluxvm_hypervisor::FluxVmBackend),
        BackendKind::Auto => bail!(
            "VM has an unresolved BackendKind::Auto — this is a bug, backend selection must happen before dispatch"
        ),
    })
}

/// Picks a concrete backend for `BackendKind::Auto`, preferring the in-tree
/// KVM engine for a raw Linux image when explicitly configured, then Firecracker
/// (fastest microVM start) when a direct-boot kernel is available, then
/// Cloud Hypervisor when a kernel or firmware is available, falling back to
/// QEMU (works with just a disk image, no kernel/firmware required — the
/// only one of the three that boots via its own BIOS/UEFI). Any non-`Auto`
/// request passes through unchanged. Called once, as the very first step of
/// `create()`, before the resolved kind is ever persisted or dispatched on.
pub fn resolve_backend(req: &CreateVmRequest, cfg: &Config) -> BackendKind {
    if req.backend != BackendKind::Auto {
        return req.backend;
    }
    let native_kernel =
        req.kernel.is_some() || cfg.fluxvm_kernel.is_some() || cfg.firecracker_kernel.is_some();
    let raw_image = matches!(
        req.image.extension().and_then(|e| e.to_str()),
        Some("raw" | "ext4")
    );
    if cfg.fluxvm_engine == fluxvm_core::config::FluxVmEngine::Kvm
        && native_kernel
        && raw_image
        && req.firmware.is_none()
        && !req.hyperv
    {
        return BackendKind::FluxVm;
    }
    let firecracker_ok = req.kernel.is_some() || cfg.firecracker_kernel.is_some();
    let cloud_hypervisor_ok =
        req.kernel.is_some() || req.firmware.is_some() || cfg.cloud_hypervisor_firmware.is_some();
    if firecracker_ok {
        BackendKind::Firecracker
    } else if cloud_hypervisor_ok {
        BackendKind::CloudHypervisor
    } else {
        BackendKind::Qemu
    }
}

/// `Some(message)` when `req` asks for `secure_boot`/`tpm` against a
/// backend that doesn't implement it. Extracted as its own pure function
/// so it's directly unit-testable without spinning up a full
/// `VmManager`/`Store`, the same "small pure helper, real coverage" shape
/// `resolve_backend` above already has. Unlike
/// `vfio_devices`/`numa_node`/`hugepages`, which other backends silently
/// ignore, this is a hard rejection: a caller believing they got Secure
/// Boot/measured boot when they silently didn't is a real,
/// security-relevant footgun, not a cosmetic no-op.
///
/// The two fields have different real scope, deliberately not treated the
/// same:
///  - `secure_boot` is QEMU-only. Cloud Hypervisor's own `--firmware` is a
///    single opaque file with no documented persistent UEFI variable
///    store separate from it (confirmed against Cloud Hypervisor's own
///    `docs/uefi.md` and Windows-guest docs, which describe plain UEFI
///    boot only) -- there is nothing to enroll Secure Boot keys into, so
///    claiming support would be dishonest, not just unimplemented.
///  - `tpm` is QEMU **and** Cloud Hypervisor: CH has a real, documented
///    `--tpm socket=<path>` flag (confirmed against a real `cloud-hypervisor
///    --help`, v53.0) that dials the exact same `swtpm`-backed Unix socket
///    QEMU's `-tpmdev emulator` does -- `fluxvm_core::process::spawn_swtpm`
///    is shared between both backends for this reason.
///  - Firecracker has no firmware concept (always direct kernel boot) and
///    no TPM device -- both fields are rejected there.
fn secure_boot_or_tpm_backend_error(req: &CreateVmRequest) -> Option<String> {
    if req.secure_boot.unwrap_or(false) && req.backend != BackendKind::Qemu {
        return Some(format!(
            "secure_boot requires backend qemu (OVMF split pflash + smm=on) -- Cloud Hypervisor has no documented persistent UEFI variable store to enroll keys into, and Firecracker has no firmware concept at all; got {:?}",
            req.backend
        ));
    }
    if req.tpm.unwrap_or(false)
        && !matches!(
            req.backend,
            BackendKind::Qemu | BackendKind::CloudHypervisor
        )
    {
        return Some(format!(
            "tpm requires backend qemu or cloud-hypervisor (both dial a swtpm-backed emulated TPM device); got {:?}",
            req.backend
        ));
    }
    None
}

/// VM-state snapshot save/restore: QEMU (`savevm`/`-loadvm`), Cloud Hypervisor
/// (snapshot dir + `--restore`), Firecracker (`/snapshot/create`+`/load`), and
/// FluxVm (hypervisor control SnapshotSave/Restore — FC or FLUXKVM1 by engine).
fn snapshot_backend_error(backend: BackendKind) -> Option<String> {
    match backend {
        BackendKind::Qemu
        | BackendKind::CloudHypervisor
        | BackendKind::Firecracker
        | BackendKind::FluxVm => None,
        other => Some(format!("snapshot not supported for backend {other:?}")),
    }
}

/// Admission check for `cfg.policy`, run once resolved (see `resolve_backend`)
/// but before any disk/network work — a rejected request should be cheap.
fn audit_event(event: &str, pairs: &[(&str, &str)]) {
    let record = fluxvm_core::policy::format_audit_record(event, pairs);
    tracing::info!(target: "fluxvm_audit", record = %record, "audit");
    events::record(event, pairs);
}

/// Snapshot tags become directory names / qcow2 snapshot names.
fn validate_snapshot_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || tag.len() > 128
        || tag.starts_with('.')
        || !tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!(
            "invalid snapshot tag {tag:?}: use 1-128 chars of [A-Za-z0-9._-], not starting with '.'"
        );
    }
    Ok(())
}

fn validate_vm_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid VM name {name:?}: use 1-63 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

fn validate_label_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 63
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
    {
        bail!("invalid label key {key:?}: use 1-63 chars of [A-Za-z0-9._/-]");
    }
    Ok(())
}

/// VM label enabling scheduled snapshots: an interval like `3600`, `30m`,
/// `6h` or `1d`.
pub const SNAPSHOT_EVERY_LABEL: &str = "fluxvm.io/snapshot-every";
/// VM label: how many `auto-*` snapshots to retain (default 7).
pub const SNAPSHOT_KEEP_LABEL: &str = "fluxvm.io/snapshot-keep";
const DEFAULT_SNAPSHOT_KEEP: usize = 7;
const AUTO_SNAPSHOT_PREFIX: &str = "auto-";
/// Anything shorter would snapshot on nearly every reaper tick.
const MIN_SNAPSHOT_INTERVAL_SECS: u64 = 60;

fn parse_interval_secs(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mult) = match v.char_indices().last()? {
        (i, 's') => (&v[..i], 1),
        (i, 'm') => (&v[..i], 60),
        (i, 'h') => (&v[..i], 3600),
        (i, 'd') => (&v[..i], 86400),
        _ => (v, 1),
    };
    num.parse::<u64>()
        .ok()?
        .checked_mul(mult)
        .filter(|s| *s >= MIN_SNAPSHOT_INTERVAL_SECS)
}

/// `(due, tags_to_prune)` for one VM's `auto-*` snapshots. Pruning keeps the
/// newest `keep`; manual snapshots are never touched.
fn snapshot_schedule_plan(
    snaps: &[fluxvm_core::model::VmSnapshotInfo],
    every_secs: u64,
    keep: usize,
    now: chrono::DateTime<Utc>,
) -> (bool, Vec<String>) {
    let mut auto: Vec<_> = snaps
        .iter()
        .filter(|s| s.tag.starts_with(AUTO_SNAPSHOT_PREFIX))
        .collect();
    auto.sort_by_key(|s| s.created_at);
    let due = auto
        .last()
        .and_then(|s| s.created_at)
        .is_none_or(|t| (now - t).num_seconds() >= every_secs as i64);
    let prune = auto
        .iter()
        .take(auto.len().saturating_sub(keep))
        .map(|s| s.tag.clone())
        .collect();
    (due, prune)
}

fn dir_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

/// Cert/key files must exist; optionally under `policy.allowed_migration_tls_dirs`.
fn validate_migration_tls_spec(tls: &MigrationTlsSpec, cfg: &Config) -> Result<()> {
    for (label, path) in [
        ("ca_path", &tls.ca_path),
        ("cert_path", &tls.cert_path),
        ("key_path", &tls.key_path),
    ] {
        if !path.exists() {
            bail!("migration tls {label} does not exist: {}", path.display());
        }
        if let Some(dirs) = &cfg.policy.allowed_migration_tls_dirs {
            if !fluxvm_core::policy::image_within_allowed(path, dirs) {
                bail!(
                    "migration tls {label} {} is not under any policy allowed_migration_tls_dirs {:?}",
                    path.display(),
                    dirs
                );
            }
        }
    }
    Ok(())
}

fn validate_migration_receiver_request(
    req: &fluxvm_core::model::MigrationReceiverRequest,
    cfg: &Config,
) -> Result<()> {
    let listen = if req.listen_host.is_empty() {
        "0.0.0.0"
    } else {
        req.listen_host.as_str()
    };
    if let Some(allowed) = &cfg.policy.allowed_migration_bind_addresses {
        if !allowed.iter().any(|a| a == listen) {
            bail!(
                "migration listen_host {listen:?} is not in policy allowed_migration_bind_addresses {allowed:?}"
            );
        }
    }
    if let Some(tls) = &req.tls {
        validate_migration_tls_spec(tls, cfg)?;
    }
    Ok(())
}

/// Extra NICs next to a netns primary reach the VMM as inherited tap fds,
/// which only the QEMU backend accepts.
fn validate_netns_extras(req: &CreateVmRequest) -> Result<()> {
    if let NetworkSpec::Tap {
        netns: true, extra, ..
    } = &req.network
        && extra.iter().any(|n| !is_free_nic_slot(n))
        && req.backend != BackendKind::Qemu
    {
        bail!("extra NICs on a netns VM (network.netns=true) need backend qemu");
    }
    Ok(())
}

fn validate_policy(req: &CreateVmRequest, cfg: &Config) -> Result<()> {
    let p = &cfg.policy;
    if let Some(max) = p.max_vcpus {
        if req.vcpus > max {
            bail!(
                "request vcpus ({}) exceeds policy max_vcpus ({max})",
                req.vcpus
            );
        }
    }
    if let Some(max) = p.max_memory_mib {
        if req.memory_mib > max {
            bail!(
                "request memory_mib ({}) exceeds policy max_memory_mib ({max})",
                req.memory_mib
            );
        }
    }
    if let Some(max) = p.max_disk_gib {
        if let Some(disk) = req.disk_size_gib {
            if disk > max {
                bail!("request disk_size_gib ({disk}) exceeds policy max_disk_gib ({max})");
            }
        }
    }
    if let Some(max) = p.max_ttl_seconds {
        match req.ttl_seconds {
            Some(ttl) if ttl > max => {
                bail!("request ttl_seconds ({ttl}) exceeds policy max_ttl_seconds ({max})")
            }
            None => bail!(
                "policy requires ttl_seconds to be set (max_ttl_seconds={max}); unbounded VMs are not allowed"
            ),
            _ => {}
        }
    }
    if let Some(allowed) = &p.allowed_backends {
        if !allowed.contains(&req.backend) {
            bail!(
                "backend {:?} is not permitted by policy allowed_backends {:?}",
                req.backend,
                allowed
            );
        }
    }
    if let Some(dirs) = &p.allowed_image_dirs {
        if !fluxvm_core::policy::image_within_allowed(&req.image, dirs) {
            bail!(
                "image {} is not under any policy allowed_image_dirs {:?}",
                req.image.display(),
                dirs
            );
        }
    }
    if let Some(modes) = &p.allowed_network_modes {
        let mode = match &req.network {
            fluxvm_core::model::NetworkSpec::None => "none",
            fluxvm_core::model::NetworkSpec::User { .. } => "user",
            fluxvm_core::model::NetworkSpec::Tap { .. } => "tap",
            fluxvm_core::model::NetworkSpec::Macvtap { .. } => "macvtap",
        };
        if !modes.iter().any(|m| m == mode) {
            bail!(
                "network mode '{mode}' is not permitted by policy allowed_network_modes {modes:?}"
            );
        }
    }
    if !p.allow_extra_args && !req.extra_args.is_empty() {
        bail!("policy forbids extra_args (set policy.allow_extra_args = true to permit)");
    }
    validate_cpu_template(req, cfg)?;
    Ok(())
}

/// Firecracker static CPU templates only — CH/QEMU/kvm have no FC-style ABI.
fn validate_cpu_template(req: &CreateVmRequest, cfg: &Config) -> Result<()> {
    let Some(ref t) = req.cpu_template else {
        return Ok(());
    };
    if t.trim().is_empty() {
        bail!(
            "cpu_template must be a non-empty Firecracker static template name (e.g. T2, T2A, C3)"
        );
    }
    match req.backend {
        BackendKind::Firecracker => Ok(()),
        BackendKind::FluxVm => match cfg.fluxvm_engine {
            fluxvm_core::config::FluxVmEngine::Firecracker => Ok(()),
            fluxvm_core::config::FluxVmEngine::Kvm => bail!(
                "cpu_template requires fluxvm_engine=firecracker (in-tree kvm has no FC CPU templates)"
            ),
        },
        other => bail!(
            "cpu_template is Firecracker-only (got backend {other:?}; Cloud Hypervisor/QEMU have no FC-style CPU templates)"
        ),
    }
}

/// Do not accept options that the native VMM would silently discard.
fn validate_native_kvm_profile(req: &CreateVmRequest, cfg: &Config) -> Result<()> {
    if req.backend != BackendKind::FluxVm
        || cfg.fluxvm_engine != fluxvm_core::config::FluxVmEngine::Kvm
    {
        return Ok(());
    }
    if req.firmware.is_some() || req.hyperv {
        bail!("in-tree KVM requires Linux direct kernel boot; UEFI and Hyper-V are unsupported");
    }
    if !req.shared_folders.is_empty() {
        bail!("in-tree KVM does not attach shared_folders yet");
    }
    if req.storage != StorageBackend::Default {
        bail!(
            "QEMU-free in-tree KVM provisioning currently requires storage=default (a cloned raw disk)"
        );
    }
    if req.max_vcpus.is_some_and(|max| max > req.vcpus) {
        bail!("in-tree KVM does not support live vCPU hotplug");
    }
    Ok(())
}

/// Aggregate per-tenant admission check -- see `Policy::tenants`'s own doc
/// comment for why this is a separate function from `validate_policy`
/// rather than folded into it: every check in `validate_policy` is a pure
/// function of the one incoming request, but this one needs to sum
/// resource usage across every *existing* VM the same tenant already
/// owns, which means it needs `existing_for_tenant` (already filtered by
/// the caller, see `VmManager::create`) rather than just `(req, cfg)`.
/// A no-op (`Ok(())`) when `req.tenant` is unset or has no matching
/// `[[policy.tenants]]` entry -- unrestricted by this mechanism, same
/// "absent means unrestricted" convention every other `Policy` field has.
///
/// Production create path uses `fluxvm_core::policy::enforce_tenant_totals`;
/// this helper remains for unit coverage of the same rules.
#[cfg(test)]
fn validate_tenant_policy(
    req: &CreateVmRequest,
    cfg: &Config,
    existing_for_tenant: &[VmRecord],
) -> Result<()> {
    let Some(tenant) = req.tenant.as_deref() else {
        return Ok(());
    };
    let Some(tp) = cfg.policy.tenants.iter().find(|t| t.tenant == tenant) else {
        return Ok(());
    };
    if let Some(max) = tp.max_vms_total {
        if existing_for_tenant.len() >= max {
            bail!("tenant '{tenant}' is already at max_vms_total ({max})");
        }
    }
    if let Some(max) = tp.max_vcpus_total {
        let used: u32 = existing_for_tenant
            .iter()
            .map(|v| v.request.vcpus as u32)
            .sum();
        if used.saturating_add(req.vcpus as u32) > max {
            bail!(
                "tenant '{tenant}' would exceed max_vcpus_total ({max}): {used} already used + {} requested",
                req.vcpus
            );
        }
    }
    if let Some(max) = tp.max_memory_mib_total {
        let used: u64 = existing_for_tenant
            .iter()
            .map(|v| v.request.memory_mib)
            .sum();
        if used.saturating_add(req.memory_mib) > max {
            bail!(
                "tenant '{tenant}' would exceed max_memory_mib_total ({max}): {used} already used + {} requested",
                req.memory_mib
            );
        }
    }
    Ok(())
}

pub struct VmManager {
    pub cfg: Config,
    pub store: Arc<Store>,
    pub pools: Arc<PoolStore>,
    /// One mutex per pool name, created on demand, so concurrent backfill
    /// triggers for the *same* pool (e.g. `create_pool` and a `claim` racing
    /// each other) serialize instead of both creating members past `size`;
    /// backfills for *different* pools still run fully in parallel.
    backfill_locks: AsyncMutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    /// Serializes catalog.json read-modify-write cycles — add/remove/
    /// rename/clone all load the whole file, mutate, and write it back, so
    /// two concurrent calls need to not interleave.
    catalog_lock: AsyncMutex<()>,
    /// Serializes templates.json read-modify-write within this process.
    template_lock: AsyncMutex<()>,
    /// Serializes the "is this volume already attached?" check with the VM
    /// record write in `create_sandbox`, so two creates cannot both claim one volume.
    sandbox_volume_lock: AsyncMutex<()>,
    /// Serialises GPU selection with the VM create that records it, so no GPU is handed out twice.
    sandbox_gpu_lock: AsyncMutex<()>,
    /// Last activity timestamps for AutoPause / wake-on-request (sandbox id → UTC).
    activity: AsyncMutex<HashMap<Uuid, chrono::DateTime<chrono::Utc>>>,
    /// A scheduled-snapshot pass can outlast a reaper tick (savevm is slow).
    scheduled_snapshots_busy: std::sync::atomic::AtomicBool,
}

impl VmManager {
    pub fn new(cfg: Config) -> Result<Arc<Self>> {
        cfg.ensure_dirs()?;
        let store = Arc::new(Store::load(&cfg.state_dir)?);
        let pools = Arc::new(PoolStore::load(&cfg.state_dir)?);
        events::init(&cfg.state_dir);
        // Best-effort: delegating cgroup controllers needs to write under
        // /sys/fs/cgroup, which isn't available in every environment this
        // constructor runs in (e.g. an unprivileged `cargo test`) — a
        // failure here shouldn't block VmManager from doing everything
        // else, only resource-control/metrics for VMs it launches.
        if let Err(e) = fluxvm_cgroup::ensure_delegation() {
            tracing::warn!(error = %e, "failed to delegate cgroup controllers — resource control/metrics will be unavailable");
        }
        if let Err(e) = fluxvm_network::xdp::ensure(&cfg.sandbox.dataplane) {
            if cfg.sandbox.dataplane.xdp.required {
                return Err(e).context("initializing required FluxVM XDP guard");
            }
            tracing::warn!(error = %e, "FluxVM XDP guard unavailable; continuing without it");
        }
        Ok(Arc::new(Self {
            cfg,
            store,
            pools,
            backfill_locks: AsyncMutex::new(HashMap::new()),
            catalog_lock: AsyncMutex::new(()),
            template_lock: AsyncMutex::new(()),
            sandbox_volume_lock: AsyncMutex::new(()),
            sandbox_gpu_lock: AsyncMutex::new(()),
            activity: AsyncMutex::new(HashMap::new()),
            scheduled_snapshots_busy: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// Record sandbox activity (resets AutoPause idle timer).
    pub async fn touch_activity(&self, id: Uuid) {
        self.activity.lock().await.insert(id, chrono::Utc::now());
    }

    pub async fn last_activity(&self, id: Uuid) -> Option<chrono::DateTime<chrono::Utc>> {
        self.activity.lock().await.get(&id).copied()
    }

    /// Resume a paused FluxVm sandbox if needed, then mark activity.
    pub async fn ensure_running_for_request(self: &Arc<Self>, id: Uuid) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        if vm.status == VmStatus::Paused {
            vm = self.resume(id).await.context("AutoResume on request")?;
        }
        self.touch_activity(id).await;
        Ok(vm)
    }

    /// Register a new image catalog entry — see `fluxvm_image::catalog::add_entry`.
    pub async fn add_catalog_entry(
        &self,
        name: String,
        source: String,
        format: String,
    ) -> Result<fluxvm_image::catalog::CatalogEntry> {
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::add_entry(&self.cfg, name, source, format).await
    }

    /// Remove an image catalog entry — see `fluxvm_image::catalog::remove_entry`.
    pub async fn remove_catalog_entry(&self, name: &str) -> Result<()> {
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::remove_entry(&self.cfg, name)
    }

    /// Rename an image catalog entry — see `fluxvm_image::catalog::rename_entry`.
    pub async fn rename_catalog_entry(
        &self,
        name: &str,
        new_name: &str,
    ) -> Result<fluxvm_image::catalog::CatalogEntry> {
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::rename_entry(&self.cfg, name, new_name)
    }

    /// Clone an image catalog entry under a new name — see `fluxvm_image::catalog::clone_entry`.
    pub async fn clone_catalog_entry(
        &self,
        name: &str,
        target_name: &str,
    ) -> Result<fluxvm_image::catalog::CatalogEntry> {
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::clone_entry(&self.cfg, name, target_name)
    }

    /// Export a catalog entry's resolved file to `dest` — see `fluxvm_image::catalog::export_entry`.
    pub async fn export_catalog_entry(&self, name: &str, dest: &std::path::Path) -> Result<()> {
        // No write to catalog.json here, but still serialized against
        // add/remove/rename/clone so a concurrent rename can't yank the
        // entry out from under an in-flight export's lookup.
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::export_entry(&self.cfg, name, dest).await
    }

    /// Toggle a catalog entry's read-only flag — see `fluxvm_image::catalog::set_read_only`.
    pub async fn set_catalog_read_only(
        &self,
        name: &str,
        read_only: bool,
    ) -> Result<fluxvm_image::catalog::CatalogEntry> {
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::set_read_only(&self.cfg, name, read_only)
    }

    /// Remove orphaned cached downloads — see `fluxvm_image::catalog::clean_downloads`.
    pub async fn clean_catalog_downloads(&self) -> Result<Vec<String>> {
        let _guard = self.catalog_lock.lock().await;
        fluxvm_image::catalog::clean_downloads(&self.cfg)
    }

    /// One catalog entry with signature verification, or an error if missing.
    pub async fn get_catalog_entry(
        &self,
        name: &str,
    ) -> Result<fluxvm_image::catalog::CatalogListEntry> {
        let entries = fluxvm_image::catalog::list_with_verification(&self.cfg)?;
        entries
            .into_iter()
            .find(|e| e.entry.name == name)
            .with_context(|| format!("catalog entry {name:?} not found"))
    }

    fn autostart_dir(&self) -> std::path::PathBuf {
        self.cfg.state_dir.join("autostart")
    }

    /// Mark a VM to be started when `fluxctl serve` boots (machinectl `enable`).
    pub async fn enable(&self, id: Uuid) -> Result<()> {
        self.get(id).await?;
        let dir = self.autostart_dir();
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(id.to_string()), b"")?;
        Ok(())
    }

    /// Clear the autostart mark (machinectl `disable`).
    pub async fn disable(&self, id: Uuid) -> Result<()> {
        self.get(id).await?;
        let path = self.autostart_dir().join(id.to_string());
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }

    /// Whether `enable` has marked this VM for autostart.
    pub async fn is_enabled(&self, id: Uuid) -> bool {
        self.autostart_dir().join(id.to_string()).exists()
    }

    /// Start every Stopped VM that was `enable`d. Called from `fluxctl serve`.
    pub async fn start_autostart_vms(self: &Arc<Self>) {
        let dir = self.autostart_dir();
        let Ok(entries) = fs::read_dir(&dir) else {
            return;
        };
        for ent in entries.flatten() {
            let name = ent.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(id) = Uuid::parse_str(name) else {
                continue;
            };
            match self.get(id).await {
                Ok(vm) if vm.status == VmStatus::Stopped => {
                    if let Err(e) = self.start(id).await {
                        tracing::warn!(%id, error = %e, "autostart failed");
                    } else {
                        tracing::info!(%id, "autostarted enabled VM");
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(%id, error = %e, "autostart: VM missing; clearing enable mark");
                    let _ = fs::remove_file(dir.join(id.to_string()));
                }
            }
        }
    }

    /// Create the VM's cgroup and migrate `pid` into it, storing the
    /// resulting path on `record`. Best-effort and non-fatal: a VM whose
    /// cgroup setup fails still runs — it just can't be resource-controlled
    /// or have its metrics read later (`set_resources`/`freeze`/`metrics`/
    /// `pressure` all report a clear "no cgroup" error rather than a
    /// confusing failure deeper in the cgroupfs).
    fn attach_cgroup(&self, id: Uuid, pid: u32, record: &mut VmRecord, vfio_devices: &[String]) {
        match fluxvm_cgroup::CgroupManager::create_and_migrate(&id.to_string(), pid) {
            Ok(mgr) => {
                let cgroup_path = mgr.path().to_path_buf();
                record.cgroup_path = Some(cgroup_path.clone());
                // FC1: optional host oversubscription defaults from [policy].
                if let Some(pct) = self.cfg.policy.default_cpu_quota_percent {
                    if let Err(e) = mgr
                        .cpu()
                        .set_max(&fluxvm_cgroup::CpuMax::from_percent(pct as u64))
                    {
                        tracing::warn!(vm = %id, error = %e, "policy default_cpu_quota_percent apply failed");
                    }
                }
                if self.cfg.policy.memory_max_equals_guest {
                    let bytes = record.request.memory_mib.saturating_mul(1024 * 1024);
                    if let Err(e) = mgr.memory().set_max(bytes) {
                        tracing::warn!(vm = %id, error = %e, "policy memory_max_equals_guest apply failed");
                    }
                }
                // Sentinel Set 7S: device-cgroup + outbound-IP hardening for
                // the QEMU process, layered on the cgroup we just created.
                // Best-effort like the cgroup creation above it — a failure
                // here means this VM runs without the extra hardening, not
                // that it fails to launch at all.
                if self.cfg.sandbox.dataplane.mode != fluxvm_core::config::DataplaneMode::Legacy {
                    if let Err(e) = fluxvm_network::qemu_cgroup::attach(
                        &self.cfg.sandbox.dataplane,
                        id,
                        &cgroup_path,
                        vfio_devices,
                    ) {
                        tracing::warn!(vm = %id, error = %e, "Set 7S QEMU cgroup hardening attach failed");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(vm = %id, error = %e, "failed to create cgroup for VM — resource control/metrics unavailable for it")
            }
        }
    }

    /// `req.cloud_init` with a mount runcmd appended per `req.shared_folders`
    /// entry — writing a real `/etc/fstab` line (not just a one-shot `mount`
    /// command) so the share keeps working across a later stop/start, since
    /// cloud-init's own `runcmd` module only replays on a *new* instance-id,
    /// not a relaunch of the same VM (see `VmManager::start`'s doc comment).
    /// `Some` even when the caller passed no `cloud_init` at all, as long as
    /// there's at least one share to mount — otherwise the share would be
    /// attached to the guest but never actually reachable inside it.
    fn effective_cloud_init(req: &CreateVmRequest) -> Option<CloudInitSpec> {
        if req.shared_folders.is_empty() {
            return req.cloud_init.clone();
        }
        let mut ci = req.cloud_init.clone().unwrap_or_default();
        if req.backend == BackendKind::Firecracker {
            // Firecracker has no virtio-fs: shares are packed to ext4 and
            // attached as secondary virtio-block drives. Drive order is
            // root (vda), cloud-init seed (vdb — always present when this
            // function returns Some), then share0… as vdc+.
            let mut vd_idx = 2u8;
            for share in &req.shared_folders {
                let path = &share.guest_path;
                let dev = format!("/dev/vd{}", (b'a' + vd_idx) as char);
                let opts = if share.read_only { "ro" } else { "defaults" };
                ci.runcmd.push(format!("mkdir -p {path}"));
                ci.runcmd.push(format!(
                    "grep -qF ' {path} ' /etc/fstab || echo '{dev} {path} ext4 {opts} 0 0' >> /etc/fstab"
                ));
                ci.runcmd
                    .push(format!("mount {path} || mount {dev} {path}"));
                vd_idx = vd_idx.saturating_add(1);
            }
            return Some(ci);
        }
        for (i, share) in req.shared_folders.iter().enumerate() {
            let tag = format!("fs{i}");
            let path = &share.guest_path;
            // Host virtiofsd (rust-vmm) has no --readonly; enforce RO in-guest.
            let opts = if share.read_only { "ro" } else { "defaults" };
            ci.runcmd.push(format!("mkdir -p {path}"));
            ci.runcmd.push(format!(
                "grep -qF ' {path} ' /etc/fstab || echo '{tag} {path} virtiofs {opts} 0 0' >> /etc/fstab"
            ));
            ci.runcmd.push(format!("mount {path}"));
        }
        Some(ci)
    }

    fn cgroup_manager(&self, vm: &VmRecord) -> Result<fluxvm_cgroup::CgroupManager> {
        let path = vm.cgroup_path.clone().with_context(|| {
            format!(
                "VM {} has no cgroup (not running, or cgroup setup failed at launch)",
                vm.id
            )
        })?;
        Ok(fluxvm_cgroup::CgroupManager::from_path(path)?)
    }

    /// Apply a partial set of cgroup v2 resource-control settings — only
    /// the fields set in `patch` are touched.
    pub async fn set_resources(
        &self,
        id: Uuid,
        patch: fluxvm_core::model::ResourcePatch,
    ) -> Result<()> {
        let vm = self.get(id).await?;
        let mgr = self.cgroup_manager(&vm)?;
        if let Some(percent) = patch.cpu_quota_percent {
            mgr.cpu()
                .set_max(&fluxvm_cgroup::CpuMax::from_percent(percent as u64))?;
        }
        if let Some(bytes) = patch.memory_max_bytes {
            mgr.memory().set_max(bytes)?;
        }
        if let Some(weight) = patch.io_weight {
            mgr.io().set_weight(weight as u64)?;
        }
        if let Some(max) = patch.pids_max {
            mgr.pids().set_max(max)?;
        }
        if let Some(cpus) = &patch.cpuset_cpus {
            mgr.cpuset().set_cpus(cpus)?;
        }
        Ok(())
    }

    /// Hot-add `add_vcpus` vCPUs to a running VM without a reboot -- QEMU
    /// and Cloud Hypervisor only, Firecracker still has no hotplug support
    /// in this codebase. Bounded by the `max_vcpus` headroom reserved at
    /// creation (`CreateVmRequest::max_vcpus`); fails clearly once that
    /// headroom is exhausted rather than silently no-op'ing.
    pub async fn hotplug_cpu(&self, id: Uuid, add_vcpus: u8) -> Result<u8> {
        let vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::HotplugCpu,
        )?;
        let vcpus = match vm.backend {
            BackendKind::Qemu => fluxvm_qemu::hotplug_cpu(&self.cfg, &vm, add_vcpus).await?,
            BackendKind::CloudHypervisor => {
                fluxvm_cloud_hypervisor::hotplug_cpu(&self.cfg, &vm, add_vcpus).await?
            }
            other => bail!("CPU hotplug is not supported for backend {other:?}"),
        };
        self.record_hotplugged_size(id, Some(vcpus), None).await?;
        Ok(vcpus)
    }

    /// Record a hot-added size as live-only labels (the next boot uses the
    /// requested size again). The hot-added devices differ from a cold boot,
    /// so the VM is not live-migratable until it is restarted.
    async fn record_hotplugged_size(
        &self,
        id: Uuid,
        vcpus: Option<u8>,
        memory_mib: Option<u64>,
    ) -> Result<()> {
        let mut vm = self.get(id).await?;
        if let Some(v) = vcpus.filter(|v| *v > 0) {
            vm.labels
                .insert(live_migration::LIVE_VCPUS_LABEL.into(), v.to_string());
        }
        if let Some(m) = memory_mib.filter(|m| *m > 0) {
            vm.labels
                .insert(live_migration::LIVE_MEMORY_LABEL.into(), m.to_string());
        }
        vm.labels
            .insert(live_migration::HOTPLUGGED_LABEL.into(), "true".into());
        self.store.update(vm).await
    }

    /// Hot-add `add_memory_mib` MiB of RAM to a running VM without a
    /// reboot -- QEMU and Cloud Hypervisor only, same backend restriction
    /// as `hotplug_cpu`. Returns the VM's new total live memory.
    pub async fn hotplug_memory(&self, id: Uuid, add_memory_mib: u64) -> Result<u64> {
        let vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::HotplugMemory,
        )?;
        let total = match vm.backend {
            BackendKind::Qemu => {
                fluxvm_qemu::hotplug_memory(&self.cfg, &vm, add_memory_mib).await?
            }
            BackendKind::CloudHypervisor => {
                fluxvm_cloud_hypervisor::hotplug_memory(&self.cfg, &vm, add_memory_mib).await?
            }
            other => bail!("memory hotplug is not supported for backend {other:?}"),
        };
        self.record_hotplugged_size(id, None, Some(total)).await?;
        Ok(total)
    }

    /// Hot-add a virtio-net NIC on `bridge`. QEMU only. The TAP is recorded
    /// on the VM's `NetworkSpec` so stop/delete removes it. Warm-pool
    /// templates should boot with `network.mode=none` so `hotplug-pcie-0`
    /// is free; later calls fill `extra`.
    pub async fn hotplug_nic(&self, id: Uuid, bridge: String, mac: Option<String>) -> Result<()> {
        let mut vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::HotplugNic,
        )?;
        if vm.backend != BackendKind::Qemu {
            bail!("NIC hotplug is supported for the QEMU backend only");
        }
        if matches!(
            vm.request.network,
            NetworkSpec::User { .. } | NetworkSpec::Macvtap { .. }
        ) {
            bail!(
                "NIC hotplug requires network.mode=none (warm-pool template) or tap; \
                 user/macvtap already occupies the primary NIC"
            );
        }
        let in_netns = matches!(vm.request.network, NetworkSpec::Tap { netns: true, .. });
        let index = vm_nic_hotplug_index(&vm);
        if index >= 4 {
            bail!("NIC hotplug headroom exhausted (4 PCIe root ports reserved at boot)");
        }
        let tap = format!("hn{index}{}", &id.simple().to_string()[..6]);
        fluxvm_network::add_bridge_tap(&tap, &bridge)
            .await
            .context("creating hotplug TAP")?;
        // A claimed Secure Containers VM carries its Pod's UID; attach the dataplane with that identity, as
        // the cold create path does, so Pod-scoped network policy applies to it.
        if let Some(uid) = vm.request.pod_uid.as_deref() {
            let (cfg, tap_name, uid) = (self.cfg.clone(), tap.clone(), uid.to_string());
            let applied = tokio::task::spawn_blocking(move || {
                fluxvm_network::dataplane::apply_sandbox_policy(
                    &cfg,
                    id,
                    Some(&tap_name),
                    None,
                    &[],
                    Some(&uid),
                )
            })
            .await
            .context("dataplane apply panicked")?;
            if let Err(e) = applied {
                let _ = fluxvm_network::cleanup_tap(&tap).await;
                return Err(e).context("applying the VM dataplane for the hotplugged NIC");
            }
        }
        // QEMU runs inside the VM's netns there and can't open a host tap by name.
        let plugged = if in_netns {
            match fluxvm_network::direct::open_host_tap(&tap) {
                Ok(fd) => {
                    let r = fluxvm_qemu::hotplug_nic_fd(&vm, fd, mac.as_deref(), index).await;
                    fluxvm_core::process::close_fd(fd);
                    r
                }
                Err(e) => Err(e),
            }
        } else {
            fluxvm_qemu::hotplug_nic(&vm, &tap, mac.as_deref(), index).await
        };
        if let Err(e) = plugged {
            let _ = fluxvm_network::cleanup_tap(&tap).await;
            return Err(e);
        }
        record_hotplugged_nic(&mut vm, tap, bridge, mac);
        self.store.update(vm).await?;
        Ok(())
    }

    /// Hot-removes an extra bridged NIC (by MAC or tap name) from a running
    /// QEMU VM and deletes its TAP. Its slot stays reserved as an empty
    /// entry unless it was the last one, so the other NICs keep their PCIe
    /// ports across restarts.
    pub async fn unplug_nic(
        &self,
        id: Uuid,
        req: &fluxvm_core::model::UnplugNicRequest,
    ) -> Result<()> {
        let mut vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::HotplugNic,
        )?;
        if vm.backend != BackendKind::Qemu {
            bail!("NIC unplug is supported for the QEMU backend only");
        }
        if vm.status != VmStatus::Running {
            bail!("NIC unplug needs a running VM (status is {:?})", vm.status);
        }
        let NetworkSpec::Tap {
            tap_name,
            mac,
            extra,
            ..
        } = &mut vm.request.network
        else {
            bail!("VM has no tap NICs to unplug");
        };
        let Some(pos) = extra
            .iter()
            .position(|n| req.matches(n.mac.as_deref(), n.tap_name.as_deref()))
        else {
            if req.matches(
                mac.as_deref(),
                tap_name.as_deref().or(vm.tap_name.as_deref()),
            ) {
                bail!("the primary NIC can't be hot-removed; only extra NICs can");
            }
            bail!("no extra NIC matches {req:?}");
        };
        if extra[pos].direct.is_some() {
            bail!("direct (Pod-owned) NICs are removed with their sandbox, not unplugged");
        }
        let tap = extra[pos].tap_name.clone().unwrap_or_default();
        let index = u8::try_from(pos + 1).context("NIC index overflow")?;
        fluxvm_qemu::unplug_nic(&vm, index).await?;
        if let Err(e) = fluxvm_network::cleanup_tap(&tap).await {
            tracing::warn!(vm = %id, tap, "removing unplugged TAP failed: {e:#}");
        }
        free_nic_slot(&mut vm, pos);
        self.store.update(vm).await?;
        audit_event(
            "vm.nic.unplug",
            &[("vm_id", &id.to_string()), ("tap", &tap)],
        );
        Ok(())
    }

    /// Hot-adds the VM's primary NIC on a bridge-less direct attach (the warm-pool counterpart of
    /// creating a direct VM): the daemon creates the tap (inside the outer device's netns when one
    /// is given), records the wiring and applies the dataplane FIRST -- a direct tap has no bridge,
    /// so without the redirect it carries nothing -- and only then hands the tap to QEMU, as a
    /// descriptor when it lives in another netns. Any failure removes what was created.
    pub async fn hotplug_direct_nic(
        &self,
        id: Uuid,
        direct: fluxvm_core::model::DirectSpec,
        mac: Option<String>,
    ) -> Result<()> {
        let mut vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::HotplugNic,
        )?;
        let prepared = plug_direct_nic(&self.cfg, &vm, direct, mac).await?;
        vm.request.network = prepared.spec.clone();
        vm.tap_name = prepared.tap_name.clone();
        self.store.update(vm).await?;
        Ok(())
    }

    /// Drops the persisted `pod_uid` -> eBPF `pod_id` mapping of a deleted VM so the store does not grow
    /// for the node's lifetime (it was minted for every Secure Containers Pod and never released). Skipped
    /// while another VM still carries the same Pod UID -- a Pod's failed sandbox create is retried on a new
    /// VM, which may already be running when the old one's delete finishes -- because releasing the id would
    /// let a different Pod be minted the same one.
    async fn release_pod_identity(&self, deleted: &VmRecord) {
        let Some(uid) = deleted.request.pod_uid.as_deref() else {
            return;
        };
        if self
            .list()
            .await
            .iter()
            .any(|v| v.id != deleted.id && v.request.pod_uid.as_deref() == Some(uid))
        {
            return;
        }
        let (cfg, uid) = (self.cfg.clone(), uid.to_string());
        let released =
            tokio::task::spawn_blocking(move || fluxvm_network::pod_identity::forget(&cfg, &uid))
                .await;
        if !matches!(released, Ok(Ok(()))) {
            tracing::warn!(vm = %deleted.id, "releasing the Pod identity failed: {released:?}");
        }
    }

    /// Hot-adds a virtiofs share serving `host_path` to a running QEMU VM and returns its tag (`fs{N}`, the
    /// share's index in `shared_folders`). The share is recorded on the VM's request so stop/delete reaps the
    /// `virtiofsd`, and a later restart re-creates it as an ordinary boot-time share. Warm-pool templates
    /// (`network.mode=none`, `shared_memory`) use this to hand a claimed VM its per-Pod shares.
    pub async fn hotplug_share(
        &self,
        id: Uuid,
        host_path: std::path::PathBuf,
        read_only: bool,
    ) -> Result<String> {
        let mut vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::HotplugShare,
        )?;
        if vm.backend != BackendKind::Qemu && vm.backend != BackendKind::CloudHypervisor {
            bail!("share hotplug is supported for the QEMU and Cloud Hypervisor backends only");
        }
        if !matches!(vm.status, VmStatus::Running) {
            bail!(
                "share hotplug needs a running VM (status is {:?})",
                vm.status
            );
        }
        if !host_path.is_dir() {
            bail!("share source {} is not a directory", host_path.display());
        }
        let index = vm.request.shared_folders.len();
        let pid = match vm.backend {
            BackendKind::Qemu => {
                fluxvm_qemu::hotplug_virtiofs(&self.cfg, &vm, &host_path, index).await?
            }
            BackendKind::CloudHypervisor => {
                fluxvm_cloud_hypervisor::hotplug_virtiofs(&self.cfg, &vm, &host_path, index).await?
            }
            _ => unreachable!(),
        };
        let tag = format!("fs{index}");
        vm.virtiofsd_pids.push(pid);
        vm.request
            .shared_folders
            .push(fluxvm_core::model::SharedFolder {
                host_path,
                guest_path: format!("/mnt/{tag}"),
                read_only,
            });
        self.store.update(vm).await?;
        Ok(tag)
    }

    /// The cpuset currently pinned via `set_resources`'s `cpuset_cpus`, or
    /// empty if never set (cgroup default: unrestricted).
    pub async fn get_cpuset(&self, id: Uuid) -> Result<Vec<u32>> {
        let vm = self.get(id).await?;
        Ok(self.cgroup_manager(&vm)?.cpuset().get_cpus()?)
    }

    pub async fn freeze(&self, id: Uuid) -> Result<()> {
        let vm = self.get(id).await?;
        Ok(self.cgroup_manager(&vm)?.freezer().freeze()?)
    }

    pub async fn thaw(&self, id: Uuid) -> Result<()> {
        let vm = self.get(id).await?;
        Ok(self.cgroup_manager(&vm)?.freezer().thaw()?)
    }

    pub async fn is_frozen(&self, id: Uuid) -> Result<bool> {
        let vm = self.get(id).await?;
        Ok(self.cgroup_manager(&vm)?.freezer().is_frozen()?)
    }

    /// Point-in-time CPU/memory/disk usage, read from the VM's cgroup.
    pub async fn metrics(&self, id: Uuid) -> Result<fluxvm_core::model::VmMetrics> {
        let vm = self.get(id).await?;
        let mgr = self.cgroup_manager(&vm)?;

        let cpu_stat = mgr.cpu().get_stat()?;
        let num_cpus = mgr
            .cpuset()
            .get_cpus_effective()
            .ok()
            .filter(|c| !c.is_empty())
            .map(|c| c.len() as u64)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get() as u64)
                    .unwrap_or(1)
            });
        let uptime_secs = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next().map(str::to_string))
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(1.0);
        let total_usec = (uptime_secs * 1_000_000.0) as u64 * num_cpus;
        let cpu_usage_percent = if total_usec == 0 {
            0.0
        } else {
            (cpu_stat.usage_usec as f64 / total_usec as f64 * 100.0)
                .clamp(0.0, 100.0 * num_cpus as f64)
        };

        let memory_usage_bytes = mgr.memory().get_current()?;

        let (disk_read_bytes, disk_write_bytes) = mgr
            .io()
            .get_stat()
            .map(|stats| {
                stats
                    .iter()
                    .fold((0u64, 0u64), |(r, w), s| (r + s.rbytes, w + s.wbytes))
            })
            .unwrap_or((0, 0));

        Ok(fluxvm_core::model::VmMetrics {
            cpu_usage_percent,
            memory_usage_bytes,
            disk_read_bytes,
            disk_write_bytes,
        })
    }

    /// PSI pressure stats for the VM's cgroup.
    pub async fn pressure(&self, id: Uuid) -> Result<fluxvm_core::model::VmPressure> {
        let vm = self.get(id).await?;
        let mgr = self.cgroup_manager(&vm)?;
        let cpu = mgr.cpu().get_pressure().ok();
        let mem = mgr.memory().get_pressure().ok();
        let io = mgr.io().get_pressure().ok();
        Ok(fluxvm_core::model::VmPressure {
            cpu_some: cpu.map(|p| p.some),
            memory_some: mem.as_ref().map(|p| p.some.clone()),
            memory_full: mem.and_then(|p| p.full),
            io_some: io.as_ref().map(|p| p.some.clone()),
            io_full: io.and_then(|p| p.full),
        })
    }

    pub async fn list_network_groups(&self) -> Result<Vec<fluxvm_network::groups::SecurityGroup>> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::groups::list_groups(&cfg))
            .await
            .context("network group list panicked")?
    }

    pub async fn get_network_group(
        &self,
        name: &str,
    ) -> Result<fluxvm_network::groups::SecurityGroup> {
        let cfg = self.cfg.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || fluxvm_network::groups::get_group(&cfg, &name))
            .await
            .context("network group get panicked")?
    }

    pub async fn upsert_network_group(
        &self,
        group: fluxvm_network::groups::SecurityGroup,
    ) -> Result<fluxvm_network::groups::SecurityGroup> {
        let cfg = self.cfg.clone();
        let group = tokio::task::spawn_blocking({
            let cfg = cfg.clone();
            let group = group.clone();
            move || fluxvm_network::groups::upsert_group(&cfg, group)
        })
        .await
        .context("network group upsert panicked")??;
        self.reconcile_group_members(&group.name).await?;
        Ok(group)
    }

    pub async fn delete_network_group(&self, name: &str) -> Result<()> {
        let cfg = self.cfg.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || fluxvm_network::groups::delete_group(&cfg, &name))
            .await
            .context("network group delete panicked")?
    }

    pub async fn list_cnp(&self) -> Result<Vec<fluxvm_network::cnp::CiliumNetworkPolicy>> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::cnp::list_cnp(&cfg))
            .await
            .context("cnp list panicked")?
    }

    pub async fn get_cnp(&self, name: &str) -> Result<fluxvm_network::cnp::CiliumNetworkPolicy> {
        let cfg = self.cfg.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || fluxvm_network::cnp::get_cnp(&cfg, &name))
            .await
            .context("cnp get panicked")?
    }

    pub async fn apply_cnp(
        &self,
        policy: fluxvm_network::cnp::CiliumNetworkPolicy,
    ) -> Result<fluxvm_network::groups::SecurityGroup> {
        let cfg = self.cfg.clone();
        let group =
            tokio::task::spawn_blocking(move || fluxvm_network::cnp::apply_cnp(&cfg, policy))
                .await
                .context("cnp apply panicked")??;
        self.reconcile_group_members(&group.name).await?;
        Ok(group)
    }

    async fn reconcile_group_members(&self, group_name: &str) -> Result<()> {
        let vms = self.list().await;
        for vm in vms {
            if vm.status != VmStatus::Running && vm.status != VmStatus::Paused {
                continue;
            }
            let policy = match fluxvm_network::dataplane::load_policy(&self.cfg, vm.id)? {
                Some(p) => p,
                None => continue,
            };
            let groups = fluxvm_network::groups::resolve_groups(&self.cfg, &policy)?;
            if !groups.iter().any(|g| g.name == group_name) {
                continue;
            }
            let guest_cidr = vm.guest_ip.as_deref().map(|ip| format!("{ip}/32"));
            let iface = fluxvm_network::dataplane_interface_name(
                vm.id,
                vm.netns.is_some(),
                vm.tap_name.as_deref(),
            );
            let extra = if self.cfg.sandbox.egress_allow_domains.is_empty() {
                vec![]
            } else {
                fluxvm_network::egress::resolve_allow_cidrs(&self.cfg.sandbox.egress_allow_domains)
                    .await
            };
            fluxvm_network::dataplane::reconfigure_sandbox_policy(
                &self.cfg,
                vm.id,
                iface.as_deref(),
                guest_cidr.as_deref(),
                &extra,
            )?;
        }
        Ok(())
    }

    pub async fn readyz(&self) -> Result<serde_json::Value> {
        let kvm = std::path::Path::new("/dev/kvm").exists();
        let state_ok = self.cfg.state_dir.exists();
        let health = fluxvm_network::dataplane::health(&self.cfg).ok();
        let dp_ok = health.as_ref().map(|h| h.ok).unwrap_or(true);
        let required = self.cfg.sandbox.dataplane.required
            && !matches!(
                self.cfg.sandbox.dataplane.mode,
                fluxvm_core::config::DataplaneMode::Legacy
            );
        let ok = state_ok && (!required || (dp_ok && health.is_some()));
        Ok(serde_json::json!({
            "ok": ok,
            "kvm": kvm,
            "state_dir": self.cfg.state_dir,
            "dataplane": health,
            "secure_containers": Self::secure_containers_status(kvm),
        }))
    }

    /// FluxVM Secure Containers node-capability probe, surfaced under
    /// `readyz.secure_containers` (`docs/contracts/fabric-fluxvm-readyz.json`)
    /// for Fabric's `ContainerGroup` placement to filter candidate nodes on.
    /// This only checks what's visible from the FluxVM daemon itself — it
    /// does NOT know whether containerd's `config.toml` actually registers
    /// the `io.containerd.fluxvm.v2` runtime or whether a `RuntimeClass` has
    /// been applied to the cluster; both remain manual per-node setup today
    /// (see `docs/secure-containers.md`, `scripts/install-secure-containers.sh`).
    fn secure_containers_status(kvm: bool) -> serde_json::Value {
        let shim_installed = Self::secure_containers_shim_path().is_some();
        let guest_image_present = Self::secure_containers_guest_image_path().exists();
        serde_json::json!({
            "available": kvm && shim_installed && guest_image_present,
            "shim_installed": shim_installed,
            "guest_image_present": guest_image_present,
        })
    }

    fn secure_containers_shim_path() -> Option<std::path::PathBuf> {
        const BIN_NAME: &str = "containerd-shim-fluxvm-v2";
        let path_var = std::env::var_os("PATH")?;
        std::env::split_paths(&path_var)
            .map(|dir| dir.join(BIN_NAME))
            .find(|candidate| candidate.is_file())
    }

    fn secure_containers_guest_image_path() -> std::path::PathBuf {
        std::env::var("FLUXVM_CONTAINER_GUEST_IMAGE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from("/var/lib/fluxvm/images/secure-container.qcow2")
            })
    }

    pub async fn network_health(&self) -> Result<fluxvm_network::dataplane::DataplaneHealth> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::dataplane::health(&cfg))
            .await
            .context("dataplane health panicked")?
    }

    pub async fn network_ipcache(&self) -> Result<Vec<fluxvm_network::ipcache::IpcacheEntry>> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::ipcache::list(&cfg))
            .await
            .context("ipcache list panicked")?
    }

    /// `/28` allocation counts for netns sandboxes' persistent IPAM pool —
    /// see `fluxvm_network::ipam`. Independent of dataplane mode: the pool is
    /// only consumed by `network.netns: true` VMs, so a host that never uses
    /// netns sandboxing simply reports an always-empty pool.
    pub async fn network_ipam_status(&self) -> Result<fluxvm_network::ipam::IpamStatus> {
        let state_dir = self.cfg.state_dir.clone();
        tokio::task::spawn_blocking(move || {
            fluxvm_network::ipam::IpamStore::load(&state_dir).status()
        })
        .await
        .context("ipam status panicked")?
    }

    /// Fabric ClusterMesh-like remote identity fan-out into local ipcache.
    pub async fn upsert_remote_ipcache(&self, identity: u32, cidrs: Vec<String>) -> Result<usize> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || {
            fluxvm_network::ipcache::upsert_remote(&cfg, identity, &cidrs)
        })
        .await
        .context("remote ipcache upsert panicked")?
    }

    pub async fn delete_remote_ipcache(&self, identity: u32) -> Result<usize> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || {
            fluxvm_network::ipcache::remove_remote_identity(&cfg, identity)
        })
        .await
        .context("remote ipcache delete panicked")?
    }

    pub async fn refresh_fqdn_policies(&self) -> Result<usize> {
        let vms = self.list().await;
        let mut n = 0usize;
        for vm in vms {
            if vm.status != VmStatus::Running && vm.status != VmStatus::Paused {
                continue;
            }
            let guest_cidr = vm.guest_ip.as_deref().map(|ip| format!("{ip}/32"));
            let mut iface = fluxvm_network::dataplane_interface_name(
                vm.id,
                vm.netns.is_some(),
                vm.tap_name.as_deref(),
            );
            // Fall back to the currently attached edge when the prepared
            // device name is missing (common for paused/stale records).
            if iface.is_none() {
                if let Ok(status) =
                    fluxvm_network::ebpf::attachment_status(&self.cfg.sandbox.dataplane, vm.id)
                {
                    iface = status.interface;
                }
            }
            if iface.is_none() {
                tracing::debug!(
                    vm = %vm.name,
                    id = %vm.id,
                    "skipping FQDN refresh: no host-visible dataplane interface"
                );
                continue;
            }
            let extra = if self.cfg.sandbox.egress_allow_domains.is_empty() {
                vec![]
            } else {
                fluxvm_network::egress::resolve_allow_cidrs(&self.cfg.sandbox.egress_allow_domains)
                    .await
            };
            match fluxvm_network::dataplane::reconfigure_sandbox_policy(
                &self.cfg,
                vm.id,
                iface.as_deref(),
                guest_cidr.as_deref(),
                &extra,
            ) {
                Ok(()) => n += 1,
                Err(err) => {
                    // Host-wide refresh is best-effort across the fleet: one
                    // VM without a repairable edge must not fail the call.
                    tracing::warn!(
                        vm = %vm.name,
                        id = %vm.id,
                        error = %err,
                        "FQDN policy refresh skipped for VM"
                    );
                }
            }
        }
        Ok(n)
    }

    pub async fn network_endpoints(
        &self,
    ) -> Result<Vec<fluxvm_network::endpoint::CiliumEndpointView>> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::endpoint::list(&cfg))
            .await
            .context("endpoint list panicked")?
    }

    pub async fn hubble_observe_views(
        &self,
        limit: usize,
    ) -> Result<Vec<fluxvm_network::packetflow::PacketFlowView>> {
        let endpoints = self.network_endpoints().await?;
        let vms = self.list().await;
        let mode = format!("{:?}", self.cfg.sandbox.dataplane.mode).to_ascii_lowercase();
        let mut flows = Vec::new();
        for vm in vms {
            if vm.status != VmStatus::Running {
                continue;
            }
            let ep = endpoints.iter().find(|e| e.uuid == vm.id);
            let labels = ep.map(|e| e.identity_labels.clone()).unwrap_or_default();
            // F1: prefer CEP SecurityIdentity (cilium-agent or fluxvm-hash) over
            // the Fabric CT sample id so hubble observe shows the same SID as
            // `fluxctl hubble endpoints`.
            let src_sid = ep.map(|e| (e.identity, e.identity_labels.clone()));
            // A bridge-less VM must not be shown behind a bridge it does not have.
            let hop_path = fluxvm_network::packetflow::HopPath::for_vm(vm.id);
            if let Ok(items) = self.network_flows(vm.id, limit.min(32)).await {
                for item in items {
                    let dst_sid = endpoints
                        .iter()
                        .find(|e| {
                            e.networking.addressing.iter().any(|a| {
                                a.ipv4.as_deref() == Some(item.destination.as_str())
                                    || a.ipv6.as_deref() == Some(item.destination.as_str())
                            })
                        })
                        .map(|e| (e.identity, e.identity_labels.clone()));
                    flows.push(fluxvm_network::packetflow::from_flow_record_on_path(
                        &item,
                        &labels,
                        Some(&vm.name),
                        vm.guest_ip.as_deref(),
                        &mode,
                        src_sid.clone(),
                        dst_sid,
                        &hop_path,
                    ));
                }
            }
        }
        Ok(flows)
    }

    pub async fn hubble_observe(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let views = self.hubble_observe_views(limit).await?;
        let mut out = Vec::with_capacity(views.len());
        for v in &views {
            out.push(serde_json::to_value(
                fluxvm_network::packetflow::to_hubble_flow(v),
            )?);
        }
        Ok(out)
    }

    pub async fn network_observe(&self) -> Result<serde_json::Value> {
        let groups = self.list_network_groups().await?;
        let cnps = self.list_cnp().await?;
        let identities = self.list_identities().await?;
        let vms = self.list().await;
        let mut members = Vec::new();
        for vm in vms {
            if let Ok(Some(policy)) = fluxvm_network::dataplane::load_policy(&self.cfg, vm.id) {
                members.push(serde_json::json!({
                    "vm_id": vm.id,
                    "name": vm.name,
                    "status": format!("{:?}", vm.status),
                    "labels": policy.labels,
                    "groups": policy.groups,
                    "identity": fluxvm_network::ebpf::identity_for(vm.id),
                }));
            }
        }
        Ok(serde_json::json!({
            "identities": identities,
            "groups": groups,
            "policies": cnps,
            "endpoints": members,
        }))
    }

    pub async fn delete_cnp(&self, name: &str) -> Result<()> {
        let cfg = self.cfg.clone();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || fluxvm_network::cnp::delete_cnp(&cfg, &name))
            .await
            .context("cnp delete panicked")?
    }

    pub async fn list_identities(&self) -> Result<Vec<serde_json::Value>> {
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || {
            let mut out = Vec::new();
            for id in fluxvm_network::identity::reserved_identities() {
                out.push(serde_json::to_value(id)?);
            }
            for g in fluxvm_network::groups::list_groups(&cfg)? {
                out.push(serde_json::json!({
                    "id": g.identity,
                    "name": g.name,
                    "labels": g.labels,
                    "reserved": false,
                }));
            }
            Ok(out)
        })
        .await
        .context("identity list panicked")?
    }

    pub async fn network_effective(&self, id: Uuid) -> Result<serde_json::Value> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || {
            let policy = fluxvm_network::dataplane::effective_policy(&cfg, id)?;
            let membership = fluxvm_network::groups::resolve_membership(&cfg, &policy)?;
            let (merged, identities) =
                fluxvm_network::groups::merge_group_policy(&cfg, policy.clone())?;
            Ok(serde_json::json!({
                "vm_id": id,
                "vm_identity": fluxvm_network::ebpf::identity_for(id),
                "declared": policy,
                "membership": membership,
                "effective": merged,
                "group_identities": identities,
            }))
        })
        .await
        .context("network effective reader panicked")?
    }

    pub async fn network_policy(
        &self,
        id: Uuid,
    ) -> Result<fluxvm_network::dataplane::VmNetworkPolicy> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::dataplane::effective_policy(&cfg, id))
            .await
            .context("network policy reader panicked")?
    }

    pub async fn set_network_policy(
        &self,
        id: Uuid,
        policy: fluxvm_network::dataplane::VmNetworkPolicy,
    ) -> Result<fluxvm_network::dataplane::VmNetworkPolicy> {
        let vm = self.get(id).await?;
        let previous = fluxvm_network::dataplane::load_policy(&self.cfg, id)?;
        fluxvm_network::dataplane::save_policy(&self.cfg, id, &policy)?;

        if vm.status == VmStatus::Running || vm.status == VmStatus::Paused {
            let guest_cidr = vm.guest_ip.as_deref().map(|ip| format!("{ip}/32"));
            let iface = fluxvm_network::dataplane_interface_name(
                id,
                vm.netns.is_some(),
                vm.tap_name.as_deref(),
            );
            let extra = if self.cfg.sandbox.egress_allow_domains.is_empty() {
                vec![]
            } else {
                fluxvm_network::egress::resolve_allow_cidrs(&self.cfg.sandbox.egress_allow_domains)
                    .await
            };
            if let Err(e) = fluxvm_network::dataplane::reconfigure_sandbox_policy(
                &self.cfg,
                id,
                iface.as_deref(),
                guest_cidr.as_deref(),
                &extra,
            ) {
                // Restore both durable control-plane state and kernel state.
                match previous.as_ref() {
                    Some(old) => {
                        let _ = fluxvm_network::dataplane::save_policy(&self.cfg, id, old);
                    }
                    None => {
                        let _ = fluxvm_network::dataplane::delete_policy(&self.cfg, id);
                    }
                }
                let _ = fluxvm_network::dataplane::reconfigure_sandbox_policy(
                    &self.cfg,
                    id,
                    iface.as_deref(),
                    guest_cidr.as_deref(),
                    &extra,
                );
                return Err(e).context("applying updated VM network policy");
            }
        }
        Ok(policy)
    }

    pub async fn pod_network_policy(
        &self,
        id: Uuid,
    ) -> Result<Option<fluxvm_network::dataplane::PodNetworkPolicy>> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::dataplane::load_pod_policy(&cfg, id))
            .await
            .context("Pod network policy reader panicked")?
    }

    /// Set 6S: Kubernetes-Pod-identity-scoped policy, additive on top of
    /// `set_network_policy`'s VM-level CIDR/L4 policy. Requires the VM to
    /// already be attached with a Pod identity (see `CreateVmRequest::pod_uid`)
    /// -- unlike `set_network_policy`, this does not attempt to attach a VM
    /// that isn't already running eBPF, since Pod-scoped policy has no
    /// standalone meaning without a VM-level attachment to layer onto.
    pub async fn set_pod_network_policy(
        &self,
        id: Uuid,
        policy: Option<fluxvm_network::dataplane::PodNetworkPolicy>,
    ) -> Result<()> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || {
            fluxvm_network::dataplane::set_pod_network_policy(&cfg, id, policy)
        })
        .await
        .context("Pod network policy apply panicked")?
    }

    pub async fn network_status(
        &self,
        id: Uuid,
    ) -> Result<fluxvm_network::dataplane::DataplaneStatus> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::dataplane::status(&cfg, id))
            .await
            .context("network status reader panicked")?
    }

    pub async fn network_stats(
        &self,
        id: Uuid,
    ) -> Result<fluxvm_network::dataplane::DataplaneStats> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::dataplane::stats(&cfg, id))
            .await
            .context("network stats reader panicked")?
    }

    pub async fn network_flows(
        &self,
        id: Uuid,
        limit: usize,
    ) -> Result<Vec<fluxvm_network::dataplane::FlowRecord>> {
        self.get(id).await?;
        let cfg = self.cfg.clone();
        tokio::task::spawn_blocking(move || fluxvm_network::dataplane::flows(&cfg, id, limit))
            .await
            .context("network flow reader panicked")?
    }

    pub async fn create(self: &Arc<Self>, mut req: CreateVmRequest) -> Result<VmRecord> {
        let started = std::time::Instant::now();
        // Resolve BackendKind::Auto before anything else — everything below
        // (the disk filename, the persisted record, the launch dispatch)
        // assumes a concrete backend and must never see Auto.
        req.backend = resolve_backend(&req, &self.cfg);
        let requested_profile = req.security_profile;
        let catalog_signed = fluxvm_image::catalog::is_approved_signed_image(&self.cfg, &req.image);
        let caps = fluxvm_core::security::HostCapabilities::discover(&self.cfg);
        fluxvm_core::security::validate_create_request(
            requested_profile,
            req.backend == BackendKind::Qemu,
            &req.extra_args,
            req.shared_memory,
            req.hugepages == Some(true),
            req.loadvm_tag.is_some(),
            &caps,
            self.cfg.security.allow_unverified_confidential,
        )?;
        if requested_profile.requires_measurement_chain() {
            if !catalog_signed {
                bail!(
                    "security_profile {} requires an approved signed catalog image",
                    requested_profile.as_str()
                );
            }
            req.secure_boot = Some(true);
            req.tpm = Some(true);
        }
        // Resolved before policy so allowed_image_dirs governs the actual
        // downloaded/verified file a catalog alias points to, not the
        // alias string itself.
        let resolved = fluxvm_image::catalog::resolve_with_provenance(&self.cfg, &req.image)
            .await
            .context("resolving image from catalog")?;
        fluxvm_core::policy::require_signed_catalog(
            self.cfg.policy.require_catalog_names,
            resolved.from_catalog,
            resolved.signed_by.as_deref(),
        )?;
        let image_sha256 = resolved.sha256.clone().unwrap_or_default();
        let signed_by = resolved.signed_by.clone().unwrap_or_default();
        req.image = resolved.path;
        validate_policy(&req, &self.cfg)?;
        validate_native_kvm_profile(&req, &self.cfg)?;
        validate_netns_extras(&req)?;
        if !req.cdroms.is_empty() {
            if req.backend != BackendKind::Qemu {
                anyhow::bail!("cdroms requires backend qemu");
            }
            if req.cdroms.len() > fluxvm_core::model::MAX_CDROMS {
                anyhow::bail!("at most {} cdroms", fluxvm_core::model::MAX_CDROMS);
            }
            let mut seen = std::collections::HashSet::new();
            for c in &mut req.cdroms {
                fluxvm_qemu::disks::validate_disk_name(&c.name)
                    .with_context(|| format!("cdrom {:?}", c.name))?;
                if !seen.insert(c.name.clone()) {
                    anyhow::bail!("duplicate cdrom name {:?}", c.name);
                }
                c.path = self
                    .check_disk_source(&c.path)
                    .with_context(|| format!("cdrom {:?}", c.name))?;
            }
        }
        let ledger = self.store.quota_ledger().await?;
        if let Some(tenant) = req.tenant.as_deref()
            && !self.cfg.policy.tenants.is_empty()
        {
            if let Err(e) = fluxvm_core::policy::enforce_tenant_totals(
                tenant,
                req.vcpus,
                req.memory_mib,
                &self.cfg.policy,
                &ledger,
            ) {
                let reason = e.to_string();
                audit_event("quota.deny", &[("tenant", tenant), ("reason", &reason)]);
                return Err(e);
            }
        }
        if let Err(e) = fluxvm_core::policy::enforce_host_totals(
            req.vcpus,
            req.memory_mib,
            &self.cfg.policy,
            &fluxvm_core::policy::ledger_for_host_admission(&ledger),
        ) {
            let reason = e.to_string();
            audit_event("quota.deny", &[("scope", "host"), ("reason", &reason)]);
            return Err(e);
        }
        // Every storage backend except CephRbd points `image` at a real
        // filesystem entry (a file for Default/Nbd, a block device for
        // LvmThin) — CephRbd's `image` is a `pool/image` reference with no
        // local path to check at all.
        if !req.storage.is_ceph_rbd() && !req.image.exists() {
            bail!("base image does not exist: {}", req.image.display());
        }
        let id = Uuid::new_v4();
        let workspace = self.cfg.state_dir.join("instances").join(id.to_string());
        fs::create_dir_all(&workspace)?;
        let disk = workspace.join(if req.backend == BackendKind::Qemu {
            "root.qcow2"
        } else {
            "root.raw"
        });
        let log_path = workspace.join("console.log");
        let expires_at = req
            .ttl_seconds
            .map(|s| Utc::now() + Duration::seconds(s as i64));
        let needs_cid = req.agent.as_ref().is_some_and(|a| a.enabled);
        // Every agent-enabled VM gets a token whether the caller supplied
        // one or not — generated here (before `placeholder` is built) so
        // the persisted record always reflects the token actually burned
        // into the guest's disk below, never a stale/absent one.
        if needs_cid {
            let agent = req
                .agent
                .as_mut()
                .expect("needs_cid implies req.agent is Some");
            if agent.token.is_none() {
                agent.token = Some(Uuid::new_v4().to_string());
            }
        }

        let placeholder = VmRecord {
            id,
            name: req.name.clone(),
            backend: req.backend,
            status: VmStatus::Creating,
            pid: None,
            created_at: Utc::now(),
            expires_at,
            workspace: workspace.clone(),
            disk: disk.clone(),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: log_path.clone(),
            error: None,
            request: req.clone(),
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: Vec::new(),
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
            requested_security_profile: requested_profile,
            achieved_security_profile: fluxvm_core::security::SecurityProfile::default(),
            security_evidence: None,
            labels: Default::default(),
        };
        // Deciding the CID and reserving it happen as one atomic, locked
        // operation in the store — see fluxvm-storage::Store::insert_with_cid
        // for why a separate "list, then insert" pair isn't safe across
        // concurrent `fluxvm` processes.
        let mut record = self
            .store
            .insert_with_cid(placeholder, needs_cid, FIRST_GUEST_CID)
            .await?;
        let guest_cid = record.guest_cid;

        if req.qga.as_ref().is_some_and(|q| q.enabled)
            && !matches!(
                req.backend,
                BackendKind::Qemu | BackendKind::CloudHypervisor
            )
        {
            anyhow::bail!(
                "qga.enabled requires backend qemu (virtio-serial) or cloud-hypervisor (serial socket)"
            );
        }
        // secure_boot is QEMU-only; tpm is QEMU or Cloud Hypervisor -- see
        // secure_boot_or_tpm_backend_error's own doc comment for why the
        // two have different real scope. Unlike
        // vfio_devices/numa_node/hugepages, which other backends silently
        // ignore, these are hard-rejected on a mismatched backend: a
        // caller believing they got Secure Boot/measured boot when they
        // silently didn't is a real, security-relevant footgun, not a
        // cosmetic no-op.
        if let Some(msg) = secure_boot_or_tpm_backend_error(&req) {
            anyhow::bail!(msg);
        }
        if !req.data_disks.is_empty() && req.backend != BackendKind::Qemu {
            anyhow::bail!("data_disks requires backend qemu");
        }

        let result: Result<()> = async {
            if req.storage == StorageBackend::Shared {
                if req.image.starts_with(self.clone_base_dir()) {
                    bail!("storage=shared cannot use a disk under the managed clone directory");
                }
                // Claimed before provisioning writes the agent token into it.
                self.claim_shared_disk(&req.image, id, &[]).await?;
            }
            let agent_token = req.agent.as_ref().and_then(|a| a.token.as_deref());
            let provisioned = fluxvm_image::storage::provision(
                &self.cfg,
                &req.image,
                req.backend,
                req.storage,
                &workspace,
                &disk,
                req.disk_size_gib,
                id,
                agent_token,
            )
            .await
            .context("provisioning VM disk")?;
            record.disk = provisioned.disk.clone();
            record.lvm_lv = provisioned.lvm_lv.clone();
            record.nbd_pid = provisioned.nbd_pid;
            for d in &req.data_disks {
                let backing = self.check_disk_source(&d.backing)?;
                fluxvm_qemu::disks::create_overlay(&self.cfg, &workspace, &d.name, &backing)
                    .await
                    .with_context(|| format!("creating data disk {:?}", d.name))?;
            }
            // Network prep runs before the cloud-init seed: a static
            // network-config (CloudInitSpec.static_network) needs the
            // guest's reserved address, which only exists once
            // fluxvm_network::prepare has actually created the namespace
            // (see fluxvm_network::netns::NetnsHandle).
            let network = fluxvm_network::prepare(&self.cfg, id, &req.network).await?;
            let dataplane_if = fluxvm_network::dataplane_interface(id, &network);
            let network_spec_for_dataplane = network.spec.clone();
            record.tap_name = network.tap_name.clone();
            record.netns = network.netns.clone();
            record.dhcp_leasefile = network.dhcp_leasefile.clone();
            record.guest_ip = network.guest_ip.clone();

            let effective_cloud_init = Self::effective_cloud_init(&req);
            let static_net = network
                .guest_cidr
                .as_deref()
                .zip(network.gateway.as_deref());
            let native_kvm = req.backend == BackendKind::FluxVm
                && self.cfg.fluxvm_engine == fluxvm_core::config::FluxVmEngine::Kvm;
            let seed = match &effective_cloud_init {
                Some(ci) if native_kvm => {
                    let disk = record.disk.clone();
                    let workspace = workspace.clone();
                    let ci = ci.clone();
                    let static_net = static_net.map(|(cidr, gateway)| (cidr.to_owned(), gateway.to_owned()));
                    tokio::task::spawn_blocking(move || {
                        fluxvm_image::cloudinit::inject_nocloud_raw(
                            &disk,
                            &workspace,
                            &ci,
                            static_net.as_ref().map(|(cidr, gateway)| (cidr.as_str(), gateway.as_str())),
                        )
                    })
                    .await
                    .context("native KVM NoCloud worker panicked")??;
                    None
                }
                Some(ci) => Some(
                    fluxvm_image::cloudinit::build_seed(&self.cfg, &workspace, ci, static_net)
                        .await?,
                ),
                None => None,
            };
            record.seed_disk = seed.clone();

            // QEMU talks straight to the guest_cid over a real kernel vsock
            // device; Cloud Hypervisor/Firecracker instead proxy vsock over
            // a UDS the VMM creates at launch, so only they need a path.
            let vsock_socket = match (guest_cid, req.backend) {
                (Some(_), BackendKind::Qemu) => None,
                (Some(_), _) => Some(workspace.join("vsock.sock")),
                (None, _) => None,
            };

            let guest_cidr_for_policy = network
                .guest_cidr
                .clone()
                .or_else(|| record.guest_ip.as_ref().map(|ip| format!("{ip}/32")));

            // Fabric and most production drivers use QEMU/CH/FC with TAP+netns;
            // attach the VM-edge dataplane for every backend (not only flux-vm).
            {
                let allow_cidrs = if self.cfg.sandbox.egress_allow_domains.is_empty() {
                    vec![]
                } else {
                    fluxvm_network::egress::resolve_allow_cidrs(
                        &self.cfg.sandbox.egress_allow_domains,
                    )
                    .await
                };
                if let Err(e) = fluxvm_network::dataplane::apply_sandbox_policy(
                    &self.cfg,
                    id,
                    dataplane_if.as_deref(),
                    guest_cidr_for_policy.as_deref(),
                    &allow_cidrs,
                    req.pod_uid.as_deref(),
                ) {
                    if is_direct(&network_spec_for_dataplane)
                        || self.cfg.sandbox.dataplane.required
                        || self.cfg.sandbox.dataplane.mode
                            != fluxvm_core::config::DataplaneMode::Legacy
                    {
                        return Err(e).context("applying VM dataplane before launch");
                    }
                    tracing::warn!(vm = %id, error = %e, "VM dataplane apply failed");
                }
            }

            let ctx = LaunchContext {
                id,
                workspace: workspace.clone(),
                disk: record.disk.clone(),
                seed_disk: seed,
                log_path: log_path.clone(),
                network,
                guest_cid,
                vsock_socket,
                disk_format: fluxvm_image::storage::disk_format(req.backend, req.storage),
                nbd_export: provisioned.nbd_export,
            };
            let launch = backend(req.backend)?.launch(&self.cfg, &req, &ctx).await?;
            record.pid = Some(launch.pid);
            record.control_socket = launch.control_socket;
            record.jail_path = launch.jail_path;
            record.vsock_socket = launch.vsock_socket;
            record.virtiofsd_pids = launch.virtiofsd_pids;
            record.swtpm_pid = launch.swtpm_pid;
            if req.qga.as_ref().is_some_and(|q| q.enabled) {
                record.qga_socket = Some(workspace.join("qga.sock"));
            }
            self.attach_cgroup(id, launch.pid, &mut record, &req.vfio_devices);
            record.status = VmStatus::Running;
            if req.backend == BackendKind::FluxVm
                && !self.cfg.sandbox.egress_proxy_listen.is_empty()
            {
                if let Ok(addr) = self.cfg.sandbox.egress_proxy_listen.parse::<std::net::SocketAddr>()
                {
                    if let Err(e) = fluxvm_network::egress::apply_egress_redirect(addr.port()) {
                        tracing::warn!(vm = %id, error = %e, "egress redirect nftables apply failed");
                    }
                }
            }
            if requested_profile.requires_measurement_chain() && req.backend == BackendKind::Qemu
            {
                let firmware = self.cfg.qemu_ovmf_code.as_deref();
                let evidence = fluxvm_core::security::collect_measured_evidence(
                    fluxvm_core::security::MeasuredLaunchInputs {
                        image: &record.disk,
                        firmware,
                        kernel: req.kernel.as_deref(),
                        catalog_signed,
                        secure_boot: req.secure_boot.unwrap_or(false),
                        vtpm_attached: req.tpm.unwrap_or(false),
                    },
                )?;
                fluxvm_core::security::write_evidence(&workspace, &evidence)?;
                record.security_evidence = Some(evidence);
            }
            record.achieved_security_profile =
                fluxvm_core::security::achieved_security_profile(requested_profile, &caps);
            Ok(())
        }
        .await;

        if let Err(e) = result {
            let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
            if let Some(tap) = &record.tap_name {
                let _ = fluxvm_network::cleanup(
                    &self.cfg.state_dir,
                    id,
                    &req.network,
                    tap,
                    record.netns.as_deref(),
                )
                .await;
            }
            // A later step (network prep, launch) can fail after the disk
            // was already provisioned — don't leak the LV/qemu-nbd process.
            if let Some(lv) = &record.lvm_lv {
                let _ = fluxvm_image::storage::cleanup_lvm_lv(lv).await;
            }
            if let Some(pid) = record.nbd_pid {
                let _ = fluxvm_image::storage::cleanup_nbd(pid).await;
            }
            if req.storage == StorageBackend::Shared {
                self.release_shared_disk(&req.image, id);
            }
            record.status = VmStatus::Failed;
            record.error = Some(format!("{e:#}"));
            self.store.update(record.clone()).await?;
            return Err(e);
        }
        self.touch_activity(id).await;
        self.store.update(record.clone()).await?;
        metrics::record_vm_create(started.elapsed().as_millis() as u64);
        let vm_id = record.id.to_string();
        let tenant = record.request.tenant.clone().unwrap_or_default();
        audit_event(
            "vm.create",
            &[
                ("vm_id", &vm_id),
                ("tenant", &tenant),
                ("image_sha256", &image_sha256),
                ("signed_by", &signed_by),
            ],
        );
        Ok(record)
    }

    pub async fn list(&self) -> Vec<VmRecord> {
        self.store
            .list()
            .await
            .into_iter()
            .map(Self::with_guest_ip)
            .collect()
    }

    /// Per-token `max_vms_per_token`/`max_memory_mib_per_token` enforcement
    /// for `create_vm` and `create_sandbox` (`fluxvm-api`) alike -- shared
    /// here rather than duplicated per call site since both need the exact
    /// same accounting. `actor` is the caller's own token identity
    /// (`AuditActor`); `req` is the about-to-be-created VM/sandbox's
    /// resolved `CreateVmRequest`.
    ///
    /// Previously counted every VM on the node from every token
    /// ("conservative", per this function's own prior comment) against
    /// each token's own quota -- a real correctness bug, and dangerous in
    /// the untrusted-multi-tenant direction specifically: with two tokens
    /// both configured with a quota of 10, the first token to reach 10 VMs
    /// blocked every *other* token from creating any more. A quota meant
    /// to contain a noisy tenant instead let that tenant deny service to
    /// every other tenant. Now filtered to `created_by_token == actor` --
    /// stamped server-side in `create_vm`/`create_sandbox`, never settable
    /// from the request body, so this can't be spoofed by a client either.
    pub fn host_security_capabilities(&self) -> fluxvm_core::security::HostCapabilities {
        fluxvm_core::security::HostCapabilities::discover(&self.cfg)
    }

    pub async fn release_test_secret(
        &self,
        id: Uuid,
    ) -> Result<fluxvm_core::security::SecretRelease> {
        let vm = self.get(id).await?;
        let policy = vm
            .request
            .measurement_policy
            .as_ref()
            .context("VM has no measurement_policy")?;
        let evidence = match &vm.security_evidence {
            Some(ev) => ev.clone(),
            None => fluxvm_core::security::read_evidence(&vm.workspace)
                .context("no security evidence on record or disk")?,
        };
        Ok(fluxvm_core::security::release_test_secret(
            &evidence, policy,
        ))
    }

    pub async fn enforce_token_quotas(
        &self,
        actor: Option<&str>,
        req: &CreateVmRequest,
    ) -> Result<()> {
        let Some(actor) = actor else {
            return Ok(());
        };
        if actor == "anonymous-admin" || actor == "none" {
            return Ok(());
        }
        let ledger = self.store.quota_ledger().await?;
        if let Err(e) = fluxvm_core::policy::enforce_token_totals(
            actor,
            req.vcpus,
            req.memory_mib,
            self.cfg.auth.max_vms_per_token,
            self.cfg.auth.max_memory_mib_per_token,
            &ledger,
        ) {
            let reason = e.to_string();
            audit_event("quota.deny", &[("token", actor), ("reason", &reason)]);
            return Err(e);
        }
        Ok(())
    }

    pub async fn get(&self, id: Uuid) -> Result<VmRecord> {
        self.store
            .get(id)
            .await
            .context("VM not found")
            .map(Self::with_guest_ip)
    }

    /// Resolves `guest_ip` fresh from the DHCP lease file on every read
    /// rather than trusting a stored value, since leases renew and this is
    /// cheap (one small file read, only for netns-networked VMs). Not
    /// persisted back to the store -- the store keeps `dhcp_leasefile`
    /// (stable) and leaves `guest_ip` for the caller to fill in, same as
    /// this method does for every API response.
    fn with_guest_ip(mut record: VmRecord) -> VmRecord {
        let mac = match &record.request.network {
            NetworkSpec::Tap { mac: Some(m), .. } => m.as_str(),
            _ => return record,
        };
        let Some(leasefile) = &record.dhcp_leasefile else {
            return record;
        };
        // The address is reserved (dnsmasq --dhcp-host) the moment the
        // namespace is created -- record.guest_ip is already set to it at
        // create/start time. A lease-file hit here just confirms the guest
        // actually completed a DHCP handshake for it; a miss does *not*
        // mean "not known", it means either the guest hasn't DHCP'd yet or
        // (CloudInitSpec.static_network) never will, since the address was
        // configured directly and no DHCP exchange happens at all. Either
        // way, keep the already-known reservation rather than clearing it.
        if let Some(ip) = fluxvm_network::netns::guest_ip_from_lease(leasefile, mac) {
            record.guest_ip = Some(ip);
        }
        record
    }

    /// Relaunch a `Stopped` VM from its existing disk/seed — unlike
    /// `create`, this skips image cloning, guest-agent token injection, and
    /// cloud-init seed generation, since all of that already happened the
    /// first time this record was created and is still sitting on disk.
    /// Only network device prep is redone (the tap/macvtap was torn down on
    /// stop). Added for consumers keyed by a name/register-then-start model
    /// (zyvor-fabric's `driver-core::VMDriver::start`) that need to resume a
    /// VM without repeating create-time work.
    pub async fn start(self: &Arc<Self>, id: Uuid) -> Result<VmRecord> {
        self.start_impl(id, None).await
    }

    /// Same as [`Self::start`], but restores from a prior [`Self::create_vm_snapshot`]
    /// tag. QEMU/CH use `loadvm_tag` / `--restore`; Firecracker and FluxVm use
    /// dedicated snapshot-load paths (they ignore `loadvm_tag` on cold launch).
    pub async fn start_from_snapshot(self: &Arc<Self>, id: Uuid, tag: &str) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::SnapshotRestore,
        )?;
        if let Some(e) = snapshot_backend_error(vm.backend) {
            bail!(e);
        }
        match vm.backend {
            BackendKind::Firecracker => self.start_firecracker_from_snapshot(id, tag).await,
            BackendKind::FluxVm => self.start_fluxvm_from_snapshot(id, tag).await,
            _ => self.start_impl(id, Some(tag)).await,
        }
    }

    async fn start_firecracker_from_snapshot(
        self: &Arc<Self>,
        id: Uuid,
        tag: &str,
    ) -> Result<VmRecord> {
        let started = std::time::Instant::now();
        let mut vm = self.get(id).await?;
        if vm.status == VmStatus::Running {
            return Ok(vm);
        }
        let dest = vm.workspace.join("snapshots").join(tag);
        fluxvm_firecracker::snapshot::assert_snapshot_dir(&dest)?;

        let network = fluxvm_network::prepare(&self.cfg, id, &vm.request.network).await?;
        vm.tap_name = network.tap_name.clone();
        vm.netns = network.netns.clone();
        vm.dhcp_leasefile = network.dhcp_leasefile.clone();
        vm.guest_ip = network.guest_ip.clone();

        let log_path = vm.workspace.join("vm.log");
        let vsock = vm.vsock_socket.clone();
        let result = fluxvm_firecracker::snapshot::snapshot_restore(
            &self.cfg,
            &vm.workspace,
            &dest,
            &log_path,
            vsock.as_deref(),
            network.netns.as_deref(),
        )
        .await;

        match result {
            Ok((pid, api)) => {
                vm.pid = Some(pid);
                vm.control_socket = Some(api);
                let vfio = vm.request.vfio_devices.clone();
                self.attach_cgroup(id, pid, &mut vm, &vfio);
                vm.status = VmStatus::Running;
                vm.error = None;
                self.store.update(vm.clone()).await?;
                metrics::record_vm_start(started.elapsed().as_millis() as u64);
                Ok(vm)
            }
            Err(e) => {
                if let Some(tap) = &vm.tap_name {
                    let _ = fluxvm_network::cleanup(
                        &self.cfg.state_dir,
                        id,
                        &vm.request.network,
                        tap,
                        vm.netns.as_deref(),
                    )
                    .await;
                }
                vm.status = VmStatus::Failed;
                vm.error = Some(format!("{e:#}"));
                self.store.update(vm.clone()).await?;
                Err(e)
            }
        }
    }

    async fn start_fluxvm_from_snapshot(self: &Arc<Self>, id: Uuid, tag: &str) -> Result<VmRecord> {
        let started = std::time::Instant::now();
        let mut vm = self.get(id).await?;
        if vm.status == VmStatus::Running {
            return Ok(vm);
        }
        let dest = vm.workspace.join("snapshots").join(tag);
        let meta = dest.join("snap");
        if !meta.exists() {
            bail!(
                "FluxVm snapshot metadata missing at {} (create with POST .../snapshot first)",
                meta.display()
            );
        }

        let network = fluxvm_network::prepare(&self.cfg, id, &vm.request.network).await?;
        vm.tap_name = network.tap_name.clone();
        vm.netns = network.netns.clone();
        vm.dhcp_leasefile = network.dhcp_leasefile.clone();
        vm.guest_ip = network.guest_ip.clone();

        let api = vm.workspace.join("fluxvm.sock");
        let _ = tokio::fs::remove_file(&api).await;
        let log_path = vm.workspace.join("vm.log");
        let args = vec!["--api-sock".into(), api.display().to_string()];
        let (program, args) = fluxvm_core::process::netns_wrap(
            network.netns.as_deref(),
            &self.cfg.fluxvm_hypervisor_binary,
            &args,
        );
        let child = fluxvm_core::process::spawn_logged_with_env(
            &program,
            &args,
            &log_path,
            &[
                (
                    "FLUXVM_FIRECRACKER_BINARY",
                    self.cfg.firecracker_binary.as_str(),
                ),
                (
                    "FLUXVM_ENGINE",
                    match self.cfg.fluxvm_engine {
                        fluxvm_core::config::FluxVmEngine::Firecracker => "firecracker",
                        fluxvm_core::config::FluxVmEngine::Kvm => "kvm",
                    },
                ),
            ],
        )
        .await?;
        let pid = child
            .id()
            .context("fluxvm-hypervisor exited before PID was available")?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if tokio::time::Instant::now() > deadline {
                bail!("fluxvm-hypervisor API not ready for snapshot restore");
            }
            match fluxvm_hypervisor::control::request(&api, &fluxvm_hypervisor::ApiRequest::Ping)
                .await
            {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }

        let req = fluxvm_hypervisor::ApiRequest::SnapshotRestore { path: meta };
        let resp = fluxvm_hypervisor::control::request(&api, &req).await?;
        match resp {
            fluxvm_hypervisor::ApiResponse::Ok { .. } => {}
            fluxvm_hypervisor::ApiResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected restore response: {other:?}"),
        }

        vm.pid = Some(pid);
        vm.control_socket = Some(api);
        let vfio = vm.request.vfio_devices.clone();
        self.attach_cgroup(id, pid, &mut vm, &vfio);
        vm.status = VmStatus::Running;
        vm.error = None;
        self.store.update(vm.clone()).await?;
        metrics::record_vm_start(started.elapsed().as_millis() as u64);
        Ok(vm)
    }

    // ZYVOR_RUNTIME_BOUNDARY_V1: FluxVM performs the VMM transport; Fabric chooses hosts/policy.
    pub async fn start_migration(
        &self,
        id: Uuid,
        request: &fluxvm_core::model::MigrationStartRequest,
    ) -> Result<fluxvm_core::model::MigrationStatus> {
        let vm = self.get(id).await?;
        if vm.status != VmStatus::Running {
            bail!(
                "live migration requires a running VM (status={:?})",
                vm.status
            );
        }
        if vm.request.network.is_direct() {
            bail!("live migration of a direct-datapath VM is refused until a two-host test exists");
        }
        if let Some(tls) = &request.tls {
            validate_migration_tls_spec(tls, &self.cfg)?;
        }
        let vm_id = id.to_string();
        audit_event(
            "migration.start",
            &[("vm_id", &vm_id), ("destination", &request.destination)],
        );
        let quiesced = fluxvm_network::ebpf::attachment_status(&self.cfg.sandbox.dataplane, id)
            .map(|status| status.attached)
            .unwrap_or(false);
        if quiesced {
            if let Err(e) = fluxvm_network::migration_state::quiesce(&self.cfg, id) {
                if let Err(resume) = fluxvm_network::migration_state::resume(&self.cfg, id) {
                    tracing::warn!(vm = %id, error = %resume, "resuming dataplane after quiesce failed");
                }
                return Err(e);
            }
        }
        // A netns VM's QEMU cannot reach host-namespace addresses; hand it a
        // workspace socket that FluxVM relays to the TCP destination.
        let mut request = request.clone();
        if vm.backend == BackendKind::Qemu
            && vm.netns.is_some()
            && let Some(dest) = migration_relay::tcp_target(&request.destination)
        {
            let sock = vm.workspace.join(live_migration::OUTGOING_SOCKET);
            let ws = vm.workspace.clone();
            migration_relay::spawn_unix_to_tcp(
                sock.clone(),
                dest.to_string(),
                std::time::Duration::from_secs(3600),
                move || ws.exists(),
            )
            .context("starting the migration relay")?;
            request.destination = migration_relay::unix_uri(&sock);
        }
        let request = &request;
        let started = match vm.backend {
            BackendKind::Qemu => fluxvm_qemu::migration_start(&self.cfg, &vm, request).await,
            BackendKind::CloudHypervisor => {
                fluxvm_cloud_hypervisor::migration_start(&self.cfg, &vm, request).await
            }
            other => Err(anyhow::anyhow!(
                "live migration contract v1 supports qemu only (backend={other:?})"
            )),
        };
        // QEMU can return Ok(Failed); keep the dataplane quiesced only while
        // migration is still in flight (Active/Setup/…).
        let should_resume = match &started {
            Err(_) => true,
            Ok(status) => matches!(
                status.phase,
                MigrationPhase::Failed | MigrationPhase::Cancelled
            ),
        };
        if quiesced && should_resume {
            if let Err(e) = fluxvm_network::migration_state::resume(&self.cfg, id) {
                tracing::warn!(vm = %id, error = %e, "resuming dataplane after migration start failed");
            }
        }
        started
    }

    pub async fn migration_status(&self, id: Uuid) -> Result<fluxvm_core::model::MigrationStatus> {
        let vm = self.get(id).await?;
        let status = match vm.backend {
            BackendKind::Qemu => fluxvm_qemu::migration_status(&self.cfg, &vm).await?,
            BackendKind::CloudHypervisor => bail!(
                "Cloud Hypervisor's migration API has no status-polling primitive (send-migration \
                 is fire-and-forget) -- check whether this VM is still Running on this node instead"
            ),
            other => bail!("migration status contract v1 supports qemu only (backend={other:?})"),
        };
        if matches!(
            status.phase,
            MigrationPhase::Failed | MigrationPhase::Cancelled
        ) {
            if let Err(e) = fluxvm_network::migration_state::resume(&self.cfg, id) {
                tracing::warn!(vm = %id, error = %e, "resuming dataplane after terminal migration status");
            }
        }
        Ok(status)
    }

    pub async fn cancel_migration(&self, id: Uuid) -> Result<fluxvm_core::model::MigrationStatus> {
        let vm = self.get(id).await?;
        let status = match vm.backend {
            BackendKind::Qemu => fluxvm_qemu::migration_cancel(&self.cfg, &vm).await?,
            BackendKind::CloudHypervisor => bail!(
                "Cloud Hypervisor's migration API has no cancellation primitive once a migration \
                 has been requested"
            ),
            other => bail!("migration cancel contract v1 supports qemu only (backend={other:?})"),
        };
        if let Err(e) = fluxvm_network::migration_state::resume(&self.cfg, id) {
            tracing::warn!(vm = %id, error = %e, "resuming dataplane after migration cancel");
        }
        let vm_id = id.to_string();
        audit_event("migration.cancel", &[("vm_id", &vm_id)]);
        Ok(status)
    }

    fn receiver_dir(&self) -> std::path::PathBuf {
        self.cfg.state_dir.join("migration-receivers")
    }

    fn read_receiver(&self, id: Uuid) -> Result<fluxvm_core::model::MigrationReceiver> {
        let path = self.receiver_dir().join(format!("{id}.json"));
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("migration receiver {id} not found"))?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn write_receiver(&self, rec: &fluxvm_core::model::MigrationReceiver) -> Result<()> {
        let dir = self.receiver_dir();
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", rec.id));
        fs::write(&path, serde_json::to_vec_pretty(rec)?)?;
        Ok(())
    }

    /// Incoming QEMU only. Cloud Hypervisor, Firecracker, and the in-tree
    /// hypervisor stay unsupported. The receiver does not choose a node.
    pub async fn create_migration_receiver(
        &self,
        mut req: fluxvm_core::model::MigrationReceiverRequest,
    ) -> Result<fluxvm_core::model::MigrationReceiver> {
        if let Some(source) = req.record.take() {
            return self.launch_adopt_receiver(req, *source).await;
        }
        if req.vcpus == 0 || req.memory_mib == 0 {
            bail!("migration receiver needs vcpus and memory_mib (or a source record)");
        }
        let cpu = if req.cpu_model.is_empty() {
            "host"
        } else {
            req.cpu_model.as_str()
        };
        let machine = if req.machine.is_empty() {
            "q35"
        } else {
            req.machine.as_str()
        };
        fluxvm_qemu::receiver::validate_receiver(cpu, machine, &req.disk)?;
        validate_migration_receiver_request(&req, &self.cfg)?;
        let vcpus = req.vcpus;
        let memory_mib = req.memory_mib;
        if let Err(e) = self
            .store
            .reserve_untracked_host(vcpus, memory_mib, &self.cfg.policy)
            .await
        {
            let reason = e.to_string();
            audit_event("quota.deny", &[("scope", "host"), ("reason", &reason)]);
            return Err(e);
        }
        match self.launch_reserved_receiver(req).await {
            Ok(rec) => Ok(rec),
            Err(e) => {
                if let Err(release) = self.store.release_untracked_host(vcpus, memory_mib).await {
                    tracing::warn!(
                        error = %release,
                        "releasing migration receiver host reservation"
                    );
                }
                Err(e)
            }
        }
    }

    async fn launch_reserved_receiver(
        &self,
        req: fluxvm_core::model::MigrationReceiverRequest,
    ) -> Result<fluxvm_core::model::MigrationReceiver> {
        let id = Uuid::new_v4();
        let workspace = self.receiver_dir().join(id.to_string());
        let launched = fluxvm_qemu::receiver::launch(
            &self.cfg,
            &workspace,
            &req.disk,
            &req.disk_format,
            req.vcpus,
            req.memory_mib,
            &req.listen_host,
            &req.advertise_host,
            req.listen_port,
        )
        .await?;
        let cgroup_path =
            match fluxvm_cgroup::CgroupManager::create_and_migrate(&id.to_string(), launched.pid) {
                Ok(mgr) => Some(mgr.path().to_path_buf()),
                Err(e) => {
                    if let Err(stop) = process::terminate_pid(launched.pid).await {
                        tracing::warn!(
                            receiver = %id,
                            error = %stop,
                            "stopping receiver after cgroup reservation failed"
                        );
                    }
                    let _ = fs::remove_dir_all(&workspace);
                    bail!("migration receiver cgroup reservation failed: {e}");
                }
            };
        let ttl = req.expires_in_seconds.unwrap_or(600);
        let rec = fluxvm_core::model::MigrationReceiver {
            id,
            uri: launched.uri,
            listen_uri: launched.listen_uri,
            token: Uuid::new_v4().to_string(),
            expires_at_unix: (Utc::now() + Duration::seconds(ttl as i64)).timestamp() as u64,
            pid: launched.pid,
            qmp_socket: launched.qmp_socket,
            workspace,
            disk: req.disk,
            cgroup_path,
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            tls: req.tls,
            source_id: None,
        };
        if let Err(e) = self.write_receiver(&rec) {
            if let Err(stop) = process::terminate_pid(launched.pid).await {
                tracing::warn!(receiver = %id, error = %stop, "stopping receiver after persisting it failed");
            }
            if let Some(path) = &rec.cgroup_path
                && let Ok(mgr) = fluxvm_cgroup::CgroupManager::from_path(path.clone())
                && let Err(remove) = mgr.remove()
            {
                tracing::warn!(receiver = %id, error = %remove, "removing receiver cgroup after persist failed");
            }
            let _ = fs::remove_dir_all(&rec.workspace);
            return Err(e);
        }
        let vm_id = rec.id.to_string();
        audit_event(
            "migration.receiver",
            &[("receiver_id", &vm_id), ("uri", &rec.uri)],
        );
        Ok(rec)
    }

    pub async fn activate_migration_receiver(
        &self,
        id: Uuid,
        token: &str,
    ) -> Result<fluxvm_core::model::MigrationReceiver> {
        let rec = self.read_receiver(id)?;
        if rec.token != token {
            bail!("migration receiver token does not match");
        }
        if rec.expires_at_unix < Utc::now().timestamp() as u64 {
            bail!("migration receiver {id} has expired");
        }
        let incoming = if rec.listen_uri.is_empty() {
            rec.uri.as_str()
        } else {
            rec.listen_uri.as_str()
        };
        fluxvm_qemu::receiver::activate(&rec.qmp_socket, incoming, rec.tls.as_ref()).await?;
        Ok(rec)
    }

    pub async fn delete_migration_receiver(&self, id: Uuid) -> Result<()> {
        let path = self.receiver_dir().join(format!("{id}.json"));
        if let Ok(rec) = self.read_receiver(id) {
            if let Err(e) = process::terminate_pid(rec.pid).await {
                tracing::warn!(receiver = %id, error = %e, "stopping migration receiver");
            }
            if rec.source_id.is_some()
                && let Some(vm) = self.store.get(id).await
            {
                self.discard_receiver_record(&vm).await;
            }
            if let Some(path) = rec.cgroup_path {
                if let Ok(mgr) = fluxvm_cgroup::CgroupManager::from_path(path) {
                    if let Err(e) = mgr.remove() {
                        tracing::warn!(receiver = %id, error = %e, "removing migration receiver cgroup");
                    }
                }
            }
            if let Err(e) = self
                .store
                .release_untracked_host(rec.vcpus, rec.memory_mib)
                .await
            {
                tracing::warn!(receiver = %id, error = %e, "releasing migration receiver host reservation");
            }
        }
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let workspace = self.receiver_dir().join(id.to_string());
        if workspace.exists() {
            let _ = fs::remove_dir_all(&workspace);
        }
        Ok(())
    }

    pub async fn reap_migration_receivers(&self) {
        let dir = self.receiver_dir();
        let Ok(entries) = fs::read_dir(&dir) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(rec) = serde_json::from_str::<fluxvm_core::model::MigrationReceiver>(&raw)
            else {
                continue;
            };
            if rec.expires_at_unix < now {
                let _ = self.delete_migration_receiver(rec.id).await;
            }
        }
    }

    /// Set host reservations from the receiver files still on disk. Called
    /// after the startup reap, before the API accepts requests.
    pub async fn sync_receiver_host_quota(&self) -> Result<()> {
        let dir = self.receiver_dir();
        let mut vcpus = 0u64;
        let mut memory_mib = 0u64;
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let Ok(raw) = fs::read_to_string(&path) else {
                    continue;
                };
                let Ok(rec) = serde_json::from_str::<fluxvm_core::model::MigrationReceiver>(&raw)
                else {
                    continue;
                };
                vcpus = vcpus.saturating_add(u64::from(rec.vcpus));
                memory_mib = memory_mib.saturating_add(rec.memory_mib);
            }
        }
        self.store.set_untracked_host(vcpus, memory_mib).await
    }

    /// Save full VM state so a later [`Self::start_from_snapshot`] can restore it.
    /// QEMU uses an internal `savevm` tag on the VM disk; Cloud Hypervisor /
    /// Firecracker write under `<workspace>/snapshots/<tag>/`; FluxVm uses the
    /// hypervisor control SnapshotSave path (same layout as sandbox snaps).
    pub async fn create_vm_snapshot(self: &Arc<Self>, id: Uuid, tag: &str) -> Result<()> {
        validate_snapshot_tag(tag)?;
        self.create_vm_snapshot_inner(id, tag).await?;
        audit_event("vm.snapshot", &[("vm_id", &id.to_string()), ("tag", tag)]);
        Ok(())
    }

    async fn create_vm_snapshot_inner(self: &Arc<Self>, id: Uuid, tag: &str) -> Result<()> {
        let vm = self.get(id).await?;
        fluxvm_core::security::check_operation(
            vm.requested_security_profile,
            fluxvm_core::security::VmOperation::SnapshotSave,
        )?;
        if vm.status != VmStatus::Running && vm.status != VmStatus::Paused {
            bail!(
                "snapshot requires a running or paused VM (status={:?})",
                vm.status
            );
        }
        if let Some(e) = snapshot_backend_error(vm.backend) {
            bail!(e);
        }
        match vm.backend {
            BackendKind::Qemu => fluxvm_qemu::snapshot_save(&self.cfg, &vm, tag).await,
            BackendKind::CloudHypervisor => {
                let dest = vm.workspace.join("snapshots").join(tag);
                tokio::fs::create_dir_all(&dest).await?;
                fluxvm_cloud_hypervisor::snapshot_save(&self.cfg, &vm, &dest).await
            }
            BackendKind::Firecracker => {
                let dest = vm.workspace.join("snapshots").join(tag);
                tokio::fs::create_dir_all(&dest).await?;
                fluxvm_firecracker::snapshot::snapshot_save(&self.cfg, &vm, &dest).await
            }
            BackendKind::FluxVm => {
                let dest = vm.workspace.join("snapshots").join(tag);
                tokio::fs::create_dir_all(&dest).await?;
                // Metadata JSON path; hypervisor writes sibling .mem/.vmstate/.rootfs.
                let meta = dest.join("snap");
                let sock = vm
                    .control_socket
                    .as_ref()
                    .context("FluxVm VM has no control socket")?;
                let req = fluxvm_hypervisor::ApiRequest::SnapshotSave { path: meta };
                let resp = fluxvm_hypervisor::control::request(sock, &req).await?;
                match resp {
                    fluxvm_hypervisor::ApiResponse::Ok { .. } => Ok(()),
                    fluxvm_hypervisor::ApiResponse::Error { message } => bail!("{message}"),
                    other => bail!("unexpected snapshot response: {other:?}"),
                }
            }
            _ => unreachable!("snapshot_backend_error already rejected every other backend"),
        }
    }

    async fn start_impl(self: &Arc<Self>, id: Uuid, loadvm_tag: Option<&str>) -> Result<VmRecord> {
        let started = std::time::Instant::now();
        let mut vm = self.get(id).await?;
        if vm.status == VmStatus::Running {
            return Ok(vm);
        }
        // A CephRbd disk is a `rbd:pool/image:...` URI, not a real
        // filesystem path — there's nothing on the local filesystem to
        // check `exists()` against. LvmThin (a block device) and Nbd (the
        // local qcow2 file the export serves) both really do live on disk.
        if !vm.request.storage.is_ceph_rbd() && !vm.disk.exists() {
            bail!(
                "cannot start {id}: disk no longer exists at {}",
                vm.disk.display()
            );
        }

        let result: Result<()> = async {
            if vm.request.storage == StorageBackend::Shared {
                self.claim_shared_disk(&vm.disk, id, &[]).await?;
            }
            let network = fluxvm_network::prepare(&self.cfg, id, &vm.request.network).await?;
            let dataplane_if = fluxvm_network::dataplane_interface(id, &network);
            let network_spec_for_dataplane = network.spec.clone();
            vm.tap_name = network.tap_name.clone();
            vm.netns = network.netns.clone();
            vm.dhcp_leasefile = network.dhcp_leasefile.clone();
            vm.guest_ip = network.guest_ip.clone();

            let guest_cidr_for_policy = network
                .guest_cidr
                .clone()
                .or_else(|| vm.guest_ip.as_ref().map(|ip| format!("{ip}/32")));

            let vsock_socket = match (vm.guest_cid, vm.backend) {
                (Some(_), BackendKind::Qemu) => None,
                (Some(_), _) => Some(vm.workspace.join("vsock.sock")),
                (None, _) => None,
            };
            // `StorageBackend::Nbd`'s qemu-nbd export is left running across
            // stop/start (see `VmRecord::nbd_pid`), so its socket is already
            // there to reattach to — nothing to reprovision.
            let nbd_export =
                (vm.request.storage == StorageBackend::Nbd).then(|| vm.workspace.join("nbd.sock"));

            // Same as create: attach for QEMU/CH/FC as well as flux-vm.
            {
                let allow_cidrs = if self.cfg.sandbox.egress_allow_domains.is_empty() {
                    vec![]
                } else {
                    fluxvm_network::egress::resolve_allow_cidrs(
                        &self.cfg.sandbox.egress_allow_domains,
                    )
                    .await
                };
                if let Err(e) = fluxvm_network::dataplane::apply_sandbox_policy(
                    &self.cfg,
                    id,
                    dataplane_if.as_deref(),
                    guest_cidr_for_policy.as_deref(),
                    &allow_cidrs,
                    vm.request.pod_uid.as_deref(),
                ) {
                    if is_direct(&network_spec_for_dataplane)
                        || self.cfg.sandbox.dataplane.required
                        || self.cfg.sandbox.dataplane.mode
                            != fluxvm_core::config::DataplaneMode::Legacy
                    {
                        return Err(e).context("applying VM dataplane before restart");
                    }
                    tracing::warn!(vm = %id, error = %e, "VM dataplane re-apply failed");
                }
            }

            let ctx = LaunchContext {
                id,
                workspace: vm.workspace.clone(),
                disk: vm.disk.clone(),
                seed_disk: vm.seed_disk.clone(),
                log_path: vm.log_path.clone(),
                network,
                guest_cid: vm.guest_cid,
                vsock_socket,
                disk_format: fluxvm_image::storage::disk_format(vm.backend, vm.request.storage),
                nbd_export,
            };
            // Cloned, not mutated in place: `vm.request` is the VM's
            // original creation-time request and gets persisted below via
            // `self.store.update` -- a loadvm_tag baked in there would
            // stick around and get replayed on every later plain `start`
            // too, long after the snapshot it names is stale.
            let mut launch_req = vm.request.clone();
            launch_req.loadvm_tag = loadvm_tag.map(String::from);
            let launch = backend(vm.backend)?
                .launch(&self.cfg, &launch_req, &ctx)
                .await?;
            vm.pid = Some(launch.pid);
            vm.control_socket = launch.control_socket;
            vm.jail_path = launch.jail_path;
            vm.vsock_socket = launch.vsock_socket;
            vm.virtiofsd_pids = launch.virtiofsd_pids;
            vm.swtpm_pid = launch.swtpm_pid;
            if vm.request.qga.as_ref().is_some_and(|q| q.enabled) {
                vm.qga_socket = Some(vm.workspace.join("qga.sock"));
            }
            let vfio_devices = vm.request.vfio_devices.clone();
            self.attach_cgroup(id, launch.pid, &mut vm, &vfio_devices);
            vm.status = VmStatus::Running;
            vm.error = None;
            live_migration::clear_hotplug_labels(&mut vm.labels);
            if let Some(ref ns) = vm.netns {
                if let Err(e) = fluxvm_network::netns::repair_named_netns(ns, launch.pid).await {
                    tracing::warn!(
                        vm = %id,
                        netns = %ns,
                        error = %e,
                        "named netns handle repair failed; qemu ns is still live"
                    );
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
            if let Some(tap) = &vm.tap_name {
                let _ = fluxvm_network::cleanup(
                    &self.cfg.state_dir,
                    id,
                    &vm.request.network,
                    tap,
                    vm.netns.as_deref(),
                )
                .await;
            }
            if vm.request.storage == StorageBackend::Shared {
                self.release_shared_disk(&vm.disk, id);
            }
            vm.status = VmStatus::Failed;
            vm.error = Some(format!("{e:#}"));
            self.store.update(vm.clone()).await?;
            return Err(e);
        }
        self.store.update(vm.clone()).await?;
        metrics::record_vm_start(started.elapsed().as_millis() as u64);
        let vm_id = id.to_string();
        audit_event(
            "vm.start",
            &[("vm_id", &vm_id), ("snapshot", loadvm_tag.unwrap_or(""))],
        );
        Ok(vm)
    }

    pub async fn stop(&self, id: Uuid) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        if let Some(pid) = vm.pid {
            if process::process_alive(pid).await {
                // Ask the VMM to shut the guest down cleanly first; only
                // force-kill if it doesn't exit within the grace period (or
                // the VMM's control channel didn't respond at all).
                let asked_nicely = match backend(vm.backend) {
                    Ok(b) => b.graceful_shutdown(&self.cfg, &vm).await.is_ok(),
                    Err(_) => false,
                };
                let exited = asked_nicely
                    && process::wait_for_exit(
                        pid,
                        (GRACEFUL_SHUTDOWN_WAIT.as_millis() / 100) as u32,
                    )
                    .await;
                if !exited && process::process_alive(pid).await {
                    process::terminate_pid(pid).await?;
                }
            }
        }
        let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
        if let Some(tap) = &vm.tap_name {
            let _ = fluxvm_network::cleanup(
                &self.cfg.state_dir,
                id,
                &vm.request.network,
                tap,
                vm.netns.as_deref(),
            )
            .await;
        }
        vm.netns = None;
        // virtiofsd instances aren't reattachable the way qemu-nbd's export
        // is (see the Nbd comment in `start`) — a fresh set gets spawned on
        // the next `start`, so tear these down unconditionally here.
        for pid in vm.virtiofsd_pids.drain(..) {
            if process::process_alive(pid).await {
                let _ = process::terminate_pid(pid).await;
            }
        }
        // swtpm isn't reattachable either, same reasoning as virtiofsd
        // above -- a fresh instance gets spawned on the next `start`. Its
        // *state* (workspace/tpm/) is untouched here, only the process.
        if let Some(pid) = vm.swtpm_pid.take() {
            if process::process_alive(pid).await {
                let _ = process::terminate_pid(pid).await;
            }
        }
        // cgroup v2 requires a cgroup to be empty (no PIDs left in
        // cgroup.procs) before rmdir succeeds — safe here since the process
        // is confirmed dead by this point either way (graceful exit,
        // terminate_pid, or it just never had one to begin with).
        if let Some(cgroup_path) = vm.cgroup_path.take() {
            let _ =
                fluxvm_network::qemu_cgroup::detach(&self.cfg.sandbox.dataplane, id, &cgroup_path);
            if let Ok(mgr) = fluxvm_cgroup::CgroupManager::from_path(cgroup_path) {
                if let Err(e) = mgr.remove() {
                    tracing::warn!(vm = %id, error = %e, "failed to remove VM cgroup");
                }
            }
        }
        if vm.request.storage == StorageBackend::Shared {
            self.release_shared_disk(&vm.disk, id);
        }
        vm.status = VmStatus::Stopped;
        vm.pid = None;
        self.store.update(vm.clone()).await?;
        audit_event("vm.stop", &[("vm_id", &id.to_string())]);
        Ok(vm)
    }

    pub async fn pause(&self, id: Uuid) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        procbox_sandbox::require_guest(&vm, "pausing")?;
        backend(vm.backend)?.pause(&self.cfg, &vm).await?;
        vm.status = VmStatus::Paused;
        self.store.update(vm.clone()).await?;
        audit_event("vm.pause", &[("vm_id", &id.to_string())]);
        Ok(vm)
    }

    pub async fn resume(&self, id: Uuid) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        procbox_sandbox::require_guest(&vm, "resuming")?;
        backend(vm.backend)?.resume(&self.cfg, &vm).await?;
        vm.status = VmStatus::Running;
        self.store.update(vm.clone()).await?;
        audit_event("vm.resume", &[("vm_id", &id.to_string())]);
        Ok(vm)
    }

    /// Stop (graceful, then forced) and start again as one operation.
    pub async fn restart(self: &Arc<Self>, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if matches!(vm.status, VmStatus::Running | VmStatus::Paused) {
            self.stop(id).await.context("restart: stop")?;
        }
        let vm = self.start(id).await.context("restart: start")?;
        audit_event("vm.restart", &[("vm_id", &id.to_string())]);
        Ok(vm)
    }

    /// Rename and/or edit labels (`PATCH /v1/vms/{id}`).
    pub async fn patch(&self, id: Uuid, patch: fluxvm_core::model::VmPatch) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        let mut changed = Vec::new();
        if let Some(name) = patch.name {
            validate_vm_name(&name)?;
            if name != vm.name {
                changed.push(format!("name:{}->{}", vm.name, name));
                vm.name = name.clone();
                vm.request.name = name;
            }
        }
        for (k, v) in patch.labels {
            validate_label_key(&k)?;
            match v {
                Some(v) => {
                    if v.len() > 253 {
                        bail!("label {k:?} value longer than 253 chars");
                    }
                    changed.push(format!("{k}={v}"));
                    vm.labels.insert(k, v);
                }
                None => {
                    if vm.labels.remove(&k).is_some() {
                        changed.push(format!("{k}-"));
                    }
                }
            }
        }
        if !changed.is_empty() {
            self.store.update(vm.clone()).await?;
            audit_event(
                "vm.patch",
                &[("vm_id", &id.to_string()), ("changes", &changed.join(","))],
            );
        }
        Ok(vm)
    }

    /// Snapshots taken by [`Self::create_vm_snapshot`]: qcow2-internal for
    /// QEMU, `workspace/snapshots/<tag>` for every other backend.
    pub async fn list_vm_snapshots(
        &self,
        id: Uuid,
    ) -> Result<Vec<fluxvm_core::model::VmSnapshotInfo>> {
        let vm = self.get(id).await?;
        if vm.backend == BackendKind::Qemu {
            return fluxvm_qemu::snapshot_list(&self.cfg, &vm).await;
        }
        let dir = vm.workspace.join("snapshots");
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&dir) else {
            return Ok(out);
        };
        for e in entries.flatten() {
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_dir() {
                continue;
            }
            out.push(fluxvm_core::model::VmSnapshotInfo {
                tag: e.file_name().to_string_lossy().into_owned(),
                created_at: meta.modified().ok().map(chrono::DateTime::<Utc>::from),
                size_bytes: dir_size(&e.path()),
            });
        }
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    pub async fn delete_vm_snapshot(&self, id: Uuid, tag: &str) -> Result<()> {
        validate_snapshot_tag(tag)?;
        let vm = self.get(id).await?;
        if vm.backend == BackendKind::Qemu {
            fluxvm_qemu::snapshot_delete(&self.cfg, &vm, tag).await?;
        } else {
            let path = vm.workspace.join("snapshots").join(tag);
            if !path.is_dir() {
                bail!("snapshot {tag:?} not found for VM {id}");
            }
            tokio::fs::remove_dir_all(&path)
                .await
                .with_context(|| format!("removing {}", path.display()))?;
        }
        audit_event(
            "vm.snapshot.delete",
            &[("vm_id", &id.to_string()), ("tag", tag)],
        );
        Ok(())
    }

    /// Flatten a VM's root disk into a standalone qcow2 at `dest`
    /// (default `state_dir/backups/<name>-<utc>.qcow2`), or with `all_disks`
    /// the root and every data disk into a directory. A stopped VM on any
    /// engine is read straight off its disk files; a running QEMU VM is
    /// captured through one short-lived internal snapshot (savevm covers all
    /// its qcow2 disks), so the copies are crash-consistent with each other;
    /// with the guest agent answering, filesystems are frozen around that
    /// snapshot (see [`fluxvm_core::model::BackupQuiesce`]). A metadata
    /// sidecar (`<file>.json` or `<dir>/backup.json`) records the source VM.
    pub async fn backup_vm(
        self: &Arc<Self>,
        id: Uuid,
        opts: fluxvm_core::model::BackupOptions,
    ) -> Result<serde_json::Value> {
        let fluxvm_core::model::BackupOptions {
            dest,
            name,
            compress,
            all_disks,
            quiesce,
        } = opts;
        let dest = match (dest, name) {
            (Some(d), _) => Some(d),
            (None, Some(n)) => {
                let n = n.strip_suffix(".qcow2").unwrap_or(&n);
                backup::validate_backup_name(n)?;
                let base = self.backups_dir().join(n);
                Some(if all_disks {
                    base
                } else {
                    base.with_extension("qcow2")
                })
            }
            (None, None) => None,
        };
        let vm = self.get(id).await?;
        if let Some(why) = backup::backup_refusal(
            vm.backend,
            vm.request.storage,
            vm.disk.is_file(),
            vm.status,
            false,
        ) {
            bail!(why);
        }
        let root_format = backup::root_disk_format(&vm);
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        // Linked images and block devices belong to someone else, the same
        // reason restore skips them.
        let data = if all_disks {
            fluxvm_qemu::disks::data_disks(&vm.workspace)
                .into_iter()
                .filter(|(_, p)| !fluxvm_qemu::disks::is_external(p))
                .collect()
        } else {
            vec![]
        };
        let default_base = self
            .cfg
            .state_dir
            .join("backups")
            .join(format!("{}-{stamp}", vm.request.name));
        // One file for the root disk alone; a directory of
        // `root.qcow2` + `<disk>.qcow2` with `all_disks`.
        let (dest, targets) = if all_disks {
            let dir = dest.unwrap_or(default_base);
            let mut t = vec![(
                fluxvm_qemu::disks::ROOT_DISK.to_string(),
                vm.disk.clone(),
                dir.join("root.qcow2"),
            )];
            t.extend(
                data.into_iter()
                    .map(|(n, p)| (n.clone(), p, dir.join(format!("{n}.qcow2")))),
            );
            (dir, t)
        } else {
            let file = dest.unwrap_or_else(|| default_base.with_extension("qcow2"));
            (
                file.clone(),
                vec![(
                    fluxvm_qemu::disks::ROOT_DISK.to_string(),
                    vm.disk.clone(),
                    file,
                )],
            )
        };
        if dest.exists() {
            bail!("{} already exists", dest.display());
        }
        let parent = if all_disks {
            dest.clone()
        } else {
            dest.parent()
                .map(std::path::Path::to_path_buf)
                .unwrap_or_default()
        };
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(&parent).await?;
        }
        let live = matches!(vm.status, VmStatus::Running | VmStatus::Paused);
        let tag = format!("backup-{stamp}");
        let mut quiesced = false;
        if live {
            quiesced = self.backup_freeze(&vm, quiesce).await?;
            let snap = self.create_vm_snapshot_inner(id, &tag).await;
            if quiesced {
                let sock = Self::qga_socket_for(&vm)?;
                let thawed =
                    tokio::task::spawn_blocking(move || fluxvm_image::qga::fsfreeze_thaw(&sock))
                        .await;
                if !matches!(thawed, Ok(Ok(_))) {
                    tracing::error!(vm=%id, "thawing guest filesystems after backup snapshot failed: {thawed:?}");
                }
            }
            snap?;
        }
        let mut result: Result<Vec<serde_json::Value>> = Ok(Vec::new());
        for (name, src, dst) in &targets {
            let src_format = if name == fluxvm_qemu::disks::ROOT_DISK {
                root_format.as_str()
            } else {
                backup::data_disk_format(src)
            };
            let mut cmd = tokio::process::Command::new(&self.cfg.qemu_img_binary);
            cmd.args(["convert", "-U", "-f", src_format, "-O", "qcow2"]);
            if compress {
                cmd.arg("-c");
            }
            if live {
                cmd.args(["-l", &format!("snapshot.name={tag}")]);
            }
            let out = cmd
                .arg(src)
                .arg(dst)
                .output()
                .await
                .with_context(|| format!("running {}", self.cfg.qemu_img_binary));
            match out {
                Ok(o) if o.status.success() => {
                    if let Ok(items) = result.as_mut() {
                        items.push(serde_json::json!({
                            "name": name,
                            "path": dst,
                            "size_bytes": fs::metadata(dst).map(|m| m.len()).unwrap_or(0),
                        }));
                    }
                }
                Ok(o) => {
                    result = Err(anyhow::anyhow!(
                        "qemu-img convert {name} failed: {}",
                        String::from_utf8_lossy(&o.stderr).trim()
                    ));
                    break;
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        if live && let Err(e) = fluxvm_qemu::snapshot_delete(&self.cfg, &vm, &tag).await {
            tracing::warn!(vm=%id, tag, error=?e, "dropping backup snapshot failed");
        }
        let disks = match result {
            Ok(d) => d,
            Err(e) => {
                if all_disks {
                    let _ = fs::remove_dir_all(&dest);
                } else {
                    let _ = fs::remove_file(&dest);
                }
                return Err(e);
            }
        };
        let size_bytes: u64 = disks.iter().filter_map(|d| d["size_bytes"].as_u64()).sum();
        let dest_s = dest.display().to_string();
        audit_event(
            "vm.backup",
            &[("vm_id", &id.to_string()), ("path", &dest_s)],
        );
        let out = serde_json::json!({
            "name": dest.file_name().map(|n| n.to_string_lossy().into_owned()),
            "vm_id": id,
            "vm_name": vm.request.name,
            "created_at": Utc::now(),
            "path": dest,
            "size_bytes": size_bytes,
            "live": live,
            "quiesced": quiesced,
            "disks": disks,
        });
        let sidecar = backup::sidecar_path(&dest, all_disks);
        if let Err(e) = fs::write(&sidecar, serde_json::to_vec_pretty(&out)?) {
            tracing::warn!(vm=%id, path=%sidecar.display(), "writing backup metadata failed: {e}");
        }
        Ok(out)
    }

    /// One pass of label-driven scheduled snapshots (see
    /// [`SNAPSHOT_EVERY_LABEL`]): take an `auto-*` snapshot when the newest
    /// is older than the interval, then prune beyond the keep count.
    pub async fn run_scheduled_snapshots(self: &Arc<Self>) {
        let now = Utc::now();
        for vm in self.store.list().await {
            let Some(every) = vm
                .labels
                .get(SNAPSHOT_EVERY_LABEL)
                .and_then(|v| parse_interval_secs(v))
            else {
                continue;
            };
            if vm.status != VmStatus::Running || vm.backend != BackendKind::Qemu {
                continue;
            }
            let keep = vm
                .labels
                .get(SNAPSHOT_KEEP_LABEL)
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(DEFAULT_SNAPSHOT_KEEP)
                .max(1);
            let snaps = match self.list_vm_snapshots(vm.id).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(vm=%vm.id, error=?e, "scheduled snapshot: listing failed");
                    continue;
                }
            };
            let (due, _) = snapshot_schedule_plan(&snaps, every, keep, now);
            if !due {
                continue;
            }
            let tag = format!("{AUTO_SNAPSHOT_PREFIX}{}", now.format("%Y%m%dT%H%M%SZ"));
            if let Err(e) = self.create_vm_snapshot(vm.id, &tag).await {
                tracing::warn!(vm=%vm.id, error=?e, "scheduled snapshot failed");
                continue;
            }
            let Ok(snaps) = self.list_vm_snapshots(vm.id).await else {
                continue;
            };
            let (_, prune) = snapshot_schedule_plan(&snaps, every, keep, now);
            for old in prune {
                if let Err(e) = self.delete_vm_snapshot(vm.id, &old).await {
                    tracing::warn!(vm=%vm.id, tag=old, error=?e, "pruning scheduled snapshot failed");
                }
            }
        }
    }

    /// Connect to a running QEMU VM's serial socket.
    pub async fn open_serial(&self, id: Uuid) -> Result<tokio::net::UnixStream> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Qemu {
            bail!("serial console is supported for the QEMU backend only");
        }
        if !matches!(vm.status, VmStatus::Running | VmStatus::Paused) {
            bail!("VM {id} is not running (status={:?})", vm.status);
        }
        let path = vm.workspace.join(fluxvm_qemu::SERIAL_SOCKET);
        tokio::net::UnixStream::connect(&path)
            .await
            .with_context(|| {
                format!(
                    "connecting {} (VMs booted before serial sockets existed need a restart)",
                    path.display()
                )
            })
    }

    async fn qemu_vm_for_disks(&self, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Qemu {
            bail!("disk operations are supported for the QEMU backend only");
        }
        Ok(vm)
    }

    pub async fn list_vm_disks(&self, id: Uuid) -> Result<Vec<fluxvm_core::model::VmDiskInfo>> {
        let vm = self.qemu_vm_for_disks(id).await?;
        fluxvm_qemu::disks::list(&self.cfg, &vm).await
    }

    /// New qcow2 data disk, hot-added when the VM is running.
    pub async fn attach_vm_disk(
        &self,
        id: Uuid,
        name: &str,
        size_gib: u64,
    ) -> Result<fluxvm_core::model::VmDiskInfo> {
        let vm = self.qemu_vm_for_disks(id).await?;
        let info = fluxvm_qemu::disks::attach(&self.cfg, &vm, name, size_gib).await?;
        audit_event(
            "vm.disk.attach",
            &[
                ("vm_id", &id.to_string()),
                ("disk", name),
                ("size_gib", &size_gib.to_string()),
            ],
        );
        Ok(info)
    }

    /// Attach an existing image file or block device as a data disk. Files
    /// must sit under `policy.allowed_image_dirs` when that is set; block
    /// devices must resolve under `/dev`.
    pub async fn attach_existing_vm_disk(
        &self,
        id: Uuid,
        name: &str,
        source: &std::path::Path,
    ) -> Result<fluxvm_core::model::VmDiskInfo> {
        let vm = self.qemu_vm_for_disks(id).await?;
        let real = self.check_disk_source(source)?;
        let info = fluxvm_qemu::disks::attach_existing(&self.cfg, &vm, name, &real).await?;
        audit_event(
            "vm.disk.attach",
            &[
                ("vm_id", &id.to_string()),
                ("disk", name),
                ("source", &real.to_string_lossy()),
            ],
        );
        Ok(info)
    }

    /// Create data disk `name` as a qcow2 overlay on `backing`, which is
    /// checked like an `attach_existing_vm_disk` source and never written.
    pub async fn attach_overlay_vm_disk(
        &self,
        id: Uuid,
        name: &str,
        backing: &std::path::Path,
    ) -> Result<fluxvm_core::model::VmDiskInfo> {
        let vm = self.qemu_vm_for_disks(id).await?;
        let real = self.check_disk_source(backing)?;
        let info = fluxvm_qemu::disks::attach_overlay(&self.cfg, &vm, name, &real).await?;
        audit_event(
            "vm.disk.attach",
            &[
                ("vm_id", &id.to_string()),
                ("disk", name),
                ("backing", &real.to_string_lossy()),
            ],
        );
        Ok(info)
    }

    /// Canonical path of a disk source: a block device under `/dev`, or a
    /// file under `policy.allowed_image_dirs` when that is set.
    fn check_disk_source(&self, source: &std::path::Path) -> Result<std::path::PathBuf> {
        let real = fs::canonicalize(source)
            .with_context(|| format!("resolving disk source {}", source.display()))?;
        let block = {
            use std::os::unix::fs::FileTypeExt;
            fs::metadata(&real)?.file_type().is_block_device()
        };
        if block {
            if !real.starts_with("/dev") {
                bail!("block device source {} is not under /dev", real.display());
            }
        } else if let Some(dirs) = &self.cfg.policy.allowed_image_dirs
            && !dirs
                .iter()
                .any(|d| fs::canonicalize(d).is_ok_and(|d| real.starts_with(d)))
        {
            bail!(
                "disk source {} is not under any policy allowed_image_dirs {dirs:?}",
                source.display()
            );
        }
        Ok(real)
    }

    pub async fn detach_vm_disk(&self, id: Uuid, name: &str) -> Result<()> {
        let vm = self.qemu_vm_for_disks(id).await?;
        fluxvm_qemu::disks::detach(&vm, name).await?;
        audit_event(
            "vm.disk.detach",
            &[("vm_id", &id.to_string()), ("disk", name)],
        );
        Ok(())
    }

    /// Grow `root` or a data disk (live `block_resize`, else `qemu-img resize`).
    pub async fn resize_vm_disk(
        &self,
        id: Uuid,
        name: &str,
        size_gib: u64,
    ) -> Result<fluxvm_core::model::VmDiskInfo> {
        let vm = self.qemu_vm_for_disks(id).await?;
        if name == fluxvm_qemu::disks::ROOT_DISK && vm.request.storage != StorageBackend::Default {
            bail!("root disk resize needs the default qcow2 storage backend");
        }
        let info = fluxvm_qemu::disks::resize(&self.cfg, &vm, name, size_gib).await?;
        audit_event(
            "vm.disk.resize",
            &[
                ("vm_id", &id.to_string()),
                ("disk", name),
                ("size_gib", &size_gib.to_string()),
            ],
        );
        Ok(info)
    }

    /// Limits and current usage for one API token (`GET /v1/quotas/me`).
    pub async fn token_quota_usage(&self, actor: Option<&str>) -> Result<serde_json::Value> {
        let actor = actor.unwrap_or("none");
        let unlimited = actor == "anonymous-admin" || actor == "none";
        let (vms, vcpus, memory_mib) = self
            .list()
            .await
            .iter()
            .filter(|vm| vm.request.created_by_token.as_deref() == Some(actor))
            .fold((0u64, 0u64, 0u64), |(n, c, m), vm| {
                (
                    n + 1,
                    c + vm.request.vcpus as u64,
                    m + vm.request.memory_mib,
                )
            });
        Ok(serde_json::json!({
            "token": actor,
            "unlimited": unlimited,
            "limits": {
                "max_vms": if unlimited { None } else { self.cfg.auth.max_vms_per_token },
                "max_memory_mib": if unlimited { None } else { self.cfg.auth.max_memory_mib_per_token },
            },
            "usage": {"vms": vms, "vcpus": vcpus, "memory_mib": memory_mib},
        }))
    }

    pub async fn exec(
        &self,
        id: Uuid,
        command: String,
        timeout_seconds: Option<u64>,
    ) -> Result<fluxvm_guest_protocol::AgentResponse> {
        let vm = self.get(id).await?;
        if let Some(spec) = procbox_sandbox::load_spec(&vm)? {
            return self.procbox_exec(&vm, spec, command, timeout_seconds).await;
        }
        let wait = std::time::Duration::from_secs(
            timeout_seconds.unwrap_or(fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS) + 5,
        );
        fluxvm_vsock_client::call(
            &vm,
            AgentRequest::Exec {
                command,
                timeout_seconds,
            },
            wait,
        )
        .await
    }

    /// Health-checks the vsock guest agent (`AgentRequest::Ping`) — proves
    /// the agent is up and, if a token is configured, that this VM's own
    /// token still authenticates, without spending a real `exec` round trip
    /// (and whatever guest-side work that implies) just to find out.
    /// Distinct from `qga_ping`, which checks the separate QEMU guest-agent
    /// (virtio-serial) channel instead.
    pub async fn agent_ping(&self, id: Uuid) -> Result<()> {
        let vm = self.get(id).await?;
        fluxvm_vsock_client::ping(&vm, fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT).await
    }

    /// Ask the guest agent to power the guest off (`shutdown -h now`).
    /// Distinct from [`Self::stop`], which tears down the VMM from the host.
    pub async fn agent_poweroff(&self, id: Uuid) -> Result<()> {
        let vm = self.get(id).await?;
        match fluxvm_vsock_client::call(
            &vm,
            AgentRequest::Shutdown,
            fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT,
        )
        .await?
        {
            AgentResponse::ShuttingDown => Ok(()),
            AgentResponse::Error { message } => bail!("guest agent error: {message}"),
            other => bail!("unexpected response to shutdown: {other:?}"),
        }
    }

    /// Ask the guest to reboot via the vsock agent (`reboot`). Connection
    /// drops mid-reboot are treated as success — the guest is often already
    /// tearing the agent down.
    pub async fn agent_reboot(&self, id: Uuid) -> Result<()> {
        match self.exec(id, "reboot".into(), Some(10)).await {
            Ok(AgentResponse::Exec { .. }) | Ok(AgentResponse::ShuttingDown) => Ok(()),
            Ok(AgentResponse::Error { message }) => {
                // `reboot` may fail the JSON round-trip after the syscall started.
                tracing::debug!(%message, "reboot agent error (guest may still be rebooting)");
                Ok(())
            }
            Ok(other) => bail!("unexpected response to reboot: {other:?}"),
            Err(e) => {
                tracing::debug!(error = %e, "reboot: agent connection closed");
                Ok(())
            }
        }
    }

    /// Immediately SIGTERM/SIGKILL the VMM process without a guest ACPI
    /// powerdown (machinectl `kill` / hard stop). Prefer [`Self::stop`] for
    /// a clean shutdown.
    pub async fn kill(&self, id: Uuid) -> Result<VmRecord> {
        let mut vm = self.get(id).await?;
        if let Some(pid) = vm.pid {
            if process::process_alive(pid).await {
                process::terminate_pid(pid).await?;
            }
        }
        let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
        if let Some(tap) = &vm.tap_name {
            let _ = fluxvm_network::cleanup(
                &self.cfg.state_dir,
                id,
                &vm.request.network,
                tap,
                vm.netns.as_deref(),
            )
            .await;
        }
        vm.netns = None;
        for pid in vm.virtiofsd_pids.drain(..) {
            if process::process_alive(pid).await {
                let _ = process::terminate_pid(pid).await;
            }
        }
        if let Some(pid) = vm.swtpm_pid.take() {
            if process::process_alive(pid).await {
                let _ = process::terminate_pid(pid).await;
            }
        }
        if let Some(cgroup_path) = vm.cgroup_path.take() {
            let _ =
                fluxvm_network::qemu_cgroup::detach(&self.cfg.sandbox.dataplane, id, &cgroup_path);
            if let Ok(mgr) = fluxvm_cgroup::CgroupManager::from_path(cgroup_path) {
                let _ = mgr.remove();
            }
        }
        vm.status = VmStatus::Stopped;
        vm.pid = None;
        vm.error = None;
        self.store.update(vm.clone()).await?;
        Ok(vm)
    }

    fn qga_socket_for(vm: &VmRecord) -> Result<std::path::PathBuf> {
        vm.qga_socket
            .clone()
            .or_else(|| {
                vm.request
                    .qga
                    .as_ref()
                    .filter(|q| q.enabled)
                    .map(|_| vm.workspace.join("qga.sock"))
            })
            .context("QGA not enabled for this VM (set qga.enabled in the create spec)")
    }

    pub async fn qga_ping(&self, id: Uuid) -> Result<()> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        tokio::task::spawn_blocking(move || fluxvm_image::qga::ping(&sock))
            .await
            .context("qga ping worker panicked")?
    }

    pub async fn qga_network_interfaces(
        &self,
        id: Uuid,
    ) -> Result<Vec<fluxvm_image::qga::QgaNetworkInterface>> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        tokio::task::spawn_blocking(move || fluxvm_image::qga::network_interfaces(&sock))
            .await
            .context("qga network-interfaces worker panicked")?
    }

    pub async fn qga_fsfreeze_freeze(&self, id: Uuid) -> Result<i64> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        tokio::task::spawn_blocking(move || fluxvm_image::qga::fsfreeze_freeze(&sock))
            .await
            .context("qga fsfreeze-freeze worker panicked")?
    }

    pub async fn qga_fsfreeze_thaw(&self, id: Uuid) -> Result<i64> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        tokio::task::spawn_blocking(move || fluxvm_image::qga::fsfreeze_thaw(&sock))
            .await
            .context("qga fsfreeze-thaw worker panicked")?
    }

    pub async fn qga_fsfreeze_status(&self, id: Uuid) -> Result<String> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        tokio::task::spawn_blocking(move || fluxvm_image::qga::fsfreeze_status(&sock))
            .await
            .context("qga fsfreeze-status worker panicked")?
    }

    pub async fn qga_exec(
        &self,
        id: Uuid,
        path: String,
        args: Vec<String>,
        timeout_seconds: Option<u64>,
    ) -> Result<fluxvm_image::qga::QgaExecResult> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(60));
        tokio::task::spawn_blocking(move || fluxvm_image::qga::exec(&sock, &path, &args, timeout))
            .await
            .context("qga exec worker panicked")?
    }

    pub async fn qga_powershell(
        &self,
        id: Uuid,
        command: String,
        timeout_seconds: Option<u64>,
    ) -> Result<fluxvm_image::qga::QgaExecResult> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(60));
        tokio::task::spawn_blocking(move || fluxvm_image::qga::powershell(&sock, &command, timeout))
            .await
            .context("qga powershell worker panicked")?
    }

    pub async fn qga_firewall_open(
        &self,
        id: Uuid,
        name: String,
        port: u16,
        protocol: String,
        timeout_seconds: Option<u64>,
    ) -> Result<fluxvm_image::qga::QgaExecResult> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(60));
        tokio::task::spawn_blocking(move || {
            fluxvm_image::qga::firewall_open(&sock, &name, port, &protocol, timeout)
        })
        .await
        .context("qga firewall open worker panicked")?
    }

    pub async fn qga_firewall_close(
        &self,
        id: Uuid,
        name: String,
        timeout_seconds: Option<u64>,
    ) -> Result<fluxvm_image::qga::QgaExecResult> {
        let vm = self.get(id).await?;
        let sock = Self::qga_socket_for(&vm)?;
        let timeout = std::time::Duration::from_secs(timeout_seconds.unwrap_or(60));
        tokio::task::spawn_blocking(move || {
            fluxvm_image::qga::firewall_close(&sock, &name, timeout)
        })
        .await
        .context("qga firewall close worker panicked")?
    }

    /// Write a file into the guest over the vsock agent — see
    /// `AgentRequest::PutFile`.
    pub async fn put_file(
        &self,
        id: Uuid,
        path: String,
        content_base64: String,
        mode: Option<u32>,
    ) -> Result<fluxvm_guest_protocol::AgentResponse> {
        let vm = self.get(id).await?;
        if procbox_sandbox::is_procbox(&vm) {
            return self.procbox_put_file(&vm, path, content_base64, mode).await;
        }
        fluxvm_vsock_client::call(
            &vm,
            AgentRequest::PutFile {
                path,
                content_base64,
                mode,
            },
            fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT,
        )
        .await
    }

    /// Read a file from the guest over the vsock agent — see
    /// `AgentRequest::GetFile`.
    pub async fn get_file(
        &self,
        id: Uuid,
        path: String,
    ) -> Result<fluxvm_guest_protocol::AgentResponse> {
        let vm = self.get(id).await?;
        if procbox_sandbox::is_procbox(&vm) {
            return self.procbox_get_file(&vm, path).await;
        }
        fluxvm_vsock_client::call(
            &vm,
            AgentRequest::GetFile { path },
            fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT,
        )
        .await
    }

    /// Open an interactive shell on the guest over the vsock agent — see
    /// `fluxvm_vsock_client::open_shell`. The returned stream is raw PTY
    /// traffic once the handshake completes; callers relay it themselves
    /// (e.g. `fluxvm-api`'s WebSocket console endpoint).
    pub async fn open_console(
        &self,
        id: Uuid,
        cols: u16,
        rows: u16,
    ) -> Result<fluxvm_vsock_client::ConsoleStream> {
        let vm = self.get(id).await?;
        procbox_sandbox::require_guest(&vm, "an interactive console")?;
        fluxvm_vsock_client::open_shell(&vm, cols, rows, fluxvm_vsock_client::DEFAULT_CALL_TIMEOUT)
            .await
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let mut vm = self.get(id).await?;
        // A Paused VM is not "already stopped" — its process is fully
        // alive with vCPUs suspended (real bug found on real hardware: a
        // warm pool's never-claimed, still-Paused members were getting
        // their workspace/disk deleted out from under a live QEMU process,
        // because this only checked for Running, leaking an orphaned
        // process on every `delete_pool` and every pool-member cleanup).
        // `pid.is_some()` is the right test for "there's a process to kill"
        // regardless of which of those two statuses got it there.
        if vm.pid.is_some() {
            vm = self.stop(id).await.context("stopping VM before delete")?;
        }
        // Defense in depth: `stop()` already falls back from graceful
        // shutdown to a waited SIGTERM/SIGKILL, so this should never fire —
        // but if it somehow does, refuse to reclaim the disk out from under
        // a process that's still actually running, rather than silently
        // deleting it and leaking an untracked orphan (the original shape
        // of the bug above, one layer deeper).
        if let Some(pid) = vm.pid {
            if process::process_alive(pid).await {
                bail!("refusing to delete {id}: pid {pid} is still alive after stop");
            }
        }
        let vm = self.store.remove(id).await?.context("VM vanished")?;
        let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, id);
        let _ = fluxvm_network::dataplane::delete_policy(&self.cfg, id);
        let _ = fluxvm_network::edge_contract::delete(&self.cfg, id);
        self.release_pod_identity(&vm).await;
        self.activity.lock().await.remove(&id);
        // These three point at live state outside `workspace` (a
        // still-active LV, a still-running qemu-nbd process, a Ceph clone)
        // that only `delete` ever reclaims — `stop` deliberately leaves them
        // alone, same as it leaves the disk file itself alone, so a stopped
        // VM can be `start`ed again without reprovisioning storage.
        if let Some(lv) = &vm.lvm_lv {
            if let Err(e) = fluxvm_image::storage::cleanup_lvm_lv(lv).await {
                tracing::warn!(vm = %id, error = %e, "failed to remove LVM thin snapshot");
            }
        }
        if let Some(pid) = vm.nbd_pid {
            if let Err(e) = fluxvm_image::storage::cleanup_nbd(pid).await {
                tracing::warn!(vm = %id, error = %e, "failed to stop qemu-nbd export");
            }
        }
        // CephRbdInPlace and Shared disks belong to whoever created them;
        // never removed here (a Shared disk is outside `workspace`).
        if vm.request.storage == StorageBackend::Shared {
            self.release_shared_disk(&vm.disk, id);
        }
        if vm.request.storage == StorageBackend::CephRbd {
            if let Some(pool_image) = fluxvm_image::storage::ceph_rbd_ref(&vm.disk) {
                if let Err(e) =
                    fluxvm_image::storage::cleanup_ceph_rbd(&self.cfg, &pool_image).await
                {
                    tracing::warn!(vm = %id, error = %e, "failed to remove Ceph RBD clone (unverified backend)");
                }
            }
        }
        if vm.workspace.exists() {
            fs::remove_dir_all(vm.workspace)?;
        }
        // Firecracker-jailer VMs place resources under a separate chroot
        // tree (`cfg.jailer.chroot_base_dir`, not `state_dir`) that
        // `workspace` above never covers.
        if let Some(jail_path) = &vm.jail_path {
            if jail_path.exists() {
                fs::remove_dir_all(jail_path)?;
            }
        }
        self.remove_unreferenced_clone_base(&vm.request.image).await;
        let vm_id = id.to_string();
        let tenant = vm.request.tenant.clone().unwrap_or_default();
        audit_event("vm.delete", &[("vm_id", &vm_id), ("tenant", &tenant)]);
        Ok(())
    }

    pub fn list_vm_templates(&self) -> Result<Vec<templates::VmTemplate>> {
        Ok(templates::load(&self.cfg.state_dir)?
            .into_values()
            .collect())
    }

    pub fn get_vm_template(&self, name: &str) -> Result<templates::VmTemplate> {
        templates::load(&self.cfg.state_dir)?
            .remove(name)
            .with_context(|| format!("template {name:?} not found"))
    }

    /// Save (or with `replace`, overwrite) a named template.
    pub async fn save_vm_template(
        &self,
        name: &str,
        description: Option<String>,
        spec: CreateVmRequest,
        replace: bool,
    ) -> Result<templates::VmTemplate> {
        templates::validate_name(name)?;
        let _guard = self.template_lock.lock().await;
        let mut all = templates::load(&self.cfg.state_dir)?;
        if !replace && all.contains_key(name) {
            bail!("template {name:?} already exists");
        }
        let t = templates::VmTemplate {
            name: name.to_string(),
            description,
            created_at: Utc::now(),
            spec: templates::spec_from_request(spec),
        };
        all.insert(name.to_string(), t.clone());
        templates::store(&self.cfg.state_dir, &all)?;
        audit_event("vm_template.save", &[("template", name)]);
        Ok(t)
    }

    pub async fn delete_vm_template(&self, name: &str) -> Result<()> {
        let image = {
            let _guard = self.template_lock.lock().await;
            let mut all = templates::load(&self.cfg.state_dir)?;
            let t = all
                .remove(name)
                .with_context(|| format!("template {name:?} not found"))?;
            templates::store(&self.cfg.state_dir, &all)?;
            t.spec.image
        };
        self.remove_unreferenced_clone_base(&image).await;
        audit_event("vm_template.delete", &[("template", name)]);
        Ok(())
    }

    /// The template's spec renamed to `vm_name`, ready for `create`.
    pub fn vm_template_request(&self, template: &str, vm_name: &str) -> Result<CreateVmRequest> {
        validate_vm_name(vm_name)?;
        let mut req = self.get_vm_template(template)?.spec;
        req.name = vm_name.to_string();
        Ok(req)
    }

    fn clone_base_dir(&self) -> std::path::PathBuf {
        self.cfg.state_dir.join("images").join("clones")
    }

    /// A clone's flattened base lives under `images/clones/` and backs the
    /// clone's copy-on-write disk; drop it once no VM references it.
    async fn remove_unreferenced_clone_base(&self, image: &std::path::Path) {
        if !image.starts_with(self.clone_base_dir()) {
            return;
        }
        if self.list().await.iter().any(|v| v.request.image == image) {
            return;
        }
        match templates::load(&self.cfg.state_dir) {
            Ok(all) if all.values().all(|t| t.spec.image != image) => {}
            _ => return,
        }
        if let Err(e) = fs::remove_file(image) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(image = %image.display(), error = %e, "failed to remove clone base");
            }
        }
    }

    /// Copy a stopped VM into a new VM: flatten its disk (backing chain
    /// included) into `images/clones/`, then `create` from that with the
    /// source's spec, a fresh MAC, and the source's labels.
    pub async fn clone_vm(
        self: &Arc<Self>,
        id: Uuid,
        name: String,
        actor: Option<&str>,
    ) -> Result<VmRecord> {
        validate_vm_name(&name)?;
        let src = self.get(id).await?;
        if src.status != VmStatus::Stopped {
            bail!(
                "clone needs a stopped VM for a consistent disk (status={:?}); stop it first",
                src.status
            );
        }
        if src.request.storage != StorageBackend::Default || !src.disk.is_file() {
            bail!("clone supports local file-backed disks only");
        }
        let dir = self.clone_base_dir();
        tokio::fs::create_dir_all(&dir).await?;
        let base = dir.join(format!(
            "{name}-{}.qcow2",
            &Uuid::new_v4().simple().to_string()[..8]
        ));
        let out = tokio::process::Command::new(&self.cfg.qemu_img_binary)
            .args(["convert", "-O", "qcow2"])
            .arg(&src.disk)
            .arg(&base)
            .output()
            .await
            .with_context(|| format!("running {}", self.cfg.qemu_img_binary))?;
        if !out.status.success() {
            let _ = fs::remove_file(&base);
            bail!(
                "qemu-img convert failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let mut req = src.request.clone();
        req.name = name;
        req.image = base.clone();
        req.loadvm_tag = None;
        // The flattened base already carries the source's current virtual
        // size, which a live `disk resize` may have grown past this value.
        req.disk_size_gib = None;
        if let Some(actor) = actor {
            req.created_by_token = Some(actor.to_string());
        }
        if let NetworkSpec::Tap { mac, .. } = &mut req.network {
            *mac = None;
        }
        let before: std::collections::HashSet<Uuid> =
            self.store.list().await.iter().map(|v| v.id).collect();
        let clone_name = req.name.clone();
        let created = match self.create(req).await {
            Ok(vm) => vm,
            Err(e) => {
                // `create` keeps a Failed record on error; it would point at
                // the base removed below.
                for vm in self.store.list().await {
                    if vm.name == clone_name && !before.contains(&vm.id) {
                        let _ = self.delete(vm.id).await;
                    }
                }
                let _ = fs::remove_file(&base);
                return Err(e);
            }
        };
        let data = fluxvm_qemu::disks::data_disks(&src.workspace);
        if !data.is_empty() {
            let dst_dir = fluxvm_qemu::disks::disks_dir(&created.workspace);
            tokio::fs::create_dir_all(&dst_dir).await?;
            for (disk, path) in data {
                let out = tokio::process::Command::new(&self.cfg.qemu_img_binary)
                    .args(["convert", "-O", "qcow2"])
                    .arg(&path)
                    .arg(dst_dir.join(format!("{disk}.qcow2")))
                    .output()
                    .await
                    .with_context(|| format!("running {}", self.cfg.qemu_img_binary))?;
                if !out.status.success() {
                    let _ = self.delete(created.id).await;
                    bail!(
                        "copying data disk {disk:?}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
            }
        }
        let vm = if src.labels.is_empty() {
            created
        } else {
            self.patch(
                created.id,
                fluxvm_core::model::VmPatch {
                    name: None,
                    labels: src
                        .labels
                        .iter()
                        .map(|(k, v)| (k.clone(), Some(v.clone())))
                        .collect(),
                },
            )
            .await?
        };
        audit_event(
            "vm.clone",
            &[("vm_id", &vm.id.to_string()), ("source", &id.to_string())],
        );
        Ok(vm)
    }

    pub async fn reconcile(&self) -> Result<()> {
        let now = Utc::now();
        for vm in self.store.list().await {
            if vm.status == VmStatus::Running || vm.status == VmStatus::Paused {
                if let Some(pid) = vm.pid {
                    if !process::process_alive(pid).await {
                        let mut vm = vm;
                        vm.status = VmStatus::Stopped;
                        vm.pid = None;
                        let _ = fluxvm_network::dataplane::remove_sandbox_policy(&self.cfg, vm.id);
                        if let Some(tap) = &vm.tap_name {
                            let _ = fluxvm_network::cleanup(
                                &self.cfg.state_dir,
                                vm.id,
                                &vm.request.network,
                                tap,
                                vm.netns.as_deref(),
                            )
                            .await;
                        }
                        vm.netns = None;
                        if let Some(cgroup_path) = vm.cgroup_path.take() {
                            let _ = fluxvm_network::qemu_cgroup::detach(
                                &self.cfg.sandbox.dataplane,
                                vm.id,
                                &cgroup_path,
                            );
                            if let Ok(mgr) = fluxvm_cgroup::CgroupManager::from_path(cgroup_path) {
                                let _ = mgr.remove();
                            }
                        }
                        self.store.update(vm).await?;
                        continue;
                    }

                    // Daemon restart / package upgrades can leave a live VMM
                    // while TC pins/filters are missing or on an older schema.
                    if self.cfg.sandbox.dataplane.mode != fluxvm_core::config::DataplaneMode::Legacy
                    {
                        let needs_repair = fluxvm_network::dataplane::status(&self.cfg, vm.id)
                            .map(|s| !s.attached || !s.schema_compatible || !s.policy_synced)
                            .unwrap_or(true);
                        if needs_repair {
                            let iface = fluxvm_network::dataplane_interface_name(
                                vm.id,
                                vm.netns.is_some(),
                                vm.tap_name.as_deref(),
                            );
                            let extra = if self.cfg.sandbox.egress_allow_domains.is_empty() {
                                vec![]
                            } else {
                                fluxvm_network::egress::resolve_allow_cidrs(
                                    &self.cfg.sandbox.egress_allow_domains,
                                )
                                .await
                            };
                            match fluxvm_network::dataplane::ensure_sandbox_policy(
                                &self.cfg,
                                vm.id,
                                iface.as_deref(),
                                &extra,
                            ) {
                                Ok(true) => tracing::info!(
                                    vm = %vm.id,
                                    "repaired FluxVM eBPF dataplane attachment"
                                ),
                                Ok(false) => {}
                                Err(e) => tracing::warn!(
                                    vm = %vm.id,
                                    error = %e,
                                    "failed to repair FluxVM eBPF dataplane"
                                ),
                            }
                        }
                    }
                }
            } else if vm.status == VmStatus::Creating && now - vm.created_at > STUCK_CREATING_GRACE
            {
                // `create()` sets this placeholder's status to Running or
                // Failed as its very last step — a record still Creating
                // this long after `created_at` means the process running
                // that `create()` call was killed or crashed mid-flight
                // (real trigger: `fluxctl serve` killed while a pool
                // backfill's `create()` was in progress) before it could
                // reach either outcome. Nothing else will ever finish or
                // clean up this placeholder, so reclaim it here rather than
                // leave permanent litter in the store.
                tracing::warn!(vm=%vm.id, "cleaning up a VM stuck in Creating status — its creating process likely crashed");
                let _ = self.delete(vm.id).await;
            }
        }

        // Stale UUID pins are safe to collect only after the VM record is gone.
        let live_ids: Vec<Uuid> = self
            .store
            .list()
            .await
            .into_iter()
            .map(|vm| vm.id)
            .collect();
        if let Err(e) = fluxvm_network::dataplane::reconcile_orphan_pins(&self.cfg, &live_ids) {
            tracing::warn!(error = %e, "failed to reconcile orphan FluxVM eBPF pins");
        }
        Ok(())
    }

    /// Runs `reconcile()`, TTL cleanup, and pool backfill on every tick.
    /// Pool backfill in particular *needs* this: `create_pool`/
    /// `claim_from_pool` also fire off a best-effort background top-up via
    /// `tokio::spawn`, but that only actually finishes if the calling
    /// process stays alive long enough — true for a request handled inside
    /// this `serve` process, but NOT true for a one-shot `fluxctl pool
    /// create`/`claim` CLI invocation, which exits (killing every task it
    /// spawned, finished or not) right after printing its result. This tick
    /// is the backstop that keeps every pool topped up regardless of which
    /// process's claim/create under-filled it — the same reason TTL cleanup
    /// lives here rather than in `delete`'s caller.
    pub fn start_reaper(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(
                me.cfg.reaper_interval_secs.max(1),
            ));
            loop {
                tick.tick().await;
                if let Err(e) = me.reconcile().await {
                    tracing::warn!(error=?e, "reconcile failed");
                }
                let now = Utc::now();
                for vm in me.store.list().await {
                    if vm.expires_at.is_some_and(|t| t <= now) {
                        if let Err(e) = me.delete(vm.id).await {
                            tracing::warn!(vm=%vm.id, error=?e, "TTL cleanup failed");
                        }
                    }
                }
                for pool in me.pools.list().await {
                    if pool.members.len() < pool.size {
                        me.spawn_backfill(pool.name);
                    }
                }
                me.reap_migration_receivers().await;
                if !me
                    .scheduled_snapshots_busy
                    .swap(true, std::sync::atomic::Ordering::AcqRel)
                {
                    let me2 = me.clone();
                    tokio::spawn(async move {
                        me2.run_scheduled_snapshots().await;
                        me2.scheduled_snapshots_busy
                            .store(false, std::sync::atomic::Ordering::Release);
                    });
                }
            }
        });
    }

    // ---- Warm VM pools ----
    //
    // A pool keeps `size` VMs booted from `template` sitting `Paused`,
    // ready to be handed out by `claim_from_pool` in resume time (already
    // fast — see the "Pause, resume, and exec" README section) instead of
    // full create time. Pool membership (`PoolStore`) and VM lifecycle
    // (`Store`) are separate, separately-locked stores; the invariant kept
    // between them is "every id in `PoolRecord::members` is a `Paused`
    // `VmRecord` not claimed by anyone else," maintained by always popping
    // a member (removing it from that invariant) before doing anything
    // with it, and always pushing a newly-created member only after it's
    // fully paused and ready.

    pub async fn create_pool(self: &Arc<Self>, spec: PoolSpec) -> Result<PoolRecord> {
        if spec.size == 0 {
            bail!("pool size must be at least 1");
        }
        if self.pools.get(&spec.name).await.is_some() {
            bail!("pool '{}' already exists", spec.name);
        }
        let record = PoolRecord {
            name: spec.name.clone(),
            size: spec.size,
            template: spec.template,
            members: vec![],
            claimed_total: 0,
        };
        self.pools.insert(record.clone()).await?;
        self.spawn_backfill(record.name.clone());
        Ok(record)
    }

    pub async fn list_pools(&self) -> Vec<PoolRecord> {
        self.pools.list().await
    }

    pub async fn get_pool(&self, name: &str) -> Result<PoolRecord> {
        self.pools.get(name).await.context("pool not found")
    }

    pub async fn delete_pool(&self, name: &str) -> Result<()> {
        let record = self.pools.remove(name).await?.context("pool not found")?;
        for id in record.members {
            let _ = self.delete(id).await;
        }
        Ok(())
    }

    /// Changes an existing pool's target `size`, the one thing `create_pool`
    /// has no way to fix up after the fact today (a pool sized wrong for
    /// its actual load previously had to be deleted -- discarding every
    /// still-ready warm member -- and recreated from the same spec just to
    /// change one number).
    ///
    /// Growing (`size` > current) only updates the stored target and fires
    /// off the same background `spawn_backfill` `create_pool`/
    /// `claim_from_pool` already use -- the reaper's per-tick top-up is the
    /// same backstop for a resize as it is for those two, so a caller
    /// inside `serve` needs nothing further; a one-shot CLI caller should
    /// follow up with `backfill_pool_sync` exactly as `fluxctl pool create`
    /// already does, for the same reason (see its own doc comment).
    ///
    /// Shrinking (`size` < current) is handled synchronously and
    /// immediately, not left for the reaper: a caller asking for a smaller
    /// pool is asking to give resources back, and there's no reason to sit
    /// on idle-but-unwanted paused VMs until the next tick. Excess ready
    /// members are popped and deleted one at a time, fail-open per member
    /// (matching `delete_pool`'s own "best effort, log and keep going"
    /// cleanup) -- a single stuck member's delete failure must not stop the
    /// rest of the trim, and must not roll back the size change itself
    /// (leaving `size` reduced but membership not yet caught up is a
    /// correct, if temporary, state: the next reaper tick only ever grows a
    /// pool toward `size`, never shrinks it, so an under-trimmed pool
    /// simply stays put rather than drifting back up).
    ///
    /// Both directions are serialized against this same pool's own
    /// `backfill_pool` via `backfill_locks`, so a shrink can never race a
    /// concurrent grow's member creation (or vice versa) into an
    /// inconsistent intermediate membership count.
    pub async fn resize_pool(self: &Arc<Self>, name: &str, size: usize) -> Result<PoolRecord> {
        if size == 0 {
            bail!("pool size must be at least 1");
        }
        let lock = self.backfill_lock(name).await;
        let _guard = lock.lock().await;

        let existing = self.pools.get(name).await.context("pool not found")?;
        self.pools
            .set_size(name, size)
            .await?
            .context("pool not found")?;

        if size < existing.size {
            for _ in 0..(existing.size - size) {
                let Some(id) = self.pools.pop_member(name).await? else {
                    break; // fewer ready members than the excess to trim -- nothing left to remove right now
                };
                if let Err(e) = self.delete(id).await {
                    tracing::warn!(pool = %name, vm = %id, error = ?e, "failed to delete excess pool member while shrinking pool");
                }
            }
        }
        drop(_guard);
        if size > existing.size {
            self.spawn_backfill(name.to_string());
        }
        // Re-read rather than reuse either value above: it must reflect the
        // shrink loop's own member removals, which happened after both.
        self.pools.get(name).await.context("pool not found")
    }

    /// Pops one ready member off `name`'s pool, resumes it (fast — the
    /// member was already fully booted and paused ahead of time), applies
    /// `overrides`, and triggers a backfill to replace it. Fails with a
    /// clear "no ready members" error rather than falling back to a slow
    /// synchronous create — a caller who wants that can just call
    /// `create()` directly instead of `claim_from_pool`.
    ///
    /// `token_tenant`, when the caller's own API token carries one, is
    /// checked against the resumed member's own `request.tenant` (which
    /// `create_pool`'s own enforcement should already have set to match
    /// the pool's owning tenant) -- a mismatch is rejected outright rather
    /// than silently handed over. Without this, claiming from any pool
    /// whose tenant didn't happen to match the caller's own would have
    /// left `tenant_guard_middleware` denying the very caller who just
    /// claimed it access to every one of its own `/v1/vms/{id}/...`
    /// routes afterward (their token's tenant would never match the
    /// claimed VM's), which is a correctness break, not just a security
    /// one.
    pub async fn claim_from_pool(
        self: &Arc<Self>,
        name: &str,
        overrides: ClaimOverrides,
        token_tenant: Option<&str>,
    ) -> Result<VmRecord> {
        // Before popping: a bad request must not consume a ready member.
        overrides.validate().map_err(|e| anyhow::anyhow!(e))?;
        let Some(id) = self.pools.pop_member(name).await? else {
            bail!(
                "pool '{name}' has no ready members right now — try again shortly, or increase its size"
            );
        };
        self.spawn_backfill(name.to_string());

        let mut vm = match self.resume(id).await {
            Ok(vm) => vm,
            Err(e) => {
                // Already popped, so no one else can claim it — clean up
                // rather than leak a paused-but-broken VM outside any
                // pool's accounting.
                let _ = self.delete(id).await;
                return Err(e).context("resuming claimed pool member");
            }
        };
        if let Some(t) = token_tenant {
            if vm.request.tenant.as_deref() != Some(t) {
                // Already popped -- same "clean up rather than leak a
                // claimed-but-unusable VM outside any pool's accounting"
                // reasoning as the resume-failure case above; a backfill
                // was already triggered to replace it.
                let _ = self.delete(id).await;
                bail!(
                    "token tenant '{t}' cannot claim a pool member belonging to a different tenant"
                );
            }
        }
        if let Some(new_name) = overrides.name {
            vm.request.name = new_name.clone();
            vm.name = new_name;
        }
        // The pool member was booted before any Pod existed; recording the Pod's UID here is what lets the
        // dataplane attached at NIC hotplug mint the Pod's eBPF identity (Pod-scoped network policy).
        if overrides.pod_uid.is_some() {
            vm.request.pod_uid = overrides.pod_uid;
        }
        vm.request.ttl_seconds = overrides.ttl_seconds;
        vm.expires_at = overrides
            .ttl_seconds
            .map(|s| Utc::now() + Duration::seconds(s as i64));
        self.store.update(vm.clone()).await?;
        // Best-effort: the claim itself is already done (the VM is resumed
        // and handed back below) by the time this runs, so a failure here
        // must not turn a completed claim into an error over a stats
        // counter — log and keep going, same "observability must never
        // block or unwind the operation it's observing" reasoning as every
        // metrics-recording call elsewhere in this file.
        if let Err(e) = self.pools.increment_claimed(name).await {
            tracing::warn!(pool = %name, error = ?e, "failed to bump pool claimed_total");
        }
        Ok(vm)
    }

    /// Blocking variant of the backfill that `create_pool`/`claim_from_pool`
    /// otherwise only fire off in the background: waits for `name`'s pool
    /// to actually reach its target size before returning. Meant for
    /// one-shot callers — the CLI's `fluxctl pool create` uses this so the
    /// pool is genuinely ready by the time that (short-lived) process
    /// exits, without depending on a separately-running `fluxctl serve`
    /// daemon's reaper tick to finish the job later. A REST caller inside
    /// `serve` has no need for this — the process outlives the background
    /// task either way.
    pub async fn backfill_pool_sync(self: &Arc<Self>, name: &str) -> Result<()> {
        self.backfill_pool(name).await
    }

    fn spawn_backfill(self: &Arc<Self>, pool_name: String) {
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.backfill_pool(&pool_name).await {
                tracing::warn!(pool = %pool_name, error = ?e, "pool backfill failed");
            }
        });
    }

    async fn backfill_lock(&self, name: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self.backfill_locks.lock().await;
        locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    async fn backfill_pool(self: &Arc<Self>, name: &str) -> Result<()> {
        // Serializes backfill runs for THIS pool only (create_pool's
        // initial fill and a claim's replenishment can race each other);
        // backfills for other pools take a different lock and proceed
        // concurrently.
        let lock = self.backfill_lock(name).await;
        let _guard = lock.lock().await;

        loop {
            let Some(record) = self.pools.get(name).await else {
                return Ok(());
            }; // pool deleted meanwhile
            if record.members.len() >= record.size {
                return Ok(());
            }
            let mut req = record.template.clone();
            req.name = format!("{name}-pool-{}", Uuid::new_v4());
            req.ttl_seconds = None; // a paused pool member must never expire on its own
            let vm = self.create(req).await.context("creating pool member")?;

            // `create()` returns as soon as the VMM process is spawned, long
            // before the guest OS has finished booting — pausing right here
            // would freeze it mid-boot, before its guest-agent has even
            // started. Confirmed on real hardware: a member paused this
            // early comes back from `claim`'s resume still mid-boot, and
            // `exec` fails (connection reset/timeout) for as long as the
            // boot has left to run — the exact opposite of what a *warm*
            // pool is for. Wait for the agent to actually answer a ping
            // first, so a paused member is a genuinely finished, ready VM.
            if vm.request.agent.as_ref().is_some_and(|a| a.enabled) {
                if let Err(e) = wait_for_agent_ready(&vm).await {
                    let _ = self.delete(vm.id).await;
                    return Err(e)
                        .context("waiting for new pool member's guest agent to become ready");
                }
            }

            let paused = match self.pause(vm.id).await {
                Ok(paused) => paused,
                Err(e) => {
                    // The VM was created successfully but never made it into
                    // any pool's members — clean it up rather than abandon
                    // an untracked, unpaused VM outside all pool accounting
                    // (e.g. `launch` can report success even though the
                    // spawned VMM process crashes moments later for its own
                    // reasons, which then makes `pause`'s QMP connect fail).
                    let _ = self.delete(vm.id).await;
                    return Err(e).context("pausing new pool member");
                }
            };
            if !self.pools.push_member(name, paused.id).await? {
                // Pool was deleted while this member was being created.
                let _ = self.delete(paused.id).await;
                return Ok(());
            }
        }
    }
}

/// How long a pool backfill will wait for a freshly-created member's guest
/// agent to answer a ping before giving up. Generous on purpose — the
/// slowest real boot observed this session (a whole-disk-extracted
/// Firecracker rootfs hitting systemd's local-fs.target timeout) took
/// ~140s; ordinary QEMU boots are much faster, but this errs long rather
/// than abandon a legitimately-slow-but-fine boot.
const POOL_MEMBER_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Polls the guest agent with `Ping` until it answers or
/// `POOL_MEMBER_READY_TIMEOUT` elapses. See `backfill_pool`'s call site for
/// why this matters: pausing a pool member before its agent is reachable
/// freezes it mid-boot, which is not "ready," just "created."
async fn wait_for_agent_ready(vm: &VmRecord) -> Result<()> {
    let deadline = tokio::time::Instant::now() + POOL_MEMBER_READY_TIMEOUT;
    loop {
        if fluxvm_vsock_client::ping(vm, std::time::Duration::from_secs(5))
            .await
            .is_ok()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "guest agent on {} never became reachable within {POOL_MEMBER_READY_TIMEOUT:?}",
                vm.id
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::model::NetworkSpec;

    fn req(backend: BackendKind, kernel: Option<&str>, firmware: Option<&str>) -> CreateVmRequest {
        CreateVmRequest {
            name: "fixture".into(),
            tenant: None,
            created_by_token: None,
            backend,
            image: "/tmp/base.qcow2".into(),
            vcpus: 1,
            memory_mib: 512,
            max_vcpus: None,
            max_memory_mib: None,
            loadvm_tag: None,
            disk_size_gib: None,
            kernel: kernel.map(Into::into),
            initrd: None,
            firmware: firmware.map(Into::into),
            kernel_args: None,
            network: NetworkSpec::None,
            cloud_init: None,
            ttl_seconds: None,
            extra_args: vec![],
            shared_memory: false,
            agent: None,
            qga: None,
            hyperv: false,
            storage: StorageBackend::Default,
            shared_folders: vec![],
            data_disks: vec![],
            cdroms: vec![],
            numa_node: None,
            cpuset: None,
            hugepages: None,
            vfio_devices: vec![],
            pod_uid: None,
            secure_boot: None,
            tpm: None,
            security_profile: Default::default(),
            measurement_policy: None,
            net_mbit_limit: None,
            net_pps_limit: None,
            blk_mbit_limit: None,
            blk_ops_limit: None,
            cpu_template: None,
        }
    }

    #[test]
    fn effective_cloud_init_returns_none_without_seed_or_shares() {
        let r = req(BackendKind::Qemu, None, None);
        assert!(VmManager::effective_cloud_init(&r).is_none());
    }

    #[test]
    fn effective_cloud_init_synthesizes_mount_commands_with_no_prior_cloud_init() {
        let mut r = req(BackendKind::Qemu, None, None);
        r.shared_folders = vec![fluxvm_core::model::SharedFolder {
            host_path: "/srv/data".into(),
            guest_path: "/mnt/data".into(),
            read_only: false,
        }];
        let ci = VmManager::effective_cloud_init(&r).unwrap();
        let joined = ci.runcmd.join("\n");
        assert!(joined.contains("mkdir -p /mnt/data"));
        assert!(joined.contains("fs0 /mnt/data virtiofs defaults 0 0"));
        assert!(joined.contains("mount /mnt/data"));
    }

    #[test]
    fn effective_cloud_init_appends_to_an_existing_cloud_init() {
        let mut r = req(BackendKind::Qemu, None, None);
        r.cloud_init = Some(CloudInitSpec {
            runcmd: vec!["echo hi".to_string()],
            ..Default::default()
        });
        r.shared_folders = vec![fluxvm_core::model::SharedFolder {
            host_path: "/srv/data".into(),
            guest_path: "/mnt/data".into(),
            read_only: true,
        }];
        let ci = VmManager::effective_cloud_init(&r).unwrap();
        assert_eq!(ci.runcmd[0], "echo hi");
        assert!(ci.runcmd.iter().any(|c| c.contains("/mnt/data")));
        assert!(ci.runcmd.iter().any(|c| c.contains("virtiofs ro ")));
    }

    #[test]
    fn effective_cloud_init_firecracker_uses_ext4_block_mounts() {
        let mut r = req(BackendKind::Firecracker, Some("/boot/vmlinux"), None);
        r.shared_folders = vec![
            fluxvm_core::model::SharedFolder {
                host_path: "/srv/a".into(),
                guest_path: "/mnt/a".into(),
                read_only: false,
            },
            fluxvm_core::model::SharedFolder {
                host_path: "/srv/b".into(),
                guest_path: "/mnt/b".into(),
                read_only: true,
            },
        ];
        let ci = VmManager::effective_cloud_init(&r).unwrap();
        let joined = ci.runcmd.join("\n");
        assert!(joined.contains("/dev/vdc /mnt/a ext4 defaults 0 0"));
        assert!(joined.contains("/dev/vdd /mnt/b ext4 ro 0 0"));
        assert!(!joined.contains("virtiofs"));
    }

    #[test]
    fn non_auto_backend_passes_through_unchanged() {
        let cfg = Config::default();
        for backend in [
            BackendKind::Qemu,
            BackendKind::CloudHypervisor,
            BackendKind::Firecracker,
            BackendKind::FluxVm,
        ] {
            let r = req(backend, None, None);
            assert_eq!(resolve_backend(&r, &cfg), backend);
        }
    }

    #[test]
    fn auto_prefers_firecracker_when_request_supplies_a_kernel() {
        let cfg = Config::default();
        let r = req(BackendKind::Auto, Some("/boot/vmlinux"), None);
        assert_eq!(resolve_backend(&r, &cfg), BackendKind::Firecracker);
    }

    #[test]
    fn auto_prefers_firecracker_when_config_has_a_default_kernel() {
        let mut cfg = Config::default();
        cfg.firecracker_kernel = Some("/boot/vmlinux".into());
        let r = req(BackendKind::Auto, None, None);
        assert_eq!(resolve_backend(&r, &cfg), BackendKind::Firecracker);
    }

    #[test]
    fn auto_uses_opted_in_native_kvm_for_raw_linux() {
        let mut cfg = Config::default();
        cfg.fluxvm_engine = fluxvm_core::config::FluxVmEngine::Kvm;
        cfg.fluxvm_kernel = Some("/boot/vmlinux".into());
        let mut r = req(BackendKind::Auto, None, None);
        r.image = "/images/root.raw".into();
        assert_eq!(resolve_backend(&r, &cfg), BackendKind::FluxVm);
        r.image = "/images/root.qcow2".into();
        assert_ne!(resolve_backend(&r, &cfg), BackendKind::FluxVm);
    }

    #[test]
    fn native_kvm_rejects_ignored_features_before_provisioning() {
        let mut cfg = Config::default();
        cfg.fluxvm_engine = fluxvm_core::config::FluxVmEngine::Kvm;
        let mut r = req(BackendKind::FluxVm, Some("/boot/vmlinux"), None);
        assert!(validate_native_kvm_profile(&r, &cfg).is_ok());
        r.firmware = Some("/boot/OVMF.fd".into());
        assert!(validate_native_kvm_profile(&r, &cfg).is_err());
        r.firmware = None;
        r.storage = StorageBackend::Nbd;
        assert!(validate_native_kvm_profile(&r, &cfg).is_err());
    }

    #[test]
    fn secure_boot_and_tpm_are_allowed_on_qemu() {
        let mut r = req(
            BackendKind::Qemu,
            None,
            Some("/usr/share/OVMF/OVMF_CODE.fd"),
        );
        r.secure_boot = Some(true);
        r.tpm = Some(true);
        assert!(secure_boot_or_tpm_backend_error(&r).is_none());
    }

    #[test]
    fn tpm_alone_is_allowed_on_cloud_hypervisor() {
        let mut r = req(BackendKind::CloudHypervisor, None, None);
        r.tpm = Some(true);
        assert!(secure_boot_or_tpm_backend_error(&r).is_none());
    }

    #[test]
    fn secure_boot_is_rejected_on_every_non_qemu_backend() {
        for backend in [
            BackendKind::CloudHypervisor,
            BackendKind::Firecracker,
            BackendKind::FluxVm,
        ] {
            let mut r = req(backend, None, None);
            r.secure_boot = Some(true);
            assert!(
                secure_boot_or_tpm_backend_error(&r).is_some(),
                "expected secure_boot to be rejected on {backend:?}"
            );
        }
    }

    #[test]
    fn secure_boot_on_cloud_hypervisor_is_rejected_even_when_tpm_is_also_set() {
        // secure_boot must be evaluated independently of tpm -- a request
        // asking for both on Cloud Hypervisor should still fail on the
        // secure_boot half, not be waved through because tpm alone is valid there.
        let mut r = req(BackendKind::CloudHypervisor, None, None);
        r.secure_boot = Some(true);
        r.tpm = Some(true);
        assert!(secure_boot_or_tpm_backend_error(&r).is_some());
    }

    #[test]
    fn tpm_is_rejected_on_firecracker_and_fluxvm() {
        for backend in [BackendKind::Firecracker, BackendKind::FluxVm] {
            let mut r = req(backend, None, None);
            r.tpm = Some(true);
            assert!(
                secure_boot_or_tpm_backend_error(&r).is_some(),
                "expected tpm to be rejected on {backend:?}"
            );
        }
    }

    #[test]
    fn neither_secure_boot_nor_tpm_set_is_never_rejected_on_any_backend() {
        for backend in [
            BackendKind::Qemu,
            BackendKind::CloudHypervisor,
            BackendKind::Firecracker,
            BackendKind::FluxVm,
        ] {
            let r = req(backend, None, None);
            assert!(secure_boot_or_tpm_backend_error(&r).is_none());
        }
    }

    #[test]
    fn snapshot_is_allowed_on_all_vmm_backends() {
        for backend in [
            BackendKind::Qemu,
            BackendKind::CloudHypervisor,
            BackendKind::Firecracker,
            BackendKind::FluxVm,
        ] {
            assert!(
                snapshot_backend_error(backend).is_none(),
                "expected snapshot to be allowed on {backend:?}"
            );
        }
    }

    #[test]
    fn cpu_template_accepted_on_firecracker() {
        let cfg = Config::default();
        let mut r = req(BackendKind::Firecracker, Some("/boot/vmlinux"), None);
        r.cpu_template = Some("T2".into());
        assert!(validate_cpu_template(&r, &cfg).is_ok());
    }

    #[test]
    fn cpu_template_rejected_on_qemu_and_ch() {
        let cfg = Config::default();
        for backend in [BackendKind::Qemu, BackendKind::CloudHypervisor] {
            let mut r = req(backend, None, None);
            r.cpu_template = Some("T2".into());
            assert!(
                validate_cpu_template(&r, &cfg).is_err(),
                "expected cpu_template rejected on {backend:?}"
            );
        }
    }

    #[test]
    fn cpu_template_rejected_on_fluxvm_kvm_engine() {
        let mut cfg = Config::default();
        cfg.fluxvm_engine = fluxvm_core::config::FluxVmEngine::Kvm;
        let mut r = req(BackendKind::FluxVm, Some("/boot/vmlinux"), None);
        r.cpu_template = Some("T2".into());
        assert!(validate_cpu_template(&r, &cfg).is_err());
    }

    #[test]
    fn auto_falls_back_to_cloud_hypervisor_when_only_firmware_is_available() {
        let cfg = Config::default();
        let r = req(BackendKind::Auto, None, Some("/usr/share/hypervisor-fw"));
        assert_eq!(resolve_backend(&r, &cfg), BackendKind::CloudHypervisor);
    }

    #[test]
    fn auto_falls_back_to_cloud_hypervisor_when_config_has_default_firmware() {
        let mut cfg = Config::default();
        cfg.cloud_hypervisor_firmware = Some("/usr/share/hypervisor-fw".into());
        let r = req(BackendKind::Auto, None, None);
        assert_eq!(resolve_backend(&r, &cfg), BackendKind::CloudHypervisor);
    }

    #[test]
    fn auto_falls_back_to_qemu_with_nothing_configured() {
        let cfg = Config::default();
        let r = req(BackendKind::Auto, None, None);
        assert_eq!(resolve_backend(&r, &cfg), BackendKind::Qemu);
    }

    #[test]
    fn backend_rejects_unresolved_auto() {
        assert!(backend(BackendKind::Auto).is_err());
    }

    fn req_with(
        vcpus: u8,
        memory_mib: u64,
        disk_size_gib: Option<u64>,
        ttl_seconds: Option<u64>,
        backend: BackendKind,
        image: &str,
    ) -> CreateVmRequest {
        let mut r = req(backend, None, None);
        r.vcpus = vcpus;
        r.memory_mib = memory_mib;
        r.disk_size_gib = disk_size_gib;
        r.ttl_seconds = ttl_seconds;
        r.image = image.into();
        r
    }

    #[test]
    fn netns_extra_nics_need_qemu() {
        let mut r = req_with(1, 512, None, None, BackendKind::Qemu, "/x.qcow2");
        r.network = NetworkSpec::Tap {
            tap_name: None,
            bridge: None,
            mac: None,
            netns: true,
            direct: None,
            extra: vec![fluxvm_core::model::ExtraNic {
                bridge: "br0".into(),
                mac: None,
                tap_name: None,
                direct: None,
            }],
        };
        r.backend = BackendKind::Qemu;
        assert!(validate_netns_extras(&r).is_ok());
        r.backend = BackendKind::Firecracker;
        assert!(validate_netns_extras(&r).is_err());
        r.backend = BackendKind::CloudHypervisor;
        assert!(validate_netns_extras(&r).is_err());
    }

    #[test]
    fn empty_policy_allows_anything() {
        let cfg = Config::default();
        let r = req_with(
            64,
            1_000_000,
            Some(9999),
            None,
            BackendKind::Qemu,
            "/anywhere/x.qcow2",
        );
        assert!(validate_policy(&r, &cfg).is_ok());
    }

    #[test]
    fn policy_rejects_over_vcpu_limit() {
        let mut cfg = Config::default();
        cfg.policy.max_vcpus = Some(4);
        let r = req_with(8, 512, None, None, BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&r, &cfg).is_err());
    }

    #[test]
    fn policy_rejects_over_memory_limit() {
        let mut cfg = Config::default();
        cfg.policy.max_memory_mib = Some(2048);
        let r = req_with(1, 4096, None, None, BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&r, &cfg).is_err());
    }

    #[test]
    fn policy_rejects_over_disk_limit_but_allows_unset_disk() {
        let mut cfg = Config::default();
        cfg.policy.max_disk_gib = Some(50);
        let over = req_with(1, 512, Some(100), None, BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&over, &cfg).is_err());
        let unset = req_with(1, 512, None, None, BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&unset, &cfg).is_ok());
    }

    #[test]
    fn policy_with_ttl_cap_rejects_both_unbounded_and_over_cap() {
        let mut cfg = Config::default();
        cfg.policy.max_ttl_seconds = Some(3600);
        let unbounded = req_with(1, 512, None, None, BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&unbounded, &cfg).is_err());
        let too_long = req_with(1, 512, None, Some(7200), BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&too_long, &cfg).is_err());
        let ok = req_with(1, 512, None, Some(1800), BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&ok, &cfg).is_ok());
    }

    #[test]
    fn require_catalog_names_rejects_an_unsigned_resolution() {
        let err = fluxvm_core::policy::require_signed_catalog(true, true, None).unwrap_err();
        assert!(err.to_string().contains("require_catalog_names"));
        assert!(fluxvm_core::policy::require_signed_catalog(false, false, None).is_ok());
        assert!(fluxvm_core::policy::require_signed_catalog(true, true, Some("build")).is_ok());
    }

    #[test]
    fn policy_restricts_allowed_backends() {
        let mut cfg = Config::default();
        cfg.policy.allowed_backends = Some(vec![BackendKind::Firecracker]);
        let qemu = req_with(1, 512, None, None, BackendKind::Qemu, "/x.qcow2");
        assert!(validate_policy(&qemu, &cfg).is_err());
        let fc = req_with(1, 512, None, None, BackendKind::Firecracker, "/x.qcow2");
        assert!(validate_policy(&fc, &cfg).is_ok());
    }

    #[test]
    fn policy_restricts_allowed_image_dirs() {
        let mut cfg = Config::default();
        cfg.policy.allowed_image_dirs = Some(vec!["/var/lib/fluxvm/images".into()]);
        let outside = req_with(1, 512, None, None, BackendKind::Qemu, "/tmp/evil.qcow2");
        assert!(validate_policy(&outside, &cfg).is_err());
        let inside = req_with(
            1,
            512,
            None,
            None,
            BackendKind::Qemu,
            "/var/lib/fluxvm/images/base.qcow2",
        );
        assert!(validate_policy(&inside, &cfg).is_ok());
    }

    fn tenant_vm(tenant: &str, vcpus: u8, memory_mib: u64) -> VmRecord {
        let mut request = req(BackendKind::Qemu, None, None);
        request.tenant = Some(tenant.to_string());
        request.vcpus = vcpus;
        request.memory_mib = memory_mib;
        VmRecord {
            id: Uuid::new_v4(),
            name: request.name.clone(),
            backend: request.backend,
            status: VmStatus::Running,
            pid: None,
            created_at: Utc::now(),
            expires_at: None,
            workspace: "/tmp/does-not-matter".into(),
            disk: "/tmp/does-not-matter/root.qcow2".into(),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: "/tmp/does-not-matter/console.log".into(),
            error: None,
            request,
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: Vec::new(),
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
            requested_security_profile: Default::default(),
            achieved_security_profile: Default::default(),
            security_evidence: None,
            labels: Default::default(),
        }
    }

    #[test]
    fn tenant_policy_is_a_noop_without_a_matching_tenants_entry() {
        let cfg = Config::default();
        let mut r = req(BackendKind::Qemu, None, None);
        r.tenant = Some("acme".into());
        assert!(validate_tenant_policy(&r, &cfg, &[]).is_ok());
    }

    #[test]
    fn tenant_policy_is_a_noop_when_request_has_no_tenant() {
        let mut cfg = Config::default();
        cfg.policy.tenants.push(fluxvm_core::config::TenantPolicy {
            tenant: "acme".into(),
            max_vcpus_total: Some(1),
            max_memory_mib_total: None,
            max_vms_total: None,
        });
        let r = req(BackendKind::Qemu, None, None);
        assert!(validate_tenant_policy(&r, &cfg, &[]).is_ok());
    }

    #[test]
    fn tenant_policy_rejects_over_aggregate_vcpu_cap() {
        let mut cfg = Config::default();
        cfg.policy.tenants.push(fluxvm_core::config::TenantPolicy {
            tenant: "acme".into(),
            max_vcpus_total: Some(4),
            max_memory_mib_total: None,
            max_vms_total: None,
        });
        let existing = vec![tenant_vm("acme", 3, 512)];
        let mut r = req(BackendKind::Qemu, None, None);
        r.tenant = Some("acme".into());
        r.vcpus = 2; // 3 already used + 2 requested > 4
        assert!(validate_tenant_policy(&r, &cfg, &existing).is_err());
        r.vcpus = 1; // 3 + 1 == 4, exactly at the cap, still allowed
        assert!(validate_tenant_policy(&r, &cfg, &existing).is_ok());
    }

    #[test]
    fn tenant_policy_rejects_over_aggregate_memory_cap() {
        let mut cfg = Config::default();
        cfg.policy.tenants.push(fluxvm_core::config::TenantPolicy {
            tenant: "acme".into(),
            max_vcpus_total: None,
            max_memory_mib_total: Some(4096),
            max_vms_total: None,
        });
        let existing = vec![tenant_vm("acme", 1, 3072)];
        let mut r = req(BackendKind::Qemu, None, None);
        r.tenant = Some("acme".into());
        r.memory_mib = 2048; // 3072 + 2048 > 4096
        assert!(validate_tenant_policy(&r, &cfg, &existing).is_err());
    }

    #[test]
    fn tenant_policy_rejects_over_aggregate_vm_count_cap() {
        let mut cfg = Config::default();
        cfg.policy.tenants.push(fluxvm_core::config::TenantPolicy {
            tenant: "acme".into(),
            max_vcpus_total: None,
            max_memory_mib_total: None,
            max_vms_total: Some(2),
        });
        let existing = vec![tenant_vm("acme", 1, 512), tenant_vm("acme", 1, 512)];
        let mut r = req(BackendKind::Qemu, None, None);
        r.tenant = Some("acme".into());
        assert!(validate_tenant_policy(&r, &cfg, &existing).is_err());
    }

    #[test]
    fn tenant_policy_ignores_other_tenants_usage() {
        let mut cfg = Config::default();
        cfg.policy.tenants.push(fluxvm_core::config::TenantPolicy {
            tenant: "acme".into(),
            max_vcpus_total: Some(2),
            max_memory_mib_total: None,
            max_vms_total: None,
        });
        // A caller of validate_tenant_policy is responsible for
        // pre-filtering `existing_for_tenant` to the request's own tenant
        // (VmManager::create does this via Store::list().filter(...)) --
        // this test documents that the function itself does not
        // re-filter, by only ever passing already-tenant-scoped records,
        // matching real call-site behavior.
        let other_tenant_only: Vec<VmRecord> = vec![];
        let mut r = req(BackendKind::Qemu, None, None);
        r.tenant = Some("acme".into());
        r.vcpus = 2;
        assert!(validate_tenant_policy(&r, &cfg, &other_tenant_only).is_ok());
    }

    mod resize_pool_tests {
        use super::*;
        use std::path::PathBuf;

        fn manager() -> Arc<VmManager> {
            // fluxvm-scheduler has no `tempfile` dev-dependency (unlike
            // fluxvm-storage/fluxvm-api), so a plain unique directory under
            // the OS temp dir stands in for it here rather than adding one
            // just for this test module. Never cleaned up, same as the
            // Box::leak'd tempdirs elsewhere in this workspace's own test
            // helpers -- a short-lived `cargo test` process leaks either way.
            let dir =
                std::env::temp_dir().join(format!("fluxvm-resize-pool-test-{}", Uuid::new_v4()));
            let cfg = Config {
                state_dir: dir.join("state"),
                run_dir: dir.join("run"),
                ..Config::default()
            };
            VmManager::new(cfg).unwrap()
        }

        /// A minimal, fully-populated `VmRecord` a shrink's `delete()` call
        /// can actually delete cleanly: `pid: None` so `delete()` never
        /// tries to stop a "running" process that doesn't exist.
        fn paused_member(name: &str) -> VmRecord {
            VmRecord {
                id: Uuid::new_v4(),
                name: name.to_string(),
                backend: BackendKind::Qemu,
                status: VmStatus::Paused,
                pid: None,
                created_at: Utc::now(),
                expires_at: None,
                workspace: PathBuf::from("/tmp/does-not-matter"),
                disk: PathBuf::from("/tmp/does-not-matter/root.qcow2"),
                seed_disk: None,
                tap_name: None,
                control_socket: None,
                log_path: PathBuf::from("/tmp/does-not-matter/console.log"),
                error: None,
                request: req(BackendKind::Qemu, None, None),
                guest_cid: None,
                jail_path: None,
                vsock_socket: None,
                qga_socket: None,
                cgroup_path: None,
                netns: None,
                lvm_lv: None,
                nbd_pid: None,
                virtiofsd_pids: vec![],
                swtpm_pid: None,
                dhcp_leasefile: None,
                guest_ip: None,
                requested_security_profile: Default::default(),
                achieved_security_profile: Default::default(),
                security_evidence: None,
                labels: Default::default(),
            }
        }

        fn pool_with_members(name: &str, size: usize, members: Vec<Uuid>) -> PoolRecord {
            PoolRecord {
                name: name.to_string(),
                size,
                template: req(BackendKind::Qemu, None, None),
                members,
                claimed_total: 0,
            }
        }

        #[tokio::test]
        async fn resize_pool_rejects_zero_size() {
            let m = manager();
            m.pools
                .insert(pool_with_members("p", 2, vec![]))
                .await
                .unwrap();
            assert!(m.resize_pool("p", 0).await.is_err());
            // Rejected before touching the store at all.
            assert_eq!(m.pools.get("p").await.unwrap().size, 2);
        }

        #[tokio::test]
        async fn resize_pool_errors_on_unknown_pool() {
            let m = manager();
            assert!(m.resize_pool("does-not-exist", 3).await.is_err());
        }

        #[tokio::test]
        async fn resize_pool_growing_updates_target_size_immediately() {
            let m = manager();
            m.pools
                .insert(pool_with_members("p", 1, vec![]))
                .await
                .unwrap();
            let updated = m.resize_pool("p", 4).await.unwrap();
            assert_eq!(updated.size, 4);
            // Growing must never delete or reorder whatever members already
            // existed -- there were none here, but the field itself must
            // still be left alone (checked properly by the shrink test
            // below, which does start with real members).
            assert!(updated.members.is_empty());
        }

        #[tokio::test]
        async fn resize_pool_shrinking_deletes_exactly_the_excess_members() {
            let m = manager();
            let keep = paused_member("keep");
            let drop1 = paused_member("drop1");
            let drop2 = paused_member("drop2");
            for vm in [&keep, &drop1, &drop2] {
                m.store.insert(vm.clone()).await.unwrap();
            }
            // pop_member() pops from the end, so "keep" (pushed first) is
            // the one still standing once the other two are trimmed.
            m.pools
                .insert(pool_with_members("p", 3, vec![keep.id, drop1.id, drop2.id]))
                .await
                .unwrap();

            let updated = m.resize_pool("p", 1).await.unwrap();
            assert_eq!(updated.size, 1);
            assert_eq!(updated.members, vec![keep.id]);
            assert!(
                m.store.get(keep.id).await.is_some(),
                "kept member must survive"
            );
            assert!(
                m.store.get(drop1.id).await.is_none(),
                "excess member must be deleted"
            );
            assert!(
                m.store.get(drop2.id).await.is_none(),
                "excess member must be deleted"
            );
        }

        #[tokio::test]
        async fn resize_pool_shrinking_below_actual_membership_stops_at_zero_members() {
            // Asking for a smaller size than there are ready members to pop
            // (e.g. a backfill hadn't caught up yet) must not error or
            // underflow -- it just removes whatever is actually there.
            let m = manager();
            let only = paused_member("only");
            m.store.insert(only.clone()).await.unwrap();
            m.pools
                .insert(pool_with_members("p", 1, vec![only.id]))
                .await
                .unwrap();

            let updated = m.resize_pool("p", 1).await.unwrap();
            assert_eq!(updated.size, 1);
            assert_eq!(
                updated.members,
                vec![only.id],
                "no-op resize to the same size must not touch members"
            );

            let updated = m.resize_pool("p", 5).await.unwrap();
            assert_eq!(updated.size, 5);
            assert_eq!(
                updated.members,
                vec![only.id],
                "growing must leave existing members untouched (backfill tops up separately)"
            );
        }
    }
}

#[cfg(test)]
mod nic_hotplug_tests {
    use super::{
        free_nic_slot, is_direct, live_migration, nic_hotplug_index, record_hotplugged_nic,
        vm_nic_hotplug_index,
    };
    use fluxvm_core::model::{ExtraNic, NetworkSpec, VmRecord};

    fn vm(network: serde_json::Value) -> VmRecord {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "pool-member",
            "backend": "qemu",
            "status": "paused",
            "pid": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": null,
            "workspace": "/tmp/w",
            "disk": "/tmp/w/disk",
            "seed_disk": null,
            "tap_name": null,
            "control_socket": null,
            "log_path": "/tmp/w/console.log",
            "error": null,
            "request": {
                "name": "pool-member",
                "backend": "qemu",
                "image": "/img.qcow2",
                "network": network
            }
        }))
        .unwrap()
    }

    #[test]
    fn warm_pool_none_network_claims_the_first_hotplug_slot() {
        let spec = NetworkSpec::None;
        assert_eq!(nic_hotplug_index(&spec), 0);
        let mut record = vm(serde_json::json!({"mode": "none"}));
        record_hotplugged_nic(
            &mut record,
            "hn0abcdef".into(),
            "fvbhpod".into(),
            Some("02:aa:bb:cc:dd:ee".into()),
        );
        match &record.request.network {
            NetworkSpec::Tap {
                tap_name,
                bridge,
                mac,
                extra,
                netns,
                direct,
            } => {
                assert_eq!(tap_name.as_deref(), Some("hn0abcdef"));
                assert_eq!(bridge.as_deref(), Some("fvbhpod"));
                assert_eq!(mac.as_deref(), Some("02:aa:bb:cc:dd:ee"));
                assert!(extra.is_empty());
                assert!(!netns);
                assert!(direct.is_none(), "hotplugged NICs are bridged taps");
            }
            other => panic!("expected tap after first hotplug, got {other:?}"),
        }
        assert_eq!(nic_hotplug_index(&record.request.network), 1);
        assert_eq!(
            record.tap_name.as_deref(),
            Some("hn0abcdef"),
            "delete cleans the network only when the record names its primary tap"
        );
    }

    #[test]
    fn only_a_direct_tap_makes_a_dataplane_failure_fatal_regardless_of_mode() {
        let direct: NetworkSpec = serde_json::from_value(serde_json::json!({
            "mode": "tap", "direct": {"outer": "eth0"}
        }))
        .unwrap();
        let bridged: NetworkSpec = serde_json::from_value(serde_json::json!({
            "mode": "tap", "bridge": "vmbr0"
        }))
        .unwrap();
        assert!(is_direct(&direct));
        assert!(!is_direct(&bridged));
        assert!(!is_direct(&NetworkSpec::None));
        assert!(!is_direct(&NetworkSpec::User { forwards: vec![] }));
    }

    #[test]
    fn a_boot_created_primary_tap_takes_slot_zero() {
        let mut record = vm(serde_json::json!({"mode": "tap", "bridge": "br"}));
        record.tap_name = Some("eph00000000".into());
        assert_eq!(vm_nic_hotplug_index(&record), 1);
        record_hotplugged_nic(&mut record, "hn1abcdef".into(), "br".into(), None);
        let NetworkSpec::Tap {
            tap_name, extra, ..
        } = &record.request.network
        else {
            panic!("expected tap");
        };
        assert!(tap_name.is_none(), "the boot primary stays daemon-named");
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].tap_name.as_deref(), Some("hn1abcdef"));
        assert_eq!(vm_nic_hotplug_index(&record), 2);
    }

    #[test]
    fn unplugging_the_last_extra_nic_blocks_migration_until_restart() {
        let nic = |n: u8| serde_json::json!({"bridge": "br", "mac": format!("02:00:00:00:00:0{n}"), "tap_name": format!("hn{n}abcdef")});
        let mut record = vm(serde_json::json!({
            "mode": "tap", "tap_name": "hn0abcdef", "bridge": "br",
            "extra": [nic(1), nic(2)]
        }));
        free_nic_slot(&mut record, 0);
        assert!(!record.labels.contains_key(live_migration::HOTPLUGGED_LABEL));
        free_nic_slot(&mut record, 1);
        assert!(record.labels.contains_key(live_migration::HOTPLUGGED_LABEL));
    }

    #[test]
    fn unplugged_middle_nic_keeps_its_slot_for_the_next_hotplug() {
        let nic = |n: u8| serde_json::json!({"bridge": "br", "mac": format!("02:00:00:00:00:0{n}"), "tap_name": format!("hn{n}abcdef")});
        let mut record = vm(serde_json::json!({
            "mode": "tap", "tap_name": "hn0abcdef", "bridge": "br",
            "extra": [nic(1), nic(2)]
        }));
        assert_eq!(nic_hotplug_index(&record.request.network), 3);
        free_nic_slot(&mut record, 0);
        assert_eq!(
            nic_hotplug_index(&record.request.network),
            1,
            "the freed hotplug-pcie-1 is reused"
        );
        record_hotplugged_nic(&mut record, "hn1abcdef".into(), "br2".into(), None);
        let NetworkSpec::Tap { extra, .. } = &record.request.network else {
            panic!("expected tap");
        };
        assert_eq!(extra.len(), 2);
        assert_eq!(extra[0].bridge, "br2");
        assert_eq!(extra[1].tap_name.as_deref(), Some("hn2abcdef"));

        free_nic_slot(&mut record, 1);
        free_nic_slot(&mut record, 0);
        let NetworkSpec::Tap { extra, .. } = &record.request.network else {
            panic!("expected tap");
        };
        assert!(extra.is_empty(), "trailing empty slots are dropped");
        assert_eq!(nic_hotplug_index(&record.request.network), 1);
    }

    #[test]
    fn second_hotplug_appends_a_multus_extra() {
        let mut record = vm(serde_json::json!({
            "mode": "tap",
            "tap_name": "hn0abcdef",
            "bridge": "fvbhpod",
            "mac": "02:aa:bb:cc:dd:ee",
            "netns": false
        }));
        assert_eq!(nic_hotplug_index(&record.request.network), 1);
        record_hotplugged_nic(
            &mut record,
            "hn1abcdef".into(),
            "fvbhnet1".into(),
            Some("02:11:22:33:44:55".into()),
        );
        let NetworkSpec::Tap {
            tap_name, extra, ..
        } = &record.request.network
        else {
            panic!("expected tap");
        };
        assert_eq!(tap_name.as_deref(), Some("hn0abcdef"));
        assert_eq!(
            record.tap_name.as_deref(),
            Some("hn0abcdef"),
            "a Multus extra must not replace the primary tap the record names"
        );
        assert_eq!(
            extra,
            &vec![ExtraNic {
                bridge: "fvbhnet1".into(),
                mac: Some("02:11:22:33:44:55".into()),
                tap_name: Some("hn1abcdef".into()),
                direct: None,
            }]
        );
        assert_eq!(nic_hotplug_index(&record.request.network), 2);
    }

    #[test]
    fn user_and_macvtap_do_not_consume_a_recorded_slot() {
        assert_eq!(
            nic_hotplug_index(&NetworkSpec::User { forwards: vec![] }),
            0
        );
        assert_eq!(
            nic_hotplug_index(&NetworkSpec::Macvtap {
                parent: "eth0".into(),
                macvtap_mode: None,
                mac: None,
            }),
            0
        );
    }
}

#[cfg(test)]
mod direct_hotplug_tests {
    //! Root + Linux test of the direct hotplug orchestration against a MOCK QEMU (no KVM, no
    //! cgroups, no VmManager). Skipped unless root, the tools and FLUXVM_TEST_BPF_DIR are present.
    use super::*;
    use std::io::{BufRead, BufReader as StdBufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener as StdListener;
    use std::process::{Command, Stdio};

    type Seen = (String, serde_json::Value, Option<String>);

    fn sh(args: &[&str]) -> bool {
        Command::new(args[0])
            .args(&args[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The interface name behind a received tun descriptor (TUNGETIFF): proves the descriptor is
    /// the tap the daemon created, not just some file.
    fn tun_name(fd: i32) -> Option<String> {
        #[repr(C)]
        struct IfReq {
            name: [u8; 16],
            flags: i16,
            _pad: [u8; 22],
        }
        const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
        let mut ifr = IfReq {
            name: [0; 16],
            flags: 0,
            _pad: [0; 22],
        };
        // SAFETY: `ifr` is a live, correctly sized ifreq and `fd` is a caller-owned descriptor.
        if unsafe { libc::ioctl(fd, TUNGETIFF, &mut ifr as *mut IfReq) } != 0 {
            return None;
        }
        let end = ifr.name.iter().position(|&b| b == 0).unwrap_or(16);
        Some(String::from_utf8_lossy(&ifr.name[..end]).into_owned())
    }

    /// Returns the line, the received descriptor's tap name, and the descriptor itself: the caller
    /// keeps it open, exactly as a real QEMU does for the life of the VM (a tap is non-persistent
    /// and disappears with its last descriptor).
    fn recv_line(sock: &std::os::unix::net::UnixStream) -> (String, Option<String>, Option<i32>) {
        let mut buf = vec![0u8; 4096];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: pure size computation.
        let space = unsafe { libc::CMSG_SPACE(4) } as usize;
        let mut control = vec![0u8; space];
        // SAFETY: an all-zero msghdr is a valid initial value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        // SAFETY: msg points at live buffers for the duration of the call.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n <= 0 {
            return (String::new(), None, None);
        }
        let mut name = None;
        let mut held = None;
        // SAFETY: CMSG_* walk the control buffer recvmsg just filled.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
                let mut fd: i32 = -1;
                std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut _ as *mut u8, 4);
                name = tun_name(fd);
                held = Some(fd);
            }
        }
        buf.truncate(n as usize);
        (String::from_utf8_lossy(&buf).trim().to_string(), name, held)
    }

    fn serve(
        listener: StdListener,
        fail_device_add: bool,
    ) -> std::thread::JoinHandle<(Vec<Seen>, Vec<i32>)> {
        std::thread::spawn(move || {
            let mut all = Vec::new();
            let mut fds = Vec::new();
            for _ in 0..if fail_device_add { 2 } else { 1 } {
                let (stream, _) = listener.accept().unwrap();
                let mut w = stream.try_clone().unwrap();
                w.write_all(b"{\"QMP\":{}}\n").unwrap();
                let mut r = StdBufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                w.write_all(b"{\"return\":{}}\n").unwrap();
                loop {
                    let (text, fd_name, fd) = recv_line(&stream);
                    fds.extend(fd);
                    if text.is_empty() {
                        break;
                    }
                    let req: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let cmd = req["execute"].as_str().unwrap().to_string();
                    all.push((cmd.clone(), req["arguments"].clone(), fd_name));
                    let reply = if fail_device_add && cmd == "device_add" {
                        "{\"error\":{\"class\":\"GenericError\",\"desc\":\"no free slot\"}}\n"
                    } else {
                        "{\"return\":{}}\n"
                    };
                    w.write_all(reply.as_bytes()).unwrap();
                    if cmd == "device_add" || cmd == "netdev_del" {
                        break;
                    }
                }
            }
            (all, fds)
        })
    }

    struct Ns(String);
    impl Drop for Ns {
        fn drop(&mut self) {
            let _ = sh(&["ip", "netns", "del", &self.0]);
        }
    }

    fn warm_pool_member(workspace: &std::path::Path) -> VmRecord {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4().to_string(), "name": "pool-member", "backend": "qemu",
            "status": "paused", "pid": 1, "created_at": "2026-01-01T00:00:00Z", "expires_at": null,
            "workspace": workspace, "disk": workspace.join("disk"), "seed_disk": null,
            "tap_name": null, "control_socket": null, "log_path": workspace.join("console.log"),
            "error": null,
            "request": {"name": "pool-member", "backend": "qemu", "image": "/img.qcow2", "network": {"mode": "none"}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn direct_hotplug_wires_the_dataplane_then_hands_qemu_the_tap_descriptor() {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        let bpf = std::env::var_os("FLUXVM_TEST_BPF_DIR").map(std::path::PathBuf::from);
        let (true, Some(bpf)) = (root, bpf) else {
            return eprintln!("SKIP: needs root and FLUXVM_TEST_BPF_DIR");
        };
        if !bpf.join("fluxvm_direct.bpf.o").exists()
            || !sh(&["ip", "-V"])
            || !sh(&["nsenter", "--version"])
        {
            return eprintln!("SKIP: needs built BPF objects, ip and nsenter");
        }
        let pid = std::process::id();
        let (pod, host) = (format!("fvhp{pid}-pod"), format!("fvhp{pid}-host"));
        assert!(sh(&["ip", "netns", "add", &pod]) && sh(&["ip", "netns", "add", &host]));
        let _g = (Ns(pod.clone()), Ns(host.clone()));
        assert!(sh(&[
            "ip", "-n", &host, "link", "add", "lxc0", "type", "veth", "peer", "name", "eth0",
            "netns", &pod
        ]));
        assert!(
            sh(&["ip", "-n", &pod, "link", "set", "eth0", "up"])
                && sh(&["ip", "-n", &host, "link", "set", "lxc0", "up"])
        );

        let work = std::env::temp_dir().join(format!("fluxvm-hotplug-direct-{pid}"));
        std::fs::create_dir_all(work.join("ws")).unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = work.join("state");
        std::fs::create_dir_all(&cfg.state_dir).unwrap();
        cfg.sandbox.dataplane.mode = fluxvm_core::config::DataplaneMode::Ebpf;
        cfg.sandbox.dataplane.bpf_object = bpf.join("fluxvm_tc.bpf.o");
        cfg.sandbox.dataplane.required = true;
        cfg.sandbox.dataplane.default_allow = true;
        let direct = || fluxvm_core::model::DirectSpec {
            outer: "eth0".into(),
            netns_path: Some(format!("/run/netns/{pod}")),
            mode: fluxvm_core::model::DirectMode::PeerVeth,
            guest_ips: vec![],
        };

        // ── success: the mock QEMU must see getfd(with the tap) -> netdev_add -> device_add ──
        let vm = warm_pool_member(&work.join("ws"));
        let sock = vm.workspace.join("qmp.sock");
        let server = serve(StdListener::bind(&sock).unwrap(), false);
        let prepared = plug_direct_nic(&cfg, &vm, direct(), Some("02:00:00:00:00:07".into()))
            .await
            .expect("direct hotplug");
        // `held` plays QEMU's copy of the descriptor: the tap lives while it is open.
        let (seen, held) = server.join().unwrap();
        let cmds: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(cmds, ["getfd", "netdev_add", "device_add"]);
        let tap = prepared.tap_name.clone().unwrap();
        assert_eq!(
            seen[0].2.as_deref(),
            Some(tap.as_str()),
            "the descriptor QEMU received IS the tap the daemon made"
        );
        assert_eq!(
            seen[1].1["fd"], seen[0].1["fdname"],
            "netdev_add must name the descriptor getfd stored"
        );
        assert_eq!(seen[2].1["mac"], "02:00:00:00:00:07");
        assert!(
            matches!(
                &prepared.spec,
                NetworkSpec::Tap {
                    direct: Some(_),
                    bridge: None,
                    ..
                }
            ),
            "the VM record must now describe a direct tap so stop/start re-creates it"
        );
        let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, vm.id).unwrap();
        assert!(
            st.attached && st.direct_attached,
            "the dataplane must be live before QEMU got the NIC: {st:?}"
        );
        fluxvm_network::cleanup(&cfg.state_dir, vm.id, &prepared.spec, &tap, None)
            .await
            .unwrap();
        for fd in held {
            // SAFETY: the descriptors were received by the mock and are closed exactly once, here.
            unsafe { libc::close(fd) };
        }

        // ── failure: QEMU rejects device_add -> everything the daemon created is removed ──
        let vm2 = warm_pool_member(&work.join("ws"));
        let _ = std::fs::remove_file(&sock);
        let server = serve(StdListener::bind(&sock).unwrap(), true);
        let err = plug_direct_nic(&cfg, &vm2, direct(), None)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("no free slot"), "{err:#}");
        for fd in server.join().unwrap().1 {
            // SAFETY: as above.
            unsafe { libc::close(fd) };
        }
        assert!(
            fluxvm_network::direct::recorded(vm2.id).is_none(),
            "the wiring record must be removed"
        );
        let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, vm2.id).unwrap();
        assert!(
            !st.attached && !st.direct_required,
            "nothing may stay attached after a failed hotplug: {st:?}"
        );

        // ── preconditions ──
        let mut has_net = warm_pool_member(&work.join("ws"));
        has_net.request.network = NetworkSpec::User { forwards: vec![] };
        assert!(
            plug_direct_nic(&cfg, &has_net, direct(), None)
                .await
                .unwrap_err()
                .to_string()
                .contains("network.mode=none")
        );
        let mut not_qemu = warm_pool_member(&work.join("ws"));
        not_qemu.backend = BackendKind::Firecracker;
        assert!(
            plug_direct_nic(&cfg, &not_qemu, direct(), None)
                .await
                .unwrap_err()
                .to_string()
                .contains("QEMU")
        );
        let _ = std::fs::remove_dir_all(&work);
    }
}

#[cfg(test)]
mod migration_tls_validation_tests {
    use super::*;

    fn tls_spec_with_temp_files() -> (MigrationTlsSpec, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("fluxvm-tls-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&ca, b"ca").unwrap();
        std::fs::write(&cert, b"cert").unwrap();
        std::fs::write(&key, b"key").unwrap();
        (
            MigrationTlsSpec {
                ca_path: ca,
                cert_path: cert,
                key_path: key,
                tls_hostname: None,
            },
            dir,
        )
    }

    #[test]
    fn validate_migration_tls_spec_rejects_missing_file() {
        let cfg = Config::default();
        let (mut tls, _dir) = tls_spec_with_temp_files();
        tls.ca_path = std::path::PathBuf::from("/nonexistent/ca.pem");
        assert!(validate_migration_tls_spec(&tls, &cfg).is_err());
    }

    #[test]
    fn validate_migration_tls_spec_accepts_existing_files() {
        let cfg = Config::default();
        let (tls, _dir) = tls_spec_with_temp_files();
        assert!(validate_migration_tls_spec(&tls, &cfg).is_ok());
    }

    #[test]
    fn validate_migration_tls_spec_enforce_allowlist() {
        let mut cfg = Config::default();
        let (tls, dir) = tls_spec_with_temp_files();
        cfg.policy.allowed_migration_tls_dirs = Some(vec!["/nowhere".into()]);
        assert!(validate_migration_tls_spec(&tls, &cfg).is_err());
        cfg.policy.allowed_migration_tls_dirs = Some(vec![dir]);
        assert!(validate_migration_tls_spec(&tls, &cfg).is_ok());
    }

    #[test]
    fn validate_migration_receiver_listen_host_allowlist() {
        let mut cfg = Config::default();
        cfg.policy.allowed_migration_bind_addresses =
            Some(vec!["10.0.0.5".into(), "0.0.0.0".into()]);
        let mut req = fluxvm_core::model::MigrationReceiverRequest {
            vcpus: 1,
            memory_mib: 512,
            cpu_model: String::new(),
            machine: String::new(),
            disk: "/tmp/disk.raw".into(),
            disk_format: "raw".into(),
            listen_host: "10.0.0.9".into(),
            advertise_host: String::new(),
            listen_port: 0,
            expires_in_seconds: None,
            tls: None,
            record: None,
        };
        assert!(validate_migration_receiver_request(&req, &cfg).is_err());
        req.listen_host = "10.0.0.5".into();
        assert!(validate_migration_receiver_request(&req, &cfg).is_ok());
        req.listen_host.clear(); // defaults to 0.0.0.0
        assert!(validate_migration_receiver_request(&req, &cfg).is_ok());
    }
}

#[cfg(test)]
mod scheduled_snapshot_tests {
    use super::*;
    use fluxvm_core::model::VmSnapshotInfo;

    fn snap(tag: &str, secs_ago: i64, now: chrono::DateTime<Utc>) -> VmSnapshotInfo {
        VmSnapshotInfo {
            tag: tag.into(),
            created_at: Some(now - Duration::seconds(secs_ago)),
            size_bytes: 0,
        }
    }

    #[test]
    fn intervals() {
        assert_eq!(parse_interval_secs("3600"), Some(3600));
        assert_eq!(parse_interval_secs("30m"), Some(1800));
        assert_eq!(parse_interval_secs("6h"), Some(21600));
        assert_eq!(parse_interval_secs("1d"), Some(86400));
        assert_eq!(parse_interval_secs("90s"), Some(90));
        assert_eq!(parse_interval_secs("10"), None, "below the minimum");
        assert_eq!(parse_interval_secs("x"), None);
        assert_eq!(parse_interval_secs(""), None);
    }

    #[test]
    fn plan_is_due_without_auto_snapshots_and_ignores_manual_ones() {
        let now = Utc::now();
        let (due, prune) = snapshot_schedule_plan(&[snap("manual", 10, now)], 3600, 2, now);
        assert!(due);
        assert!(prune.is_empty());
    }

    #[test]
    fn plan_respects_interval_and_prunes_oldest_auto() {
        let now = Utc::now();
        let snaps = [
            snap("auto-3", 100, now),
            snap("auto-1", 7300, now),
            snap("keep-me", 9000, now),
            snap("auto-2", 3700, now),
        ];
        let (due, prune) = snapshot_schedule_plan(&snaps, 3600, 2, now);
        assert!(!due);
        assert_eq!(prune, vec!["auto-1".to_string()]);
        let (due, _) = snapshot_schedule_plan(&snaps, 60, 2, now);
        assert!(due);
    }
}
