// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! VM-edge eBPF state continuity for live migration.
//!
//! This module deliberately owns only node-local FluxVM state. Zyvor Fabric
//! remains responsible for cross-node orchestration, destination selection,
//! routing/BGP and distributed leases. The source VM is first moved into
//! `quiescing`: existing conntrack entries continue, new non-bootstrap flows
//! are rejected by the TC program. The destination enters `restoring`, imports
//! the state, and is explicitly resumed after the VMM cutover completes.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::ebpf::{self, DATAPLANE_SCHEMA_VERSION};

pub const MIGRATION_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DataplaneMigrationPhase {
    Running,
    Quiescing,
    Restoring,
}

impl DataplaneMigrationPhase {
    fn kernel_value(self) -> u32 {
        match self {
            Self::Running => 0,
            Self::Quiescing => 1,
            Self::Restoring => 2,
        }
    }

    fn from_kernel(value: u32) -> Self {
        match value {
            1 => Self::Quiescing,
            2 => Self::Restoring,
            _ => Self::Running,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawMapEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmNetworkStateSnapshot {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub identity: u32,
    pub dataplane_schema_version: u32,
    pub exported_at_unix_ms: u64,
    pub policy_fingerprint: Option<u64>,
    /// Established VM flows. This is the state required to let the source
    /// quiesce while preserving connections across the destination cutover.
    pub conntrack: Vec<RawMapEntry>,
    /// Observability continuity only; safe to omit when minimizing transfer.
    #[serde(default)]
    pub flows: Vec<RawMapEntry>,
    /// Kernel-native branch reasons from dataplane schema v6.
    #[serde(default)]
    pub drop_reasons: Vec<RawMapEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStateStatus {
    pub vm_id: Uuid,
    pub identity: u32,
    pub phase: DataplaneMigrationPhase,
    pub generation: u32,
    pub dataplane_schema_version: Option<u32>,
    pub schema_compatible: bool,
}

pub fn status(cfg: &Config, id: Uuid) -> Result<MigrationStateStatus> {
    let attach = ebpf::attachment_status(&cfg.sandbox.dataplane, id)?;
    let (phase, generation) = read_phase(cfg, id)?;
    Ok(MigrationStateStatus {
        vm_id: id,
        identity: ebpf::identity_for(id),
        phase,
        generation,
        dataplane_schema_version: attach.schema_version,
        schema_compatible: attach.schema_version == Some(DATAPLANE_SCHEMA_VERSION),
    })
}

pub fn quiesce(cfg: &Config, id: Uuid) -> Result<MigrationStateStatus> {
    set_phase(cfg, id, DataplaneMigrationPhase::Quiescing)?;
    status(cfg, id)
}

pub fn mark_restoring(cfg: &Config, id: Uuid) -> Result<MigrationStateStatus> {
    set_phase(cfg, id, DataplaneMigrationPhase::Restoring)?;
    status(cfg, id)
}

pub fn resume(cfg: &Config, id: Uuid) -> Result<MigrationStateStatus> {
    let map = migration_map(cfg, id);
    if map.exists() {
        let (phase, _) = read_phase(cfg, id)?;
        if phase != DataplaneMigrationPhase::Running {
            map_delete(&map, &ebpf::identity_for(id).to_ne_bytes())
                .context("clearing VM migration gate")?;
        }
    }
    status(cfg, id)
}

/// Export a migration-consistent snapshot. The source must already be in
/// `quiescing` so the conntrack set cannot grow while it is copied.
pub fn export_snapshot(cfg: &Config, id: Uuid) -> Result<VmNetworkStateSnapshot> {
    let st = status(cfg, id)?;
    if !st.schema_compatible {
        bail!(
            "VM {id} uses dataplane schema {:?}; schema {} is required for migration state continuity",
            st.dataplane_schema_version,
            DATAPLANE_SCHEMA_VERSION
        );
    }
    if st.phase != DataplaneMigrationPhase::Quiescing {
        bail!("VM {id} must be quiescing before network state export");
    }
    let attach = ebpf::attachment_status(&cfg.sandbox.dataplane, id)?;
    if !attach.attached {
        bail!("VM {id} has no live VM-edge eBPF attachment to export");
    }
    let policy_fingerprint = attach.policy_fingerprint.with_context(|| {
        format!(
            "VM {id} has no committed network-policy fingerprint; reconcile the dataplane before migration export"
        )
    })?;
    let maps = vm_map_dir(cfg, id);
    Ok(VmNetworkStateSnapshot {
        schema_version: MIGRATION_STATE_SCHEMA_VERSION,
        vm_id: id,
        identity: ebpf::identity_for(id),
        dataplane_schema_version: DATAPLANE_SCHEMA_VERSION,
        exported_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
        policy_fingerprint: Some(policy_fingerprint),
        conntrack: dump_map(&maps.join("fluxvm_ct"))?,
        flows: dump_map_if_present(&maps.join("fluxvm_flows"))?,
        drop_reasons: dump_map_if_present(&maps.join("fluxvm_drop_reasons"))?,
    })
}

/// Validate and import a source snapshot into an already-attached destination
/// VM. The destination is made `restoring` before any state is changed and is
/// intentionally left there. Call `resume()` only after the VMM cutover is
/// complete and the guest is ready to originate new flows.
pub fn restore_snapshot(
    cfg: &Config,
    id: Uuid,
    snapshot: &VmNetworkStateSnapshot,
) -> Result<MigrationStateStatus> {
    validate_snapshot(id, snapshot)?;
    let attach = ebpf::attachment_status(&cfg.sandbox.dataplane, id)?;
    if !attach.attached || attach.schema_version != Some(DATAPLANE_SCHEMA_VERSION) {
        bail!(
            "destination VM {id} must have an attached dataplane schema {} before state restore",
            DATAPLANE_SCHEMA_VERSION
        );
    }
    let source_policy = snapshot.policy_fingerprint.with_context(|| {
        format!("snapshot for VM {id} has no committed network-policy fingerprint")
    })?;
    let destination_policy = attach.policy_fingerprint.with_context(|| {
        format!(
            "destination VM {id} has no committed network-policy fingerprint; reconcile before restore"
        )
    })?;
    if source_policy != destination_policy {
        bail!(
            "network-policy fingerprint mismatch for VM {id}: source={source_policy} destination={destination_policy}; refusing conntrack import"
        );
    }
    mark_restoring(cfg, id)?;
    let maps = vm_map_dir(cfg, id);
    replace_map(&maps.join("fluxvm_ct"), &snapshot.conntrack).context("restoring VM conntrack")?;
    if maps.join("fluxvm_flows").exists() {
        replace_map(&maps.join("fluxvm_flows"), &snapshot.flows)
            .context("restoring VM flow history")?;
    }
    if maps.join("fluxvm_drop_reasons").exists() {
        replace_map(&maps.join("fluxvm_drop_reasons"), &snapshot.drop_reasons)
            .context("restoring VM drop-reason history")?;
    }
    status(cfg, id)
}

pub fn validate_snapshot(id: Uuid, snapshot: &VmNetworkStateSnapshot) -> Result<()> {
    if snapshot.schema_version != MIGRATION_STATE_SCHEMA_VERSION {
        bail!(
            "unsupported network migration snapshot schema {}; expected {}",
            snapshot.schema_version,
            MIGRATION_STATE_SCHEMA_VERSION
        );
    }
    if snapshot.vm_id != id {
        bail!(
            "snapshot VM {} does not match destination VM {id}",
            snapshot.vm_id
        );
    }
    let expected_identity = ebpf::identity_for(id);
    if snapshot.identity != expected_identity {
        bail!(
            "snapshot identity {} does not match stable FluxVM identity {}",
            snapshot.identity,
            expected_identity
        );
    }
    if snapshot.dataplane_schema_version != DATAPLANE_SCHEMA_VERSION {
        bail!(
            "snapshot dataplane schema {} is incompatible with local schema {}",
            snapshot.dataplane_schema_version,
            DATAPLANE_SCHEMA_VERSION
        );
    }
    Ok(())
}

fn set_phase(cfg: &Config, id: Uuid, phase: DataplaneMigrationPhase) -> Result<()> {
    let attach = ebpf::attachment_status(&cfg.sandbox.dataplane, id)?;
    if !attach.attached || attach.schema_version != Some(DATAPLANE_SCHEMA_VERSION) {
        bail!(
            "VM {id} must have an attached dataplane schema {} before migration phase changes",
            DATAPLANE_SCHEMA_VERSION
        );
    }
    let map = migration_map(cfg, id);
    require_map(&map)?;
    let (_, current_generation) = read_phase(cfg, id)?;
    let generation = current_generation.wrapping_add(1).max(1);
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&phase.kernel_value().to_ne_bytes());
    value.extend_from_slice(&generation.to_ne_bytes());
    map_update(&map, &ebpf::identity_for(id).to_ne_bytes(), &value)
}

fn read_phase(cfg: &Config, id: Uuid) -> Result<(DataplaneMigrationPhase, u32)> {
    let map = migration_map(cfg, id);
    if !map.exists() {
        return Ok((DataplaneMigrationPhase::Running, 0));
    }
    let key = ebpf::identity_for(id).to_ne_bytes();
    for entry in dump_map(&map)? {
        if entry.key == key {
            if entry.value.len() < 8 {
                bail!("fluxvm_migration value is shorter than 8 bytes");
            }
            let phase = u32::from_ne_bytes(entry.value[0..4].try_into().unwrap());
            let generation = u32::from_ne_bytes(entry.value[4..8].try_into().unwrap());
            return Ok((DataplaneMigrationPhase::from_kernel(phase), generation));
        }
    }
    Ok((DataplaneMigrationPhase::Running, 0))
}

fn vm_map_dir(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.sandbox
        .dataplane
        .pin_root
        .join("vms")
        .join(id.simple().to_string())
        .join("maps")
}

fn migration_map(cfg: &Config, id: Uuid) -> PathBuf {
    vm_map_dir(cfg, id).join("fluxvm_migration")
}

fn require_map(path: &Path) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        bail!(
            "required FluxVM BPF map is not pinned at {}",
            path.display()
        )
    }
}

fn dump_map_if_present(path: &Path) -> Result<Vec<RawMapEntry>> {
    if path.exists() {
        dump_map(path)
    } else {
        Ok(Vec::new())
    }
}

fn dump_map(path: &Path) -> Result<Vec<RawMapEntry>> {
    require_map(path)?;
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(path)
        .output()
        .with_context(|| format!("running bpftool map dump for {}", path.display()))?;
    if !out.status.success() {
        bail!(
            "bpftool map dump pinned {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    parse_dump_json(&serde_json::from_slice(&out.stdout).context("parsing bpftool JSON")?)
}

fn parse_dump_json(root: &Value) -> Result<Vec<RawMapEntry>> {
    let rows = root
        .as_array()
        .context("bpftool map dump must be an array")?;
    rows.iter()
        .map(|row| {
            Ok(RawMapEntry {
                key: json_bytes(row.get("key").context("map entry missing key")?)?,
                value: json_bytes(row.get("value").context("map entry missing value")?)?,
            })
        })
        .collect()
}

fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .map(|item| {
                if let Some(v) = item.as_u64().filter(|v| *v <= 255) {
                    return Ok(v as u8);
                }
                let raw = item
                    .as_str()
                    .context("bpftool byte must be an integer or hex string")?
                    .trim()
                    .trim_start_matches("0x");
                u8::from_str_radix(raw, 16).context("invalid bpftool hex byte")
            })
            .collect();
    }
    if let Some(object) = value.as_object() {
        if let Some(bytes) = object.get("bytes") {
            return json_bytes(bytes);
        }
    }
    if let Some(raw) = value.as_str() {
        return raw
            .replace(':', " ")
            .replace(',', " ")
            .split_whitespace()
            .map(|v| {
                u8::from_str_radix(v.trim_start_matches("0x"), 16)
                    .context("invalid bpftool hex byte")
            })
            .collect();
    }
    bail!("unsupported bpftool byte representation: {value}")
}

fn replace_map(path: &Path, entries: &[RawMapEntry]) -> Result<()> {
    clear_map(path)?;
    for entry in entries {
        map_update(path, &entry.key, &entry.value)?;
    }
    Ok(())
}

fn clear_map(path: &Path) -> Result<()> {
    for entry in dump_map(path)? {
        let _ = map_delete(path, &entry.key);
    }
    Ok(())
}

fn map_update(path: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".to_string(),
        "update".into(),
        "pinned".into(),
        path.display().to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(hex_args(key));
    args.push("value".into());
    args.push("hex".into());
    args.extend(hex_args(value));
    run_bpftool(&args)
}

fn map_delete(path: &Path, key: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".to_string(),
        "delete".into(),
        "pinned".into(),
        path.display().to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(hex_args(key));
    run_bpftool(&args)
}

fn run_bpftool(args: &[String]) -> Result<()> {
    let out = Command::new("bpftool")
        .args(args)
        .output()
        .context("running bpftool")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "bpftool {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn phase_kernel_values_are_stable() {
        assert_eq!(DataplaneMigrationPhase::Running.kernel_value(), 0);
        assert_eq!(DataplaneMigrationPhase::Quiescing.kernel_value(), 1);
        assert_eq!(DataplaneMigrationPhase::Restoring.kernel_value(), 2);
        assert_eq!(
            DataplaneMigrationPhase::from_kernel(77),
            DataplaneMigrationPhase::Running
        );
    }

    #[test]
    fn parses_bpftool_raw_entry() {
        let rows = json!([{
            "key": ["0x01", "0x02", "0x03", "0x04"],
            "value": [5, 6, 7, 8]
        }]);
        let parsed = parse_dump_json(&rows).unwrap();
        assert_eq!(parsed[0].key, vec![1, 2, 3, 4]);
        assert_eq!(parsed[0].value, vec![5, 6, 7, 8]);
    }

    #[test]
    fn snapshot_validation_rejects_wrong_vm() {
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let snapshot = VmNetworkStateSnapshot {
            schema_version: MIGRATION_STATE_SCHEMA_VERSION,
            vm_id: other,
            identity: ebpf::identity_for(other),
            dataplane_schema_version: DATAPLANE_SCHEMA_VERSION,
            exported_at_unix_ms: 0,
            policy_fingerprint: None,
            conntrack: vec![],
            flows: vec![],
            drop_reasons: vec![],
        };
        assert!(validate_snapshot(id, &snapshot).is_err());
    }
}
