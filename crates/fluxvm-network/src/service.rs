// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! FluxVM Service Fabric v1.
//!
//! Fabric (or another control plane) owns service intent. FluxVM owns the
//! node-local VM-edge mechanics: a service catalog is persisted, compiled to
//! per-VM eBPF service maps, and attached ahead of the existing policy hook.
//! v1 intentionally supports IPv4 TCP/UDP NAT mode. The schema includes DSR
//! so the wire contract does not need to churn when the dataplane grows it,
//! but DSR is rejected until the return-path requirements are implemented.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::{Config, DataplaneMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use uuid::Uuid;

pub const SERVICE_SCHEMA_VERSION: u32 = 1;
const SERVICE_TC_PRIORITY: &str = "49140";
const SERVICE_TC_HANDLE: &str = "40";
const DEFAULT_MAGLEV_TABLE_SIZE: u32 = 4093;
const ALLOWED_MAGLEV_TABLE_SIZES: &[u32] = &[251, 509, 1021, 2039, 4093, 8191, 16381];
const MAX_BACKENDS: usize = 128;
const MAX_SERVICES: usize = 4096;
const MAX_BACKEND_MAP_ENTRIES: usize = 16384;
const MAX_MAGLEV_MAP_ENTRIES: usize = 262144;
const MAX_WEIGHT: u16 = 32;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProtocol {
    Tcp,
    Udp,
}

impl ServiceProtocol {
    fn ip_proto(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAlgorithm {
    #[default]
    Maglev,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServiceMode {
    #[default]
    Nat,
    Dsr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceBackend {
    pub address: Ipv4Addr,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_weight() -> u16 {
    1
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceSpec {
    pub name: String,
    pub vip: Ipv4Addr,
    pub port: u16,
    pub protocol: ServiceProtocol,
    #[serde(default)]
    pub algorithm: ServiceAlgorithm,
    #[serde(default)]
    pub mode: ServiceMode,
    #[serde(default)]
    pub backends: Vec<ServiceBackend>,
    #[serde(default)]
    pub maglev_table_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceStatus {
    pub schema_version: u32,
    pub service_id: u32,
    pub name: String,
    pub active_backends: usize,
    pub maglev_table_size: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceCounters {
    pub service_id: u32,
    pub name: String,
    pub forward_packets: u64,
    pub forward_bytes: u64,
    pub reverse_packets: u64,
    pub backend_misses: u64,
}

pub fn validate(spec: &ServiceSpec) -> Result<()> {
    if spec.name.is_empty() || spec.name.len() > 63 {
        bail!("service name must contain 1..=63 characters");
    }
    if !spec
        .name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    {
        bail!("service name may contain only ASCII letters, digits, '-', '_' and '.'");
    }
    if spec.port == 0 {
        bail!("service port must be non-zero");
    }
    if spec.mode != ServiceMode::Nat {
        bail!("service mode 'dsr' is reserved by schema v1 but not implemented yet");
    }
    if spec.backends.len() > MAX_BACKENDS {
        bail!(
            "service has {} backends; maximum is {MAX_BACKENDS}",
            spec.backends.len()
        );
    }
    let active = spec.backends.iter().filter(|b| b.enabled).count();
    if active == 0 {
        bail!("service must have at least one enabled backend");
    }
    let mut seen = HashSet::new();
    for backend in &spec.backends {
        if backend.port == 0 {
            bail!("backend {} has port 0", backend.address);
        }
        if backend.weight == 0 || backend.weight > MAX_WEIGHT {
            bail!(
                "backend {}:{} weight must be in 1..={MAX_WEIGHT}",
                backend.address,
                backend.port
            );
        }
        if !seen.insert((backend.address, backend.port)) {
            bail!("duplicate backend {}:{}", backend.address, backend.port);
        }
    }
    let table = spec.maglev_table_size.unwrap_or(DEFAULT_MAGLEV_TABLE_SIZE);
    if !ALLOWED_MAGLEV_TABLE_SIZES.contains(&table) {
        bail!(
            "maglev_table_size {table} is unsupported; choose one of {:?}",
            ALLOWED_MAGLEV_TABLE_SIZES
        );
    }
    Ok(())
}

pub fn service_id(name: &str) -> u32 {
    // FNV-1a 32. The catalog rejects collisions across different names.
    let mut h = 0x811c9dc5u32;
    for b in name.as_bytes() {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x01000193);
    }
    h.max(1)
}

fn hash64(seed: u64, bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64 ^ seed;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    // Murmur-inspired finalizer keeps offset/skip streams decorrelated.
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^ (h >> 33)
}

/// Build a Maglev lookup table. Returned values are original backend indexes,
/// not indexes in a compacted active list, so the table can be written
/// directly to the eBPF backend map.
pub fn maglev_table(spec: &ServiceSpec) -> Result<Vec<u32>> {
    validate(spec)?;
    let m = spec.maglev_table_size.unwrap_or(DEFAULT_MAGLEV_TABLE_SIZE) as usize;

    // Implement weights with deterministic virtual backends. The eBPF table
    // still points at the original real backend index.
    let mut virtuals: Vec<(usize, String)> = Vec::new();
    for (idx, backend) in spec.backends.iter().enumerate() {
        if !backend.enabled {
            continue;
        }
        for replica in 0..backend.weight {
            virtuals.push((
                idx,
                format!("{}:{}#{replica}", backend.address, backend.port),
            ));
        }
    }

    let n = virtuals.len();
    let mut offset = vec![0usize; n];
    let mut skip = vec![0usize; n];
    let mut next = vec![0usize; n];
    for (i, (_, token)) in virtuals.iter().enumerate() {
        offset[i] = (hash64(0x46_4c_55_58_01, token.as_bytes()) % m as u64) as usize;
        skip[i] = (hash64(0x46_4c_55_58_02, token.as_bytes()) % (m as u64 - 1)) as usize + 1;
    }

    let mut entry: Vec<Option<u32>> = vec![None; m];
    let mut filled = 0usize;
    while filled < m {
        for i in 0..n {
            let mut c = (offset[i] + next[i] * skip[i]) % m;
            while entry[c].is_some() {
                next[i] += 1;
                c = (offset[i] + next[i] * skip[i]) % m;
            }
            entry[c] = Some(virtuals[i].0 as u32);
            next[i] += 1;
            filled += 1;
            if filled == m {
                break;
            }
        }
    }
    Ok(entry.into_iter().map(Option::unwrap).collect())
}

pub fn list(cfg: &Config) -> Result<Vec<ServiceSpec>> {
    let path = catalog_path(cfg);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading service catalog {}", path.display()))?;
    let mut specs: Vec<ServiceSpec> = serde_json::from_str(&raw)
        .with_context(|| format!("parsing service catalog {}", path.display()))?;
    validate_catalog(&specs)?;
    specs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(specs)
}

pub fn get(cfg: &Config, name: &str) -> Result<Option<ServiceSpec>> {
    Ok(list(cfg)?.into_iter().find(|s| s.name == name))
}

pub fn upsert(cfg: &Config, spec: ServiceSpec) -> Result<ServiceStatus> {
    validate(&spec)?;
    let mut specs = list(cfg)?;
    if let Some(existing) = specs.iter_mut().find(|s| s.name == spec.name) {
        *existing = spec.clone();
    } else {
        specs.push(spec.clone());
    }
    validate_catalog(&specs)?;
    save_catalog(cfg, &specs)?;
    sync_all(cfg)?;
    status_for(&spec)
}

pub fn delete(cfg: &Config, name: &str) -> Result<bool> {
    let mut specs = list(cfg)?;
    let before = specs.len();
    specs.retain(|s| s.name != name);
    if specs.len() == before {
        return Ok(false);
    }
    save_catalog(cfg, &specs)?;
    sync_all(cfg)?;
    Ok(true)
}

pub fn status_for(spec: &ServiceSpec) -> Result<ServiceStatus> {
    validate(spec)?;
    Ok(ServiceStatus {
        schema_version: SERVICE_SCHEMA_VERSION,
        service_id: service_id(&spec.name),
        name: spec.name.clone(),
        active_backends: spec.backends.iter().filter(|b| b.enabled).count(),
        maglev_table_size: spec.maglev_table_size.unwrap_or(DEFAULT_MAGLEV_TABLE_SIZE),
    })
}

fn validate_catalog(specs: &[ServiceSpec]) -> Result<()> {
    if specs.len() > MAX_SERVICES {
        bail!(
            "service catalog has {} entries; maximum is {MAX_SERVICES}",
            specs.len()
        );
    }
    let mut ids = HashMap::<u32, &str>::new();
    let mut names = HashSet::new();
    let mut backend_entries = 0usize;
    let mut maglev_entries = 0usize;
    for spec in specs {
        validate(spec)?;
        if !names.insert(spec.name.as_str()) {
            bail!("duplicate service name '{}'", spec.name);
        }
        backend_entries += spec.backends.iter().filter(|b| b.enabled).count();
        maglev_entries += spec.maglev_table_size.unwrap_or(DEFAULT_MAGLEV_TABLE_SIZE) as usize;
        let id = service_id(&spec.name);
        if let Some(other) = ids.insert(id, &spec.name) {
            bail!(
                "service-id collision: '{}' and '{}' both hash to {id}; rename one service",
                other,
                spec.name
            );
        }
    }
    if backend_entries > MAX_BACKEND_MAP_ENTRIES {
        bail!(
            "service catalog needs {backend_entries} backend-map entries; maximum is {MAX_BACKEND_MAP_ENTRIES}"
        );
    }
    if maglev_entries > MAX_MAGLEV_MAP_ENTRIES {
        bail!(
            "service catalog needs {maglev_entries} Maglev entries; maximum is {MAX_MAGLEV_MAP_ENTRIES}"
        );
    }
    Ok(())
}

fn catalog_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-services.json")
}

fn save_catalog(cfg: &Config, specs: &[ServiceSpec]) -> Result<()> {
    let path = catalog_path(cfg);
    let parent = path.parent().context("service catalog has no parent")?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(specs)?)?;
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(&tmp, &path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn stats_for_vm(cfg: &Config, id: Uuid) -> Result<Vec<ServiceCounters>> {
    let map = service_pin_dir(cfg, id).join("maps/fluxvm_sstats");
    if !map.exists() {
        return Ok(Vec::new());
    }
    let root = bpftool_json_dump(&map)?;
    let names: HashMap<u32, String> = list(cfg)?
        .into_iter()
        .map(|s| (service_id(&s.name), s.name))
        .collect();
    let entries = root
        .as_array()
        .context("bpftool service stats must be an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        if key.len() < 4 {
            continue;
        }
        let sid = u32::from_ne_bytes(key[0..4].try_into().unwrap());
        let mut counters = ServiceCounters {
            service_id: sid,
            name: names
                .get(&sid)
                .cloned()
                .unwrap_or_else(|| format!("service-{sid}")),
            ..ServiceCounters::default()
        };
        if let Some(values) = entry.get("values").and_then(Value::as_array) {
            for cpu in values {
                add_stat_value(&mut counters, &json_bytes(&cpu["value"])?);
            }
        } else if let Some(value) = entry.get("value") {
            add_stat_value(&mut counters, &json_bytes(value)?);
        }
        out.push(counters);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn add_stat_value(out: &mut ServiceCounters, raw: &[u8]) {
    if raw.len() < 32 {
        return;
    }
    out.forward_packets = out
        .forward_packets
        .saturating_add(u64::from_ne_bytes(raw[0..8].try_into().unwrap()));
    out.forward_bytes = out
        .forward_bytes
        .saturating_add(u64::from_ne_bytes(raw[8..16].try_into().unwrap()));
    out.reverse_packets = out
        .reverse_packets
        .saturating_add(u64::from_ne_bytes(raw[16..24].try_into().unwrap()));
    out.backend_misses = out
        .backend_misses
        .saturating_add(u64::from_ne_bytes(raw[24..32].try_into().unwrap()));
}

/// Ensure the Service Fabric programs and maps exist for one VM edge.
/// Returns true only when programs/maps had to be installed or recompiled.
pub fn ensure_for_vm(cfg: &Config, id: Uuid, iface: &str) -> Result<bool> {
    let specs = list(cfg)?;
    if specs.is_empty() {
        remove_for_vm(cfg, id, iface);
        return Ok(false);
    }
    let desired_fingerprint = catalog_fingerprint(&specs)?;
    if cfg.sandbox.dataplane.mode == DataplaneMode::Legacy {
        bail!("FluxVM services require sandbox.dataplane.mode=ebpf or cilium");
    }
    let object = service_bpf_object(cfg);
    if !object.exists() {
        bail!(
            "FluxVM service eBPF object does not exist at {}",
            object.display()
        );
    }
    require("bpftool")?;
    require("tc")?;

    let root = service_pin_dir(cfg, id);
    let prog_dir = root.join("progs");
    let map_dir = root.join("maps");
    fs::create_dir_all(&prog_dir)?;
    fs::create_dir_all(&map_dir)?;

    let ingress_prog = prog_dir.join("fvm_svc_out");
    let egress_prog = prog_dir.join("fvm_svc_in");
    let marker = meta_root()
        .join(id.simple().to_string())
        .join("service_fingerprint");
    let current_fingerprint = fs::read_to_string(&marker)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let programs_present = ingress_prog.exists() && egress_prog.exists();
    if programs_present && current_fingerprint == Some(desired_fingerprint) {
        ensure_clsact(iface)?;
        attach_service_filter(iface, "ingress", &ingress_prog)?;
        attach_service_filter(iface, "egress", &egress_prog)?;
        return Ok(false);
    }
    if !programs_present {
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&prog_dir)?;
        fs::create_dir_all(&map_dir)?;
        run(
            "bpftool",
            &[
                "prog".into(),
                "loadall".into(),
                object.display().to_string(),
                prog_dir.display().to_string(),
                "type".into(),
                "classifier".into(),
                "pinmaps".into(),
                map_dir.display().to_string(),
            ],
        )
        .context("loading FluxVM service BPF programs")?;
    }

    populate_maps(&map_dir, &specs)?;
    ensure_clsact(iface)?;
    attach_service_filter(iface, "ingress", &ingress_prog)?;
    attach_service_filter(iface, "egress", &egress_prog)?;
    if let Some(parent) = marker.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&marker, desired_fingerprint.to_string())?;
    Ok(true)
}

fn catalog_fingerprint(specs: &[ServiceSpec]) -> Result<u64> {
    let bytes = serde_json::to_vec(specs)?;
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(hash)
}

pub fn sync_all(cfg: &Config) -> Result<usize> {
    let root = meta_root();
    if !root.exists() {
        return Ok(0);
    }
    let mut synced = 0usize;
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(&name) else {
            continue;
        };
        let iface = match fs::read_to_string(entry.path().join("iface")) {
            Ok(v) => v.trim().to_string(),
            Err(_) => continue,
        };
        if iface.is_empty() {
            continue;
        }
        ensure_for_vm(cfg, id, &iface)?;
        synced += 1;
    }
    Ok(synced)
}

pub fn remove_for_vm(cfg: &Config, id: Uuid, iface: &str) {
    for direction in ["ingress", "egress"] {
        let _ = run(
            "tc",
            &[
                "filter".into(),
                "del".into(),
                "dev".into(),
                iface.into(),
                direction.into(),
                "pref".into(),
                SERVICE_TC_PRIORITY.into(),
                "handle".into(),
                SERVICE_TC_HANDLE.into(),
                "bpf".into(),
            ],
        );
    }
    let root = service_pin_dir(cfg, id);
    if root.exists() {
        let _ = fs::remove_dir_all(root);
    }
    let _ = fs::remove_file(
        meta_root()
            .join(id.simple().to_string())
            .join("service_fingerprint"),
    );
}

fn service_bpf_object(cfg: &Config) -> PathBuf {
    if let Ok(path) = std::env::var("FLUXVM_SERVICE_BPF_OBJECT") {
        return PathBuf::from(path);
    }
    cfg.sandbox
        .dataplane
        .bpf_object
        .parent()
        .unwrap_or_else(|| Path::new("/usr/lib/fluxvm/bpf"))
        .join("fluxvm_service.bpf.o")
}

fn service_pin_dir(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.sandbox
        .dataplane
        .pin_root
        .join("vms")
        .join(id.simple().to_string())
        .join("service")
}

fn meta_root() -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root).join("vms");
    }
    PathBuf::from("/run/fluxvm/ebpf/vms")
}

fn populate_maps(map_dir: &Path, specs: &[ServiceSpec]) -> Result<()> {
    let svc = map_dir.join("fluxvm_svc4");
    let guard = map_dir.join("fluxvm_sguard");
    let backend = map_dir.join("fluxvm_backend4");
    let maglev = map_dir.join("fluxvm_maglev4");

    // Fail closed across the multi-map replacement. If any operation below
    // fails, guard=1 intentionally remains in the kernel and reconciliation
    // must repair the catalog before VM TCP/UDP egress resumes.
    map_update(&guard, &0u32.to_ne_bytes(), &1u32.to_ne_bytes())?;
    let update = (|| -> Result<()> {
        clear_map(&svc)?;
        clear_map(&backend)?;
        clear_map(&maglev)?;

        for spec in specs {
            let sid = service_id(&spec.name);
            let table = maglev_table(spec)?;
            let table_size = table.len() as u32;

            let mut skey = Vec::with_capacity(8);
            skey.extend_from_slice(&spec.vip.octets());
            skey.extend_from_slice(&spec.port.to_ne_bytes());
            skey.push(spec.protocol.ip_proto());
            skey.push(0);
            let mut sval = Vec::with_capacity(8);
            sval.extend_from_slice(&sid.to_ne_bytes());
            sval.extend_from_slice(&table_size.to_ne_bytes());
            map_update(&svc, &skey, &sval)?;

            for (idx, be) in spec.backends.iter().enumerate() {
                if !be.enabled {
                    continue;
                }
                let mut bkey = Vec::with_capacity(8);
                bkey.extend_from_slice(&sid.to_ne_bytes());
                bkey.extend_from_slice(&(idx as u32).to_ne_bytes());
                let mut bval = Vec::with_capacity(8);
                bval.extend_from_slice(&be.address.octets());
                bval.extend_from_slice(&be.port.to_ne_bytes());
                bval.extend_from_slice(&1u16.to_ne_bytes());
                map_update(&backend, &bkey, &bval)?;
            }

            for (slot, backend_id) in table.into_iter().enumerate() {
                let mut mkey = Vec::with_capacity(8);
                mkey.extend_from_slice(&sid.to_ne_bytes());
                mkey.extend_from_slice(&(slot as u32).to_ne_bytes());
                map_update(&maglev, &mkey, &backend_id.to_ne_bytes())?;
            }
        }
        Ok(())
    })();
    update?;
    map_update(&guard, &0u32.to_ne_bytes(), &0u32.to_ne_bytes())?;
    Ok(())
}

fn attach_service_filter(iface: &str, direction: &str, prog: &Path) -> Result<()> {
    run(
        "tc",
        &[
            "filter".into(),
            "replace".into(),
            "dev".into(),
            iface.into(),
            direction.into(),
            "pref".into(),
            SERVICE_TC_PRIORITY.into(),
            "handle".into(),
            SERVICE_TC_HANDLE.into(),
            "bpf".into(),
            "da".into(),
            "pinned".into(),
            prog.display().to_string(),
        ],
    )
}

fn ensure_clsact(iface: &str) -> Result<()> {
    let out = Command::new("tc")
        .args(["qdisc", "add", "dev", iface, "clsact"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("File exists") {
        return Ok(());
    }
    bail!("tc qdisc add clsact on {iface} failed: {stderr}");
}

fn clear_map(map: &Path) -> Result<()> {
    let root = bpftool_json_dump(map)?;
    let entries = root
        .as_array()
        .context("bpftool map dump must be an array")?;
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

fn map_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
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
    args.push("any".into());
    run("bpftool", &args)
}

fn bpftool_json_dump(map: &Path) -> Result<Value> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()?;
    if !out.status.success() {
        bail!(
            "bpftool map dump {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout).context("parsing bpftool JSON")
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .map(|x| {
                if let Some(n) = x.as_u64().filter(|n| *n <= 255) {
                    return Ok(n as u8);
                }
                if let Some(n) = x.as_i64().filter(|n| (0..=255).contains(n)) {
                    return Ok(n as u8);
                }
                if let Some(text) = x.as_str() {
                    return u8::from_str_radix(text.trim().trim_start_matches("0x"), 16)
                        .with_context(|| format!("invalid bpftool hex byte {text:?}"));
                }
                bail!("unsupported bpftool byte {x}")
            })
            .collect();
    }
    if let Some(text) = v.as_str() {
        return text
            .replace(':', " ")
            .replace(',', " ")
            .split_whitespace()
            .map(|x| {
                u8::from_str_radix(x.trim_start_matches("0x"), 16)
                    .context("invalid bpftool hex byte")
            })
            .collect();
    }
    bail!("unsupported bpftool byte representation: {v}")
}

fn hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn require(name: &str) -> Result<()> {
    if Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
    {
        Ok(())
    } else {
        bail!("required command '{name}' is not available")
    }
}

fn run(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program).args(args).output()?;
    if out.status.success() {
        return Ok(());
    }
    bail!(
        "{} {} failed: {}",
        program,
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            name: "payments".into(),
            vip: "10.40.0.100".parse().unwrap(),
            port: 443,
            protocol: ServiceProtocol::Tcp,
            algorithm: ServiceAlgorithm::Maglev,
            mode: ServiceMode::Nat,
            backends: vec![
                ServiceBackend {
                    address: "10.40.1.21".parse().unwrap(),
                    port: 8443,
                    weight: 1,
                    enabled: true,
                },
                ServiceBackend {
                    address: "10.40.1.22".parse().unwrap(),
                    port: 8443,
                    weight: 1,
                    enabled: true,
                },
                ServiceBackend {
                    address: "10.40.1.23".parse().unwrap(),
                    port: 8443,
                    weight: 1,
                    enabled: true,
                },
            ],
            maglev_table_size: Some(251),
        }
    }

    #[test]
    fn maglev_is_deterministic_and_complete() {
        let a = maglev_table(&spec()).unwrap();
        let b = maglev_table(&spec()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 251);
        assert!(a.iter().all(|id| *id <= 2));
        for id in 0..=2u32 {
            assert!(a.contains(&id));
        }
    }

    #[test]
    fn weights_change_distribution() {
        let mut s = spec();
        s.backends[0].weight = 4;
        let t = maglev_table(&s).unwrap();
        let c0 = t.iter().filter(|id| **id == 0).count();
        let c1 = t.iter().filter(|id| **id == 1).count();
        assert!(
            c0 > c1 * 2,
            "weighted backend should receive more slots: {c0} vs {c1}"
        );
    }

    #[test]
    fn disabled_backends_receive_no_slots() {
        let mut s = spec();
        s.backends[1].enabled = false;
        let t = maglev_table(&s).unwrap();
        assert!(!t.contains(&1));
    }

    #[test]
    fn validation_rejects_dsr_until_dataplane_support_lands() {
        let mut s = spec();
        s.mode = ServiceMode::Dsr;
        assert!(validate(&s).is_err());
    }

    #[test]
    fn service_id_is_stable_nonzero() {
        assert_eq!(service_id("payments"), service_id("payments"));
        assert_ne!(service_id("payments"), 0);
        assert_ne!(service_id("payments"), service_id("search"));
    }
}
