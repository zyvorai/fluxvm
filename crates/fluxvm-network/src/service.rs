// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! FluxVM Service Fabric v2.
//!
//! Fabric owns distributed service intent; FluxVM owns the node-local
//! dataplane.  v2 is cumulative with v1 and adds:
//! - dual-stack IPv4/IPv6 VIPs and backends,
//! - routed Direct Server Return (DSR),
//! - optional per-service SNAT for non-routable client networks,
//! - host/uplink service hooks plus optional XDP north-south acceleration.
//!
//! The service BPF program remains separate from `fluxvm_tc.bpf.c`, keeping
//! the security-policy schema independent from the load-balancer schema.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::{Config, DataplaneMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use uuid::Uuid;

pub const SERVICE_SCHEMA_VERSION: u32 = 2;
const SERVICE_TC_PRIORITY: &str = "49140";
const SERVICE_TC_HANDLE: &str = "40";
const DEFAULT_MAGLEV_TABLE_SIZE: u32 = 4093;
const ALLOWED_MAGLEV_TABLE_SIZES: &[u32] = &[251, 509, 1021, 2039, 4093, 8191, 16381];
const MAX_BACKENDS: usize = 128;
const MAX_SERVICES: usize = 4096;
const MAX_BACKEND_MAP_ENTRIES: usize = 16384;
const MAX_MAGLEV_MAP_ENTRIES: usize = 262144;
const MAX_WEIGHT: u16 = 32;
const BACKEND_ENABLED: u16 = 1;
const MODE_NAT: u8 = 1;
const MODE_DSR: u8 = 2;

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

impl ServiceMode {
    fn wire(self) -> u8 {
        match self {
            Self::Nat => MODE_NAT,
            Self::Dsr => MODE_DSR,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceExposure {
    #[default]
    EastWest,
    NorthSouth,
    Both,
}

impl ServiceExposure {
    fn east_west(self) -> bool {
        matches!(self, Self::EastWest | Self::Both)
    }

    fn north_south(self) -> bool {
        matches!(self, Self::NorthSouth | Self::Both)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceBackend {
    pub address: IpAddr,
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
    pub vip: IpAddr,
    pub port: u16,
    pub protocol: ServiceProtocol,
    #[serde(default)]
    pub algorithm: ServiceAlgorithm,
    #[serde(default)]
    pub mode: ServiceMode,
    #[serde(default)]
    pub exposure: ServiceExposure,
    #[serde(default)]
    pub backends: Vec<ServiceBackend>,
    #[serde(default)]
    pub maglev_table_size: Option<u32>,
    /// Source address used by NAT services when backend networks cannot route
    /// directly to the client. Required for north-south NAT so replies are
    /// guaranteed to return through a FluxVM node and hit reverse NAT.
    #[serde(default)]
    pub snat_address: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceStatus {
    pub schema_version: u32,
    pub service_id: u32,
    pub name: String,
    pub family: String,
    pub mode: ServiceMode,
    pub exposure: ServiceExposure,
    pub active_backends: usize,
    pub maglev_table_size: u32,
    pub snat_address: Option<IpAddr>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceCounters {
    pub service_id: u32,
    pub name: String,
    pub forward_packets: u64,
    pub forward_bytes: u64,
    pub reverse_packets: u64,
    pub backend_misses: u64,
    pub dsr_packets: u64,
    pub snat_packets: u64,
    pub xdp_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostInterfaceStatus {
    pub interface: String,
    pub tc_program_pinned: bool,
    pub xdp_requested: bool,
    pub xdp_program_pinned: bool,
    pub pin_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostServiceStatus {
    pub schema_version: u32,
    pub north_south_interfaces: Vec<String>,
    pub xdp_acceleration: bool,
    pub interfaces: Vec<HostInterfaceStatus>,
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

    let vip_is_v4 = spec.vip.is_ipv4();
    let mut seen = HashSet::new();
    for backend in &spec.backends {
        if backend.port == 0 {
            bail!("backend {} has port 0", backend.address);
        }
        if backend.address.is_ipv4() != vip_is_v4 {
            bail!(
                "backend {} family does not match VIP {}",
                backend.address,
                spec.vip
            );
        }
        if backend.weight == 0 || backend.weight > MAX_WEIGHT {
            bail!(
                "backend {}:{} weight must be in 1..={MAX_WEIGHT}",
                backend.address,
                backend.port
            );
        }
        if spec.mode == ServiceMode::Dsr && backend.port != spec.port {
            bail!(
                "DSR preserves the destination port; backend {}:{} must use service port {}",
                backend.address,
                backend.port,
                spec.port
            );
        }
        if !seen.insert((backend.address, backend.port)) {
            bail!("duplicate backend {}:{}", backend.address, backend.port);
        }
    }

    if let Some(snat) = spec.snat_address {
        if snat.is_ipv4() != vip_is_v4 {
            bail!("SNAT address {snat} family does not match VIP {}", spec.vip);
        }
        if spec.mode == ServiceMode::Dsr {
            bail!("DSR preserves client source IP and cannot be combined with SNAT");
        }
    }
    if spec.exposure.north_south()
        && spec.mode == ServiceMode::Nat
        && spec.snat_address.is_none()
    {
        bail!(
            "north-south NAT requires snat_address so backend replies return through FluxVM"
        );
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
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^ (h >> 33)
}

/// Deterministic weighted Maglev table. Values are original backend indexes,
/// keeping userspace/BPF representation stable while disabled backends are
/// excluded from placement.
pub fn maglev_table(spec: &ServiceSpec) -> Result<Vec<u32>> {
    validate(spec)?;
    let m = spec.maglev_table_size.unwrap_or(DEFAULT_MAGLEV_TABLE_SIZE) as usize;
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
    let previous = list(cfg)?;
    let mut specs = previous.clone();
    if let Some(existing) = specs.iter_mut().find(|s| s.name == spec.name) {
        *existing = spec.clone();
    } else {
        specs.push(spec.clone());
    }
    validate_catalog(&specs)?;
    commit_catalog(cfg, &previous, &specs)?;
    status_for(&spec)
}

pub fn delete(cfg: &Config, name: &str) -> Result<bool> {
    let previous = list(cfg)?;
    let mut specs = previous.clone();
    let before = specs.len();
    specs.retain(|s| s.name != name);
    if specs.len() == before {
        return Ok(false);
    }
    commit_catalog(cfg, &previous, &specs)?;
    Ok(true)
}

fn commit_catalog(cfg: &Config, previous: &[ServiceSpec], desired: &[ServiceSpec]) -> Result<()> {
    save_catalog(cfg, desired)?;
    if let Err(apply_err) = sync_all(cfg) {
        if let Err(persist_err) = save_catalog(cfg, previous) {
            bail!(
                "service dataplane apply failed: {apply_err:#}; catalog rollback also failed: {persist_err:#}"
            );
        }
        if let Err(rollback_err) = sync_all(cfg) {
            bail!(
                "service dataplane apply failed: {apply_err:#}; previous catalog was restored but kernel rollback failed: {rollback_err:#}"
            );
        }
        return Err(apply_err).context(
            "service dataplane apply failed; previous catalog and local kernel state were restored",
        );
    }
    Ok(())
}

pub fn status_for(spec: &ServiceSpec) -> Result<ServiceStatus> {
    validate(spec)?;
    Ok(ServiceStatus {
        schema_version: SERVICE_SCHEMA_VERSION,
        service_id: service_id(&spec.name),
        name: spec.name.clone(),
        family: if spec.vip.is_ipv4() { "ipv4" } else { "ipv6" }.into(),
        mode: spec.mode,
        exposure: spec.exposure,
        active_backends: spec.backends.iter().filter(|b| b.enabled).count(),
        maglev_table_size: spec.maglev_table_size.unwrap_or(DEFAULT_MAGLEV_TABLE_SIZE),
        snat_address: spec.snat_address,
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
    let mut frontends = HashSet::new();
    let mut backend_entries = 0usize;
    let mut maglev_entries = 0usize;
    for spec in specs {
        validate(spec)?;
        if !names.insert(spec.name.as_str()) {
            bail!("duplicate service name '{}'", spec.name);
        }
        if !frontends.insert((spec.vip, spec.port, spec.protocol as u8)) {
            bail!(
                "duplicate service frontend {}:{}/ {:?}",
                spec.vip,
                spec.port,
                spec.protocol
            );
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
    stats_from_map(cfg, &map)
}

pub fn host_stats(cfg: &Config) -> Result<HashMap<String, Vec<ServiceCounters>>> {
    let mut out = HashMap::new();
    for iface in &cfg.sandbox.dataplane.service.north_south_interfaces {
        let map = host_pin_dir(cfg, iface).join("maps/fluxvm_sstats");
        if map.exists() {
            out.insert(iface.clone(), stats_from_map(cfg, &map)?);
        }
    }
    Ok(out)
}

fn stats_from_map(cfg: &Config, map: &Path) -> Result<Vec<ServiceCounters>> {
    if !map.exists() {
        return Ok(Vec::new());
    }
    let root = bpftool_json_dump(map)?;
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
    if raw.len() < 56 {
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
    out.dsr_packets = out
        .dsr_packets
        .saturating_add(u64::from_ne_bytes(raw[32..40].try_into().unwrap()));
    out.snat_packets = out
        .snat_packets
        .saturating_add(u64::from_ne_bytes(raw[40..48].try_into().unwrap()));
    out.xdp_packets = out
        .xdp_packets
        .saturating_add(u64::from_ne_bytes(raw[48..56].try_into().unwrap()));
}

/// Ensure the east-west service program/maps exist on one VM edge.
pub fn ensure_for_vm(cfg: &Config, id: Uuid, iface: &str) -> Result<bool> {
    let specs: Vec<ServiceSpec> = list(cfg)?
        .into_iter()
        .filter(|s| s.exposure.east_west())
        .collect();
    if specs.is_empty() {
        remove_for_vm(cfg, id, iface);
        return Ok(false);
    }
    if cfg.sandbox.dataplane.mode == DataplaneMode::Legacy {
        bail!("FluxVM services require sandbox.dataplane.mode=ebpf or cilium");
    }
    ensure_tc_instance(
        cfg,
        &specs,
        &service_pin_dir(cfg, id),
        iface,
        &vm_service_marker(id),
    )
}

/// Recompile the catalog to every known VM edge and every configured
/// north-south uplink. This is deliberately synchronous: a service write is
/// successful only after all local kernel maps are committed or an error is
/// returned while update guards stay fail-closed.
pub fn sync_all(cfg: &Config) -> Result<usize> {
    let mut synced = 0usize;
    let root = meta_root();
    if root.exists() {
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
    }
    sync_host(cfg)?;
    Ok(synced)
}

fn ensure_tc_instance(
    cfg: &Config,
    specs: &[ServiceSpec],
    root: &Path,
    iface: &str,
    marker: &Path,
) -> Result<bool> {
    let desired_fingerprint = catalog_fingerprint(specs)?;
    let object = service_bpf_object(cfg);
    if !object.exists() {
        bail!(
            "FluxVM service eBPF object does not exist at {}",
            object.display()
        );
    }
    require_bpftool()?;
    require_tc()?;

    let prog_dir = root.join("progs");
    let map_dir = root.join("maps");
    fs::create_dir_all(&prog_dir)?;
    fs::create_dir_all(&map_dir)?;
    let prog = prog_dir.join("fvm_svc_vm");
    let current_fingerprint = fs::read_to_string(marker)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());

    let mut rebuilt = false;
    if !prog.exists() {
        let _ = fs::remove_dir_all(root);
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
        rebuilt = true;
    }

    if rebuilt || current_fingerprint != Some(desired_fingerprint) {
        populate_maps(&map_dir, specs)?;
        if let Some(parent) = marker.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(marker, desired_fingerprint.to_string())?;
        rebuilt = true;
    }

    let reverse_prog = prog_dir.join("fvm_svc_rev");
    ensure_clsact(iface)?;
    attach_service_filters(iface, &prog, &reverse_prog)?;
    Ok(rebuilt)
}

fn sync_host(cfg: &Config) -> Result<()> {
    let all = list(cfg)?;
    let specs: Vec<ServiceSpec> = all
        .into_iter()
        .filter(|s| s.exposure.north_south())
        .collect();
    let svc_cfg = &cfg.sandbox.dataplane.service;

    if svc_cfg.xdp_acceleration && cfg.sandbox.dataplane.mode == DataplaneMode::Cilium {
        bail!(
            "service XDP acceleration cannot attach in dataplane.mode=cilium; disable XDP or let Cilium own the physical-NIC XDP hook"
        );
    }

    for iface in &svc_cfg.north_south_interfaces {
        if iface.is_empty() || iface.len() > 15 {
            bail!("north-south interface name {iface:?} must contain 1..=15 characters");
        }
        let root = host_pin_dir(cfg, iface);
        let marker = host_marker(iface);
        if specs.is_empty() {
            remove_host_instance(cfg, iface)?;
            continue;
        }

        let desired = catalog_fingerprint(&specs)?;
        let tc_prog_dir = root.join("progs");
        let map_dir = root.join("maps");
        fs::create_dir_all(&tc_prog_dir)?;
        fs::create_dir_all(&map_dir)?;
        let host_prog = tc_prog_dir.join("fvm_svc_host");
        let current = fs::read_to_string(&marker)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok());

        if !host_prog.exists() {
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&tc_prog_dir)?;
            fs::create_dir_all(&map_dir)?;
            run(
                "bpftool",
                &[
                    "prog".into(),
                    "loadall".into(),
                    service_bpf_object(cfg).display().to_string(),
                    tc_prog_dir.display().to_string(),
                    "type".into(),
                    "classifier".into(),
                    "pinmaps".into(),
                    map_dir.display().to_string(),
                ],
            )?;
        }
        if current != Some(desired) {
            populate_maps(&map_dir, &specs)?;
            if let Some(parent) = marker.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&marker, desired.to_string())?;
        }
        let reverse_prog = tc_prog_dir.join("fvm_svc_rev");
        ensure_clsact(iface)?;
        attach_service_filters(iface, &host_prog, &reverse_prog)?;

        if svc_cfg.xdp_acceleration {
            ensure_host_xdp(cfg, iface, &root, &map_dir)?;
        } else {
            detach_owned_xdp(cfg, iface, &root)?;
        }
    }
    Ok(())
}

fn ensure_host_xdp(cfg: &Config, iface: &str, root: &Path, map_dir: &Path) -> Result<()> {
    require_bpftool()?;
    let object = &cfg.sandbox.dataplane.service.xdp_object;
    if !object.exists() {
        bail!("FluxVM service XDP object does not exist at {}", object.display());
    }
    let xdp_dir = root.join("xdp");
    fs::create_dir_all(&xdp_dir)?;
    let xdp_pin = xdp_dir.join("fvm_svc_xdp");
    if !xdp_pin.exists() {
        let mut args = vec![
            "prog".into(),
            "load".into(),
            object.display().to_string(),
            xdp_pin.display().to_string(),
            "type".into(),
            "xdp".into(),
        ];
        for name in [
            "fluxvm_svc4",
            "fluxvm_svc6",
            "fluxvm_sguard",
            "fluxvm_backend4",
            "fluxvm_backend6",
            "fluxvm_maglev",
            // Keep LRU reverse-NAT state across catalog updates so in-flight
            // replies can still be restored. Frontend/backend/Maglev/SNAT
            // intent is replaced under the fail-closed guard.
            "fluxvm_snat4",
            "fluxvm_snat6",
            "fluxvm_sstats",
        ] {
            args.extend([
                "map".into(),
                "name".into(),
                name.into(),
                "pinned".into(),
                map_dir.join(name).display().to_string(),
            ]);
        }
        run("bpftool", &args).context("loading FluxVM XDP service program with shared maps")?;
    }

    let owned = pinned_program_id(&xdp_pin)?;
    match current_xdp_program_id(iface)? {
        Some(current) if current == owned => Ok(()),
        Some(current) => bail!(
            "interface {iface} already has XDP program id {current}; refusing to replace it with FluxVM id {owned}"
        ),
        None => run(
            "bpftool",
            &[
                "net".into(),
                "attach".into(),
                "xdp".into(),
                "pinned".into(),
                xdp_pin.display().to_string(),
                "dev".into(),
                iface.into(),
            ],
        ),
    }
}

fn detach_owned_xdp(cfg: &Config, iface: &str, root: &Path) -> Result<()> {
    let pin = root.join("xdp/fvm_svc_xdp");
    if !pin.exists() {
        return Ok(());
    }
    let owned = pinned_program_id(&pin).ok();
    let current = current_xdp_program_id(iface).ok().flatten();
    if owned.is_some() && owned == current {
        let _ = run(
            "bpftool",
            &[
                "net".into(),
                "detach".into(),
                "xdp".into(),
                "dev".into(),
                iface.into(),
            ],
        );
    }
    let _ = fs::remove_file(pin);
    let _ = cfg; // cfg kept in signature for symmetric cleanup API.
    Ok(())
}

pub fn host_status(cfg: &Config) -> Result<HostServiceStatus> {
    let svc = &cfg.sandbox.dataplane.service;
    let interfaces = svc
        .north_south_interfaces
        .iter()
        .map(|iface| {
            let root = host_pin_dir(cfg, iface);
            HostInterfaceStatus {
                interface: iface.clone(),
                tc_program_pinned: root.join("progs/fvm_svc_host").exists(),
                xdp_requested: svc.xdp_acceleration,
                xdp_program_pinned: root.join("xdp/fvm_svc_xdp").exists(),
                pin_dir: root.display().to_string(),
            }
        })
        .collect();
    Ok(HostServiceStatus {
        schema_version: SERVICE_SCHEMA_VERSION,
        north_south_interfaces: svc.north_south_interfaces.clone(),
        xdp_acceleration: svc.xdp_acceleration,
        interfaces,
    })
}

pub fn remove_for_vm_best_effort(id: Uuid, iface: &str) {
    let _ = run(
        "tc",
        &[
            "filter".into(), "del".into(), "dev".into(), iface.into(),
            "ingress".into(), "pref".into(), SERVICE_TC_PRIORITY.into(),
            "handle".into(), SERVICE_TC_HANDLE.into(), "bpf".into(),
        ],
    );
    let _ = run(
        "tc",
        &[
            "filter".into(), "del".into(), "dev".into(), iface.into(),
            "egress".into(), "pref".into(), SERVICE_TC_PRIORITY.into(),
            "handle".into(), SERVICE_TC_HANDLE.into(), "bpf".into(),
        ],
    );
    let mut roots = vec![PathBuf::from("/sys/fs/bpf/fluxvm")];
    if let Ok(root) = std::env::var("FLUXVM_BPF_PIN_ROOT") {
        let root = PathBuf::from(root);
        if !roots.contains(&root) { roots.push(root); }
    }
    for root in roots {
        let pin = root.join("vms").join(id.simple().to_string()).join("service");
        if pin.exists() { let _ = fs::remove_dir_all(pin); }
    }
    let _ = fs::remove_file(vm_service_marker(id));
}

pub fn remove_for_vm(cfg: &Config, id: Uuid, iface: &str) {
    let _ = run(
        "tc",
        &[
            "filter".into(),
            "del".into(),
            "dev".into(),
            iface.into(),
            "ingress".into(),
            "pref".into(),
            SERVICE_TC_PRIORITY.into(),
            "handle".into(),
            SERVICE_TC_HANDLE.into(),
            "bpf".into(),
        ],
    );
    let _ = run(
        "tc",
        &[
            "filter".into(),
            "del".into(),
            "dev".into(),
            iface.into(),
            "egress".into(),
            "pref".into(),
            SERVICE_TC_PRIORITY.into(),
            "handle".into(),
            SERVICE_TC_HANDLE.into(),
            "bpf".into(),
        ],
    );
    let root = service_pin_dir(cfg, id);
    if root.exists() {
        let _ = fs::remove_dir_all(root);
    }
    let _ = fs::remove_file(vm_service_marker(id));
}

fn remove_host_instance(cfg: &Config, iface: &str) -> Result<()> {
    let root = host_pin_dir(cfg, iface);
    detach_owned_xdp(cfg, iface, &root)?;
    let _ = run(
        "tc",
        &[
            "filter".into(),
            "del".into(),
            "dev".into(),
            iface.into(),
            "ingress".into(),
            "pref".into(),
            SERVICE_TC_PRIORITY.into(),
            "handle".into(),
            SERVICE_TC_HANDLE.into(),
            "bpf".into(),
        ],
    );
    let _ = run(
        "tc",
        &[
            "filter".into(),
            "del".into(),
            "dev".into(),
            iface.into(),
            "egress".into(),
            "pref".into(),
            SERVICE_TC_PRIORITY.into(),
            "handle".into(),
            SERVICE_TC_HANDLE.into(),
            "bpf".into(),
        ],
    );
    if root.exists() {
        let _ = fs::remove_dir_all(root);
    }
    let _ = fs::remove_file(host_marker(iface));
    Ok(())
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

fn host_pin_dir(cfg: &Config, iface: &str) -> PathBuf {
    cfg.sandbox
        .dataplane
        .pin_root
        .join("service-host")
        .join(iface)
}

fn meta_root() -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root).join("vms");
    }
    PathBuf::from("/run/fluxvm/ebpf/vms")
}

fn service_meta_root() -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root).join("service");
    }
    PathBuf::from("/run/fluxvm/ebpf/service")
}

fn vm_service_marker(id: Uuid) -> PathBuf {
    meta_root()
        .join(id.simple().to_string())
        .join("service_fingerprint")
}

fn host_marker(iface: &str) -> PathBuf {
    service_meta_root().join(format!("host-{iface}.fingerprint"))
}

fn populate_maps(map_dir: &Path, specs: &[ServiceSpec]) -> Result<()> {
    let guard = map_dir.join("fluxvm_sguard");
    map_update(&guard, &0u32.to_ne_bytes(), &1u32.to_ne_bytes())?;

    let update = (|| -> Result<()> {
        for map in [
            "fluxvm_svc4",
            "fluxvm_svc6",
            "fluxvm_backend4",
            "fluxvm_backend6",
            "fluxvm_maglev",
            // Keep LRU reverse-NAT state across catalog updates so in-flight
            // replies can still be restored. Frontend/backend/Maglev/SNAT
            // intent is replaced under the fail-closed guard.
            "fluxvm_snat4",
            "fluxvm_snat6",
        ] {
            clear_map(&map_dir.join(map))?;
        }

        for spec in specs {
            let sid = service_id(&spec.name);
            let table = maglev_table(spec)?;
            write_service(map_dir, spec, sid, table.len() as u32)?;
            write_backends(map_dir, spec, sid)?;
            write_snat(map_dir, spec, sid)?;
            for (slot, backend_id) in table.into_iter().enumerate() {
                let mut key = Vec::with_capacity(8);
                key.extend_from_slice(&sid.to_ne_bytes());
                key.extend_from_slice(&(slot as u32).to_ne_bytes());
                map_update(
                    &map_dir.join("fluxvm_maglev"),
                    &key,
                    &backend_id.to_ne_bytes(),
                )?;
            }
        }
        Ok(())
    })();

    update?;
    map_update(&guard, &0u32.to_ne_bytes(), &0u32.to_ne_bytes())?;
    Ok(())
}

fn write_service(map_dir: &Path, spec: &ServiceSpec, sid: u32, table_size: u32) -> Result<()> {
    let mut value = Vec::with_capacity(12);
    value.extend_from_slice(&sid.to_ne_bytes());
    value.extend_from_slice(&table_size.to_ne_bytes());
    value.push(spec.mode.wire());
    value.push(0);
    value.extend_from_slice(&0u16.to_ne_bytes());

    match spec.vip {
        IpAddr::V4(ip) => {
            let mut key = Vec::with_capacity(8);
            key.extend_from_slice(&ip.octets());
            key.extend_from_slice(&spec.port.to_ne_bytes());
            key.push(spec.protocol.ip_proto());
            key.push(0);
            map_update(&map_dir.join("fluxvm_svc4"), &key, &value)
        }
        IpAddr::V6(ip) => {
            let mut key = Vec::with_capacity(20);
            key.extend_from_slice(&ip.octets());
            key.extend_from_slice(&spec.port.to_ne_bytes());
            key.push(spec.protocol.ip_proto());
            key.push(0);
            map_update(&map_dir.join("fluxvm_svc6"), &key, &value)
        }
    }
}

fn write_backends(map_dir: &Path, spec: &ServiceSpec, sid: u32) -> Result<()> {
    for (idx, backend) in spec.backends.iter().enumerate() {
        if !backend.enabled {
            continue;
        }
        let mut key = Vec::with_capacity(8);
        key.extend_from_slice(&sid.to_ne_bytes());
        key.extend_from_slice(&(idx as u32).to_ne_bytes());
        match backend.address {
            IpAddr::V4(ip) => {
                let mut value = Vec::with_capacity(8);
                value.extend_from_slice(&ip.octets());
                value.extend_from_slice(&backend.port.to_ne_bytes());
                value.extend_from_slice(&BACKEND_ENABLED.to_ne_bytes());
                map_update(&map_dir.join("fluxvm_backend4"), &key, &value)?;
            }
            IpAddr::V6(ip) => {
                let mut value = Vec::with_capacity(20);
                value.extend_from_slice(&ip.octets());
                value.extend_from_slice(&backend.port.to_ne_bytes());
                value.extend_from_slice(&BACKEND_ENABLED.to_ne_bytes());
                map_update(&map_dir.join("fluxvm_backend6"), &key, &value)?;
            }
        }
    }
    Ok(())
}

fn write_snat(map_dir: &Path, spec: &ServiceSpec, sid: u32) -> Result<()> {
    let Some(snat) = spec.snat_address else {
        return Ok(());
    };
    let key = sid.to_ne_bytes();
    match snat {
        IpAddr::V4(ip) => {
            let mut value = Vec::with_capacity(8);
            value.extend_from_slice(&ip.octets());
            value.extend_from_slice(&1u32.to_ne_bytes());
            map_update(&map_dir.join("fluxvm_snat4"), &key, &value)
        }
        IpAddr::V6(ip) => {
            let mut value = Vec::with_capacity(20);
            value.extend_from_slice(&ip.octets());
            value.extend_from_slice(&1u32.to_ne_bytes());
            map_update(&map_dir.join("fluxvm_snat6"), &key, &value)
        }
    }
}

fn attach_service_filters(iface: &str, ingress_prog: &Path, reverse_prog: &Path) -> Result<()> {
    // `replace` is scoped to FluxVM's dedicated service priority/handle.
    // Ingress creates service/NAT state; egress consumes that same map state
    // to restore replies before they leave the client/uplink edge.
    for (direction, prog) in [("ingress", ingress_prog), ("egress", reverse_prog)] {
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
        )?;
    }
    Ok(())
}

fn ensure_clsact(iface: &str) -> Result<()> {
    let show = Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output()?;
    if show.status.success()
        && String::from_utf8_lossy(&show.stdout)
            .split_whitespace()
            .any(|token| token == "clsact")
    {
        return Ok(());
    }
    let out = Command::new("tc")
        .args(["qdisc", "add", "dev", iface, "clsact"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Race: another FluxVM attach created clsact between show and add.
    if stderr.contains("File exists") || stderr.contains("Exclusivity flag on") {
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
    if !map.exists() {
        bail!("FluxVM service map is not pinned at {}", map.display());
    }
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

fn require_bpftool() -> Result<()> {
    require_version("bpftool", &["version"])
}

fn require_tc() -> Result<()> {
    require_version("tc", &["-V"])
}

fn require_version(name: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(name)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("{name} is required for the FluxVM service dataplane"))?;
    if out.success() {
        Ok(())
    } else {
        bail!("{} {} exited with {out}", name, args.join(" "))
    }
}

fn pinned_program_id(pin: &Path) -> Result<u32> {
    let out = Command::new("bpftool")
        .args(["-j", "prog", "show", "pinned"])
        .arg(pin)
        .output()?;
    if !out.status.success() {
        bail!("unable to inspect pinned BPF program {}", pin.display());
    }
    let value: Value = serde_json::from_slice(&out.stdout)?;
    let object = value.as_array().and_then(|a| a.first()).unwrap_or(&value);
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .context("bpftool pinned program JSON has no id")?;
    u32::try_from(id).context("BPF program id does not fit u32")
}

fn current_xdp_program_id(iface: &str) -> Result<Option<u32>> {
    // Use bpftool's machine-readable output; its human-readable `net show`
    // format is explicitly not a stable API. Current bpftool returns an array
    // whose objects contain an `xdp` array with devname/mode/id records.
    let out = Command::new("bpftool")
        .args(["-j", "net", "show", "dev", iface])
        .output()?;
    if !out.status.success() {
        bail!(
            "bpftool -j net show dev {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let root: Value = serde_json::from_slice(&out.stdout)
        .context("parsing bpftool network attachment JSON")?;
    let Some(objects) = root.as_array() else {
        bail!("bpftool network attachment JSON must be an array");
    };
    for object in objects {
        let Some(entries) = object.get("xdp").and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            if entry.get("devname").and_then(Value::as_str) != Some(iface) {
                continue;
            }
            if let Some(id) = entry.get("id").and_then(Value::as_u64) {
                return Ok(Some(u32::try_from(id).context("XDP program id does not fit u32")?));
            }
        }
    }
    Ok(None)
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

    fn v4_spec() -> ServiceSpec {
        ServiceSpec {
            name: "payments".into(),
            vip: "10.40.0.100".parse().unwrap(),
            port: 443,
            protocol: ServiceProtocol::Tcp,
            algorithm: ServiceAlgorithm::Maglev,
            mode: ServiceMode::Nat,
            exposure: ServiceExposure::EastWest,
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
            snat_address: None,
        }
    }

    #[test]
    fn maglev_is_deterministic_and_complete() {
        let a = maglev_table(&v4_spec()).unwrap();
        let b = maglev_table(&v4_spec()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 251);
        assert!(a.iter().all(|id| *id <= 2));
        for id in 0..=2u32 {
            assert!(a.contains(&id));
        }
    }

    #[test]
    fn weights_change_distribution() {
        let mut s = v4_spec();
        s.backends[0].weight = 4;
        let table = maglev_table(&s).unwrap();
        assert!(table.iter().filter(|id| **id == 0).count() > 100);
    }

    #[test]
    fn ipv6_nat_is_valid() {
        let mut s = v4_spec();
        s.vip = "fd00:40::100".parse().unwrap();
        for (idx, backend) in s.backends.iter_mut().enumerate() {
            backend.address = format!("fd00:40:1::{}", idx + 1).parse().unwrap();
        }
        assert!(validate(&s).is_ok());
    }

    #[test]
    fn north_south_nat_requires_snat() {
        let mut s = v4_spec();
        s.exposure = ServiceExposure::NorthSouth;
        assert!(validate(&s).is_err());
        s.snat_address = Some("192.0.2.10".parse().unwrap());
        assert!(validate(&s).is_ok());
    }

    #[test]
    fn dsr_requires_same_port_and_no_snat() {
        let mut s = v4_spec();
        s.mode = ServiceMode::Dsr;
        assert!(validate(&s).is_err());
        for backend in &mut s.backends {
            backend.port = 443;
        }
        assert!(validate(&s).is_ok());
        s.snat_address = Some("192.0.2.10".parse().unwrap());
        assert!(validate(&s).is_err());
    }
}
