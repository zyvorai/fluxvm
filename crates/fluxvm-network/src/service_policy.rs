// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Service Fabric v6 identity/L7 policy compiler.
//!
//! Fabric owns distributed policy intent. FluxVM stores that intent locally,
//! resolves SecurityIdentity IDs through the existing ipcache and compiles
//! only FluxVM-owned BPF maps. Envoy owns HTTP/gRPC parsing; the eBPF path
//! only performs an optional transparent redirect to an operator-provided
//! proxy interface.

use crate::{ipcache, service};
use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
};

pub const SERVICE_POLICY_SCHEMA_VERSION: u32 = 1;
pub const SERVICE_PROGRAM_GENERATION: u32 = 6;
const MAX_IDENTITIES: usize = 2048;
const MAX_L7_ITEMS: usize = 256;

const POLICY_F_ENABLED: u32 = 1 << 0;
const POLICY_F_DEFAULT_DENY: u32 = 1 << 1;
const POLICY_F_AUDIT: u32 = 1 << 2;
const POLICY_F_L7_OBSERVE: u32 = 1 << 3;
const POLICY_F_L7_ENFORCE: u32 = 1 << 4;
const VERDICT_ALLOW: u32 = 1;
const VERDICT_DENY: u32 = 2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDefaultAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum L7Protocol {
    Http,
    Grpc,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum L7Mode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct L7Policy {
    pub protocol: L7Protocol,
    pub mode: L7Mode,
    #[serde(default)]
    pub proxy_ifindex: u32,
    #[serde(default)]
    pub bypass_mark: u32,
    #[serde(default)]
    pub authorities: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServicePolicySpec {
    pub service: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub default_action: PolicyDefaultAction,
    #[serde(default)]
    pub allow_identities: Vec<u32>,
    #[serde(default)]
    pub deny_identities: Vec<u32>,
    #[serde(default)]
    pub audit_only: bool,
    #[serde(default)]
    pub l7: Option<L7Policy>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServicePolicyStatus {
    pub schema_version: u32,
    pub program_generation: u32,
    pub service: String,
    pub service_id: u32,
    pub enabled: bool,
    pub compiled_ipv4: usize,
    pub compiled_ipv6: usize,
    pub unresolved_identities: Vec<u32>,
    pub l7_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvoyRedirectContract {
    pub schema_version: u32,
    pub service: String,
    pub enabled: bool,
    pub protocol: Option<L7Protocol>,
    pub mode: Option<L7Mode>,
    pub proxy_ifindex: u32,
    pub bypass_mark: u32,
    pub preserve_original_destination: bool,
    pub authorities: Vec<String>,
    pub path_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct CompiledPolicy {
    service_values: BTreeMap<Vec<u8>, Vec<u8>>,
    ipv4_values: BTreeMap<Vec<u8>, Vec<u8>>,
    ipv6_values: BTreeMap<Vec<u8>, Vec<u8>>,
    statuses: BTreeMap<String, ServicePolicyStatus>,
}

fn catalog_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-service-policies.json")
}

fn load_catalog(cfg: &Config) -> Result<Vec<ServicePolicySpec>> {
    let path = catalog_path(cfg);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut specs: Vec<ServicePolicySpec> = serde_json::from_slice(&fs::read(&path)?)
        .with_context(|| format!("parsing service policy catalog {}", path.display()))?;
    for spec in &specs {
        validate_syntax(spec)?;
    }
    specs.sort_by(|a, b| a.service.cmp(&b.service));
    Ok(specs)
}

fn save_catalog(cfg: &Config, specs: &[ServicePolicySpec]) -> Result<()> {
    let path = catalog_path(cfg);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(specs)?)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn list(cfg: &Config) -> Result<Vec<ServicePolicySpec>> {
    load_catalog(cfg)
}

pub fn get(cfg: &Config, name: &str) -> Result<Option<ServicePolicySpec>> {
    Ok(load_catalog(cfg)?.into_iter().find(|p| p.service == name))
}

pub fn validate_syntax(spec: &ServicePolicySpec) -> Result<()> {
    if spec.service.is_empty() || spec.service.len() > 63 {
        bail!("service policy name must contain 1..=63 characters");
    }
    if spec.allow_identities.len() > MAX_IDENTITIES || spec.deny_identities.len() > MAX_IDENTITIES {
        bail!("service policy identity lists are bounded to {MAX_IDENTITIES} entries each");
    }
    let allow: HashSet<u32> = spec.allow_identities.iter().copied().collect();
    let deny: HashSet<u32> = spec.deny_identities.iter().copied().collect();
    if allow.len() != spec.allow_identities.len() {
        bail!("duplicate allow identity");
    }
    if deny.len() != spec.deny_identities.len() {
        bail!("duplicate deny identity");
    }
    if allow.iter().any(|id| deny.contains(id)) {
        bail!("an identity cannot be both allowed and denied");
    }
    if allow.contains(&0) || deny.contains(&0) {
        bail!("identity 0 is reserved/unresolved");
    }
    if let Some(l7) = &spec.l7 {
        if l7.authorities.len() > MAX_L7_ITEMS || l7.path_prefixes.len() > MAX_L7_ITEMS {
            bail!("L7 authorities/path_prefixes are bounded to {MAX_L7_ITEMS} entries each");
        }
        for authority in &l7.authorities {
            if authority.is_empty() || authority.len() > 253 {
                bail!("invalid L7 authority length");
            }
        }
        for prefix in &l7.path_prefixes {
            if prefix.is_empty() || prefix.len() > 1024 || !prefix.starts_with('/') {
                bail!("L7 path prefixes must start with '/' and be <=1024 bytes");
            }
        }
        if matches!(l7.mode, L7Mode::Enforce) {
            if l7.proxy_ifindex == 0 {
                bail!("L7 enforce requires proxy_ifindex > 0");
            }
            if l7.bypass_mark == 0 {
                bail!("L7 enforce requires a non-zero bypass_mark");
            }
        }
    }
    Ok(())
}

fn validate_against_service(cfg: &Config, spec: &ServicePolicySpec) -> Result<()> {
    validate_syntax(spec)?;
    let svc = service::get(cfg, &spec.service)?
        .with_context(|| format!("service {:?} not found", spec.service))?;
    if spec.l7.is_some() {
        if svc.protocol != service::ServiceProtocol::Tcp {
            bail!("HTTP/gRPC redirect is only valid for TCP services");
        }
        if svc.mode != service::ServiceMode::Nat {
            bail!("HTTP/gRPC redirect requires NAT service mode");
        }
    }
    Ok(())
}

pub fn upsert(cfg: &Config, spec: ServicePolicySpec) -> Result<ServicePolicyStatus> {
    validate_against_service(cfg, &spec)?;
    let previous = load_catalog(cfg)?;
    let mut desired = previous.clone();
    if let Some(old) = desired.iter_mut().find(|p| p.service == spec.service) {
        *old = spec.clone();
    } else {
        desired.push(spec.clone());
    }
    desired.sort_by(|a, b| a.service.cmp(&b.service));
    save_catalog(cfg, &desired)?;
    if let Err(e) = reconcile(cfg) {
        save_catalog(cfg, &previous)?;
        let _ = reconcile(cfg);
        return Err(e).context("service policy apply failed; catalog restored");
    }
    status(cfg, &spec.service)?.context("policy disappeared after successful apply")
}

pub fn delete(cfg: &Config, name: &str) -> Result<bool> {
    let previous = load_catalog(cfg)?;
    let mut desired = previous.clone();
    let before = desired.len();
    desired.retain(|p| p.service != name);
    if desired.len() == before {
        return Ok(false);
    }
    save_catalog(cfg, &desired)?;
    if let Err(e) = reconcile(cfg) {
        save_catalog(cfg, &previous)?;
        let _ = reconcile(cfg);
        return Err(e).context("service policy delete failed; catalog restored");
    }
    Ok(true)
}

pub fn delete_best_effort(cfg: &Config, name: &str) {
    if let Ok(mut desired) = load_catalog(cfg) {
        let before = desired.len();
        desired.retain(|p| p.service != name);
        if desired.len() != before {
            let _ = save_catalog(cfg, &desired);
            let _ = reconcile(cfg);
        }
    }
}

pub fn status(cfg: &Config, name: &str) -> Result<Option<ServicePolicyStatus>> {
    let compiled = compile(cfg, &load_catalog(cfg)?)?;
    Ok(compiled.statuses.get(name).cloned())
}

pub fn statuses(cfg: &Config) -> Result<Vec<ServicePolicyStatus>> {
    let compiled = compile(cfg, &load_catalog(cfg)?)?;
    Ok(compiled.statuses.into_values().collect())
}

pub fn envoy_contract(cfg: &Config, name: &str) -> Result<EnvoyRedirectContract> {
    let policy = get(cfg, name)?.with_context(|| format!("service policy {name:?} not found"))?;
    let l7 = policy.l7.clone();
    Ok(EnvoyRedirectContract {
        schema_version: SERVICE_POLICY_SCHEMA_VERSION,
        service: name.to_string(),
        enabled: policy.enabled && l7.is_some(),
        protocol: l7.as_ref().map(|v| v.protocol),
        mode: l7.as_ref().map(|v| v.mode),
        proxy_ifindex: l7.as_ref().map(|v| v.proxy_ifindex).unwrap_or(0),
        bypass_mark: l7.as_ref().map(|v| v.bypass_mark).unwrap_or(0),
        preserve_original_destination: true,
        authorities: l7
            .as_ref()
            .map(|v| v.authorities.clone())
            .unwrap_or_default(),
        path_prefixes: l7.map(|v| v.path_prefixes).unwrap_or_default(),
    })
}

/// True when any durable policy currently requires enforcement. Service
/// program reloads use this to keep a newly-created v6 guard closed until the
/// additive identity maps have been restored.
pub fn has_enabled_policies(cfg: &Config) -> Result<bool> {
    Ok(load_catalog(cfg)?.iter().any(|spec| spec.enabled))
}

pub fn reconcile(cfg: &Config) -> Result<Vec<ServicePolicyStatus>> {
    // `service::sync_all` performs the generation-6 reload and invokes the
    // low-level policy-map restore before newly loaded programs are allowed to
    // run with an open guard. This avoids a fail-open v5 -> v6 upgrade window.
    service::sync_all(cfg)?;
    statuses(cfg)
}

/// Reconcile policy maps after Service Fabric has synchronized its base maps.
/// This function must never call `service::sync_all`, otherwise the modules
/// recurse. Orphan policies are skipped here only to allow the transactional
/// service-delete path to remove the service first and its policy immediately
/// afterward; direct policy writes still validate that the service exists.
pub(crate) fn reconcile_after_service_sync(cfg: &Config) -> Result<Vec<ServicePolicyStatus>> {
    let specs = load_catalog(cfg)?;
    let mut live = Vec::with_capacity(specs.len());
    for spec in specs {
        if service::get(cfg, &spec.service)?.is_none() {
            continue;
        }
        validate_against_service(cfg, &spec)?;
        live.push(spec);
    }
    let compiled = compile(cfg, &live)?;
    let dirs = service_map_dirs(cfg);
    for dir in dirs {
        if !dir.join("fluxvm_spol").exists() {
            continue;
        }
        set_guard(&dir, true)?;
        let applied = (|| -> Result<()> {
            replace_map(&dir.join("fluxvm_spol"), &compiled.service_values)?;
            replace_map(&dir.join("fluxvm_sid4"), &compiled.ipv4_values)?;
            replace_map(&dir.join("fluxvm_sid6"), &compiled.ipv6_values)?;
            Ok(())
        })();
        if let Err(e) = applied {
            // Keep guard closed: a partially compiled identity policy must not
            // become a fail-open dataplane.
            return Err(e)
                .with_context(|| format!("reconciling service policy maps in {}", dir.display()));
        }
        set_guard(&dir, false)?;
    }
    Ok(compiled.statuses.into_values().collect())
}

fn compile(cfg: &Config, specs: &[ServicePolicySpec]) -> Result<CompiledPolicy> {
    let entries = ipcache::list(cfg)?;
    let mut out = CompiledPolicy::default();
    for spec in specs {
        let svc = service::get(cfg, &spec.service)?
            .with_context(|| format!("service {:?} not found", spec.service))?;
        let sid = service::service_id(&spec.service);
        let allow: BTreeSet<u32> = spec.allow_identities.iter().copied().collect();
        let deny: BTreeSet<u32> = spec.deny_identities.iter().copied().collect();
        let mut resolved = BTreeSet::new();
        let mut v4 = 0usize;
        let mut v6 = 0usize;

        if spec.enabled {
            let mut flags = POLICY_F_ENABLED;
            if matches!(spec.default_action, PolicyDefaultAction::Deny) {
                flags |= POLICY_F_DEFAULT_DENY;
            }
            if spec.audit_only {
                flags |= POLICY_F_AUDIT;
            }
            let mut proxy_ifindex = 0u32;
            let mut bypass_mark = 0u32;
            if let Some(l7) = &spec.l7 {
                match l7.mode {
                    L7Mode::Observe => flags |= POLICY_F_L7_OBSERVE,
                    L7Mode::Enforce => flags |= POLICY_F_L7_ENFORCE,
                }
                proxy_ifindex = l7.proxy_ifindex;
                bypass_mark = l7.bypass_mark;
            }
            let mut value = Vec::with_capacity(16);
            value.extend_from_slice(&flags.to_ne_bytes());
            value.extend_from_slice(&proxy_ifindex.to_ne_bytes());
            value.extend_from_slice(&bypass_mark.to_ne_bytes());
            value.extend_from_slice(&0u32.to_ne_bytes());
            out.service_values.insert(sid.to_ne_bytes().to_vec(), value);

            for entry in &entries {
                if !allow.contains(&entry.identity) && !deny.contains(&entry.identity) {
                    continue;
                }
                let ip: IpAddr = entry
                    .ip
                    .parse()
                    .with_context(|| format!("invalid ipcache address {:?}", entry.ip))?;
                resolved.insert(entry.identity);
                let verdict = if deny.contains(&entry.identity) {
                    VERDICT_DENY
                } else {
                    VERDICT_ALLOW
                };
                let mut key = sid.to_ne_bytes().to_vec();
                match ip {
                    IpAddr::V4(ip) => {
                        key.extend_from_slice(&ip.octets());
                        out.ipv4_values.insert(key, verdict.to_ne_bytes().to_vec());
                        v4 += 1;
                    }
                    IpAddr::V6(ip) => {
                        key.extend_from_slice(&ip.octets());
                        out.ipv6_values.insert(key, verdict.to_ne_bytes().to_vec());
                        v6 += 1;
                    }
                }
            }
        }
        let unresolved: Vec<u32> = allow
            .union(&deny)
            .filter(|id| !resolved.contains(id))
            .copied()
            .collect();
        out.statuses.insert(
            spec.service.clone(),
            ServicePolicyStatus {
                schema_version: SERVICE_POLICY_SCHEMA_VERSION,
                program_generation: SERVICE_PROGRAM_GENERATION,
                service: spec.service.clone(),
                service_id: sid,
                enabled: spec.enabled,
                compiled_ipv4: v4,
                compiled_ipv6: v6,
                unresolved_identities: unresolved,
                l7_ready: spec.enabled
                    && spec
                        .l7
                        .as_ref()
                        .map(|l| !matches!(l.mode, L7Mode::Enforce) || l.proxy_ifindex != 0)
                        .unwrap_or(true),
            },
        );
        let _ = svc; // validation above intentionally binds policy to a real service.
    }
    Ok(out)
}

fn service_map_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let vm_root = cfg.sandbox.dataplane.pin_root.join("vms");
    if let Ok(entries) = fs::read_dir(&vm_root) {
        for entry in entries.flatten() {
            let p = entry.path().join("service/maps");
            if p.is_dir() {
                dirs.push(p);
            }
        }
    }
    for iface in &cfg.sandbox.dataplane.service.north_south_interfaces {
        let p = cfg
            .sandbox
            .dataplane
            .pin_root
            .join("service-host")
            .join(iface)
            .join("maps");
        if p.is_dir() {
            dirs.push(p);
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

fn set_guard(map_dir: &Path, closed: bool) -> Result<()> {
    let map = map_dir.join("fluxvm_sguard");
    let key = 0u32.to_ne_bytes();
    let guard = if closed { 1u32 } else { 0u32 };
    let value = guard.to_ne_bytes();
    bpftool_update(&map, &key, &value)
}

fn replace_map(map: &Path, desired: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<()> {
    if !map.exists() {
        bail!("required v6 policy map {} is not pinned", map.display());
    }
    for key in bpftool_keys(map)? {
        bpftool_delete(map, &key)?;
    }
    for (key, value) in desired {
        bpftool_update(map, key, value)?;
    }
    Ok(())
}

fn bpftool_keys(map: &Path) -> Result<Vec<Vec<u8>>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()
        .with_context(|| format!("running bpftool for {}", map.display()))?;
    if !out.status.success() {
        bail!(
            "bpftool map dump failed for {}: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let root: Value = serde_json::from_slice(&out.stdout)?;
    let mut keys = Vec::new();
    for entry in root
        .as_array()
        .context("bpftool map dump must return an array")?
    {
        keys.push(json_bytes(&entry["key"])?);
    }
    Ok(keys)
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    let arr = v
        .as_array()
        .context("bpftool byte field must be an array")?;
    arr.iter()
        .map(|x| {
            if let Some(n) = x.as_u64() {
                return u8::try_from(n).context("bpftool byte out of range");
            }
            let s = x
                .as_str()
                .context("bpftool byte must be number or hex string")?
                .trim_start_matches("0x");
            u8::from_str_radix(s, 16).context("invalid bpftool hex byte")
        })
        .collect()
}

fn hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bpftool_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut cmd = Command::new("bpftool");
    cmd.args(["map", "update", "pinned"])
        .arg(map)
        .arg("key")
        .arg("hex");
    cmd.args(hex_args(key));
    cmd.args(["value", "hex"]);
    cmd.args(hex_args(value));
    cmd.arg("any");
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "bpftool map update {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

fn bpftool_delete(map: &Path, key: &[u8]) -> Result<()> {
    let mut cmd = Command::new("bpftool");
    cmd.args(["map", "delete", "pinned"])
        .arg(map)
        .arg("key")
        .arg("hex");
    cmd.args(hex_args(key));
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "bpftool map delete {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_identity_overlap() {
        let spec = ServicePolicySpec {
            service: "web".into(),
            enabled: true,
            default_action: PolicyDefaultAction::Deny,
            allow_identities: vec![1001],
            deny_identities: vec![1001],
            audit_only: false,
            l7: None,
        };
        assert!(validate_syntax(&spec).is_err());
    }

    #[test]
    fn enforce_requires_proxy_and_mark() {
        let spec = ServicePolicySpec {
            service: "web".into(),
            enabled: true,
            default_action: PolicyDefaultAction::Allow,
            allow_identities: vec![],
            deny_identities: vec![],
            audit_only: false,
            l7: Some(L7Policy {
                protocol: L7Protocol::Http,
                mode: L7Mode::Enforce,
                proxy_ifindex: 0,
                bypass_mark: 0,
                authorities: vec![],
                path_prefixes: vec![],
            }),
        };
        assert!(validate_syntax(&spec).is_err());
    }
}
