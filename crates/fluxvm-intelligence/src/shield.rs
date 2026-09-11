// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

pub const DEFAULT_SHIELD_PIN_ROOT: &str = "/sys/fs/bpf/fluxvm/shield";
pub const DEFAULT_SHIELD_STATE_ROOT: &str = "/var/lib/fluxvm/xdp-shield";
const DEFAULT_OBJECT: &str = "/usr/lib/fluxvm/bpf/fluxvm_xdp_shield.bpf.o";
const MAX_PPS: u32 = 10_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldPolicy {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub protect_all: bool,
    #[serde(default)]
    pub protected_ips: Vec<String>,
    #[serde(default)]
    pub allow_sources: Vec<String>,
    #[serde(default)]
    pub deny_sources: Vec<String>,
    #[serde(default = "default_syn_pps")]
    pub syn_pps: u32,
    #[serde(default = "default_udp_pps")]
    pub udp_pps: u32,
    #[serde(default = "default_icmp_pps")]
    pub icmp_pps: u32,
    #[serde(default = "default_other_pps")]
    pub other_pps: u32,
    #[serde(default = "default_burst_seconds")]
    pub burst_seconds: u32,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,
    #[serde(default = "default_xdp_mode")]
    pub xdp_mode: String,
}

impl Default for ShieldPolicy {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            protect_all: false,
            protected_ips: Vec::new(),
            allow_sources: Vec::new(),
            deny_sources: Vec::new(),
            syn_pps: default_syn_pps(),
            udp_pps: default_udp_pps(),
            icmp_pps: default_icmp_pps(),
            other_pps: default_other_pps(),
            burst_seconds: default_burst_seconds(),
            sample_rate: default_sample_rate(),
            xdp_mode: default_xdp_mode(),
        }
    }
}
fn default_mode() -> String {
    "audit".into()
}
fn default_xdp_mode() -> String {
    "auto".into()
}
fn default_syn_pps() -> u32 {
    5_000
}
fn default_udp_pps() -> u32 {
    20_000
}
fn default_icmp_pps() -> u32 {
    2_000
}
fn default_other_pps() -> u32 {
    50_000
}
fn default_burst_seconds() -> u32 {
    2
}
fn default_sample_rate() -> u32 {
    1_000
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldState {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub interface: String,
    pub generation: u32,
    pub attach_mode: String,
    pub policy: ShieldPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldReasonStat {
    pub generation: u32,
    pub reason_code: u32,
    pub reason: String,
    pub action_code: u32,
    pub action: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldSnapshot {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub interface: String,
    pub generation: u32,
    pub attached: bool,
    pub owned_program_id: Option<u32>,
    pub policy: ShieldPolicy,
    pub stats: Vec<ShieldReasonStat>,
    pub source_buckets: usize,
}

pub fn apply_policy(
    id: Uuid,
    interface: &str,
    policy: ShieldPolicy,
    pin_root: &Path,
    state_root: &Path,
) -> Result<ShieldState> {
    validate_policy(&policy)?;
    let ifindex = read_ifindex(interface)?;
    let pin_dir = vm_pin_dir(pin_root, id);
    let old = read_state(id, state_root).ok();
    if let Some(ref state) = old {
        if state.interface != interface {
            bail!(
                "shield for {id} is attached to {}; remove it before moving to {interface}",
                state.interface
            );
        }
    }
    let attach_mode = if pin_dir.join("program").exists() {
        old.as_ref()
            .map(|s| s.attach_mode.clone())
            .unwrap_or_else(|| policy.xdp_mode.clone())
    } else {
        attach(interface, &pin_dir, &policy.xdp_mode)?
    };
    let generation = old
        .as_ref()
        .map(|s| next_generation(s.generation))
        .unwrap_or(1);
    populate_generation(&pin_dir, generation, &policy)?;
    publish_config(&pin_dir, generation, ifindex, &policy)?;
    let state = ShieldState {
        schema_version: 1,
        vm_id: id,
        interface: interface.into(),
        generation,
        attach_mode,
        policy,
    };
    write_state(&state, state_root)?;
    if let Some(old) = old {
        cleanup_known_generation(&pin_dir, &old).ok();
    }
    Ok(state)
}

pub fn snapshot(id: Uuid, pin_root: &Path, state_root: &Path) -> Result<ShieldSnapshot> {
    let state = read_state(id, state_root)?;
    let pin_dir = vm_pin_dir(pin_root, id);
    let pin = pin_dir.display().to_string();
    let status = loader_json(&["status", &state.interface, &pin])?;
    let attached = status
        .get("attached")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let owned_program_id = status
        .get("owned_program_id")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .filter(|v| *v != 0);
    let mut stats = read_stats(&pin_dir.join("maps/fluxvm_shield_stats"), state.generation)?;
    stats.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| a.reason_code.cmp(&b.reason_code))
    });
    let source_buckets = bpftool_rows(&pin_dir.join("maps/fluxvm_shield_sources"))
        .map(|v| v.len())
        .unwrap_or(0);
    Ok(ShieldSnapshot {
        schema_version: 1,
        vm_id: id,
        interface: state.interface,
        generation: state.generation,
        attached,
        owned_program_id,
        policy: state.policy,
        stats,
        source_buckets,
    })
}

pub fn remove_policy(id: Uuid, pin_root: &Path, state_root: &Path) -> Result<()> {
    let state = read_state(id, state_root)?;
    let pin_dir = vm_pin_dir(pin_root, id);
    let pin = pin_dir.display().to_string();
    let _ = loader_json(&["detach", &state.interface, &pin])?;
    if pin_dir.exists() {
        fs::remove_dir_all(&pin_dir).with_context(|| format!("removing {}", pin_dir.display()))?;
    }
    let path = state_path(state_root, id);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn stream_events(id: Uuid, pin_root: &Path, seconds: u64, limit: usize) -> Result<()> {
    let map = vm_pin_dir(pin_root, id).join("maps/fluxvm_shield_events");
    if !map.exists() {
        bail!("shield event map missing: {}", map.display());
    }
    let helper = env::var("FLUXVM_SHIELD_EVENTS")
        .unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-shield-events".into());
    let status = Command::new(&helper)
        .arg(&map)
        .arg(seconds.clamp(1, 3600).to_string())
        .arg(limit.clamp(1, 10000).to_string())
        .status()
        .with_context(|| format!("running {helper}"))?;
    if !status.success() {
        bail!("shield event reader exited with {status}");
    }
    Ok(())
}

pub fn prometheus(snapshot: &ShieldSnapshot) -> String {
    let mut out = String::from(
        "# HELP fluxvm_shield_packets_total XDP Shield decisions by reason and action.\n# TYPE fluxvm_shield_packets_total counter\n",
    );
    for s in &snapshot.stats {
        out.push_str(&format!(
            "fluxvm_shield_packets_total{{vm_id=\"{}\",reason=\"{}\",action=\"{}\"}} {}\n",
            snapshot.vm_id, s.reason, s.action, s.packets
        ));
        out.push_str(&format!(
            "fluxvm_shield_bytes_total{{vm_id=\"{}\",reason=\"{}\",action=\"{}\"}} {}\n",
            snapshot.vm_id, s.reason, s.action, s.bytes
        ));
    }
    out.push_str(&format!(
        "fluxvm_shield_source_buckets{{vm_id=\"{}\"}} {}\n",
        snapshot.vm_id, snapshot.source_buckets
    ));
    out
}

pub fn read_state(id: Uuid, state_root: &Path) -> Result<ShieldState> {
    let path = state_path(state_root, id);
    serde_json::from_slice(&fs::read(&path).with_context(|| format!("reading {}", path.display()))?)
        .context("decoding shield state")
}

fn validate_policy(p: &ShieldPolicy) -> Result<()> {
    if p.mode != "audit" && p.mode != "enforce" {
        bail!("mode must be audit|enforce");
    }
    if p.xdp_mode != "auto" && p.xdp_mode != "native" && p.xdp_mode != "generic" {
        bail!("xdp_mode must be auto|native|generic");
    }
    if !p.protect_all && p.protected_ips.is_empty() {
        bail!("protected_ips must be non-empty unless protect_all=true");
    }
    for (name, rate) in [
        ("syn_pps", p.syn_pps),
        ("udp_pps", p.udp_pps),
        ("icmp_pps", p.icmp_pps),
        ("other_pps", p.other_pps),
    ] {
        if rate > MAX_PPS {
            bail!("{name} exceeds safety cap {MAX_PPS}");
        }
    }
    if !(1..=10).contains(&p.burst_seconds) {
        bail!("burst_seconds must be 1..=10");
    }
    if p.sample_rate > 1_000_000 {
        bail!("sample_rate must be <= 1000000");
    }
    for ip in &p.protected_ips {
        ip.parse::<IpAddr>()
            .with_context(|| format!("invalid protected IP {ip}"))?;
    }
    for cidr in p.allow_sources.iter().chain(p.deny_sources.iter()) {
        parse_cidr(cidr)?;
    }
    Ok(())
}

fn next_generation(old: u32) -> u32 {
    let n = old.wrapping_add(1);
    if n == 0 { 1 } else { n }
}
fn read_ifindex(iface: &str) -> Result<u32> {
    fs::read_to_string(Path::new("/sys/class/net").join(iface).join("ifindex"))?
        .trim()
        .parse()
        .context("parsing ifindex")
}
fn vm_pin_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join(id.to_string())
}
fn state_path(root: &Path, id: Uuid) -> PathBuf {
    root.join(format!("{id}.json"))
}
fn helper() -> String {
    env::var("FLUXVM_XDP_SHIELD_LOADER")
        .unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-xdp-shield-loader".into())
}
fn object() -> String {
    env::var("FLUXVM_XDP_SHIELD_OBJECT").unwrap_or_else(|_| DEFAULT_OBJECT.into())
}

fn attach(interface: &str, pin_dir: &Path, mode: &str) -> Result<String> {
    let obj = object();
    let pin = pin_dir.display().to_string();
    let v = loader_json(&["attach", interface, &obj, &pin, mode])?;
    Ok(v.get("mode")
        .and_then(Value::as_str)
        .unwrap_or(mode)
        .to_string())
}
fn loader_json(args: &[&str]) -> Result<Value> {
    let h = helper();
    let out = Command::new(&h)
        .args(args)
        .output()
        .with_context(|| format!("running {h}"))?;
    if !out.status.success() {
        bail!(
            "{h} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("decoding XDP Shield helper JSON")
}

fn populate_generation(pin_dir: &Path, generation: u32, policy: &ShieldPolicy) -> Result<()> {
    let maps = pin_dir.join("maps");
    for ip in &policy.protected_ips {
        match ip.parse::<IpAddr>()? {
            IpAddr::V4(v) => {
                let mut k = generation.to_ne_bytes().to_vec();
                k.extend(v.octets());
                map_update(
                    &maps.join("fluxvm_shield_protected4"),
                    &k,
                    &1u32.to_ne_bytes(),
                )?;
            }
            IpAddr::V6(v) => {
                let mut k = generation.to_ne_bytes().to_vec();
                k.extend(v.octets());
                map_update(
                    &maps.join("fluxvm_shield_protected6"),
                    &k,
                    &1u32.to_ne_bytes(),
                )?;
            }
        }
    }
    for (map4, map6, items) in [
        (
            "fluxvm_shield_allow4",
            "fluxvm_shield_allow6",
            &policy.allow_sources,
        ),
        (
            "fluxvm_shield_deny4",
            "fluxvm_shield_deny6",
            &policy.deny_sources,
        ),
    ] {
        for item in items {
            let (ip, prefix) = parse_cidr(item)?;
            match ip {
                IpAddr::V4(v) => {
                    let mut k = (32u32 + prefix as u32).to_ne_bytes().to_vec();
                    k.extend(generation.to_ne_bytes());
                    k.extend(mask4(v, prefix));
                    map_update(&maps.join(map4), &k, &1u32.to_ne_bytes())?;
                }
                IpAddr::V6(v) => {
                    let mut k = (32u32 + prefix as u32).to_ne_bytes().to_vec();
                    k.extend(generation.to_ne_bytes());
                    k.extend(mask6(v, prefix));
                    map_update(&maps.join(map6), &k, &1u32.to_ne_bytes())?;
                }
            }
        }
    }
    Ok(())
}

fn publish_config(pin_dir: &Path, generation: u32, _ifindex: u32, p: &ShieldPolicy) -> Result<()> {
    let mode = if p.mode == "enforce" { 2u32 } else { 1u32 };
    let fields = [
        generation,
        mode,
        p.protect_all as u32,
        p.syn_pps,
        p.udp_pps,
        p.icmp_pps,
        p.other_pps,
        p.burst_seconds,
        p.sample_rate,
        0,
    ];
    let mut value = Vec::with_capacity(40);
    for v in fields {
        value.extend(v.to_ne_bytes());
    }
    map_update(
        &pin_dir.join("maps/fluxvm_shield_cfg"),
        &0u32.to_ne_bytes(),
        &value,
    )
}

fn cleanup_known_generation(pin_dir: &Path, old: &ShieldState) -> Result<()> {
    let maps = pin_dir.join("maps");
    for ip in &old.policy.protected_ips {
        match ip.parse::<IpAddr>()? {
            IpAddr::V4(v) => {
                let mut k = old.generation.to_ne_bytes().to_vec();
                k.extend(v.octets());
                let _ = map_delete(&maps.join("fluxvm_shield_protected4"), &k);
            }
            IpAddr::V6(v) => {
                let mut k = old.generation.to_ne_bytes().to_vec();
                k.extend(v.octets());
                let _ = map_delete(&maps.join("fluxvm_shield_protected6"), &k);
            }
        }
    }
    for (map4, map6, items) in [
        (
            "fluxvm_shield_allow4",
            "fluxvm_shield_allow6",
            &old.policy.allow_sources,
        ),
        (
            "fluxvm_shield_deny4",
            "fluxvm_shield_deny6",
            &old.policy.deny_sources,
        ),
    ] {
        for item in items {
            let (ip, prefix) = parse_cidr(item)?;
            match ip {
                IpAddr::V4(v) => {
                    let mut k = (32u32 + prefix as u32).to_ne_bytes().to_vec();
                    k.extend(old.generation.to_ne_bytes());
                    k.extend(mask4(v, prefix));
                    let _ = map_delete(&maps.join(map4), &k);
                }
                IpAddr::V6(v) => {
                    let mut k = (32u32 + prefix as u32).to_ne_bytes().to_vec();
                    k.extend(old.generation.to_ne_bytes());
                    k.extend(mask6(v, prefix));
                    let _ = map_delete(&maps.join(map6), &k);
                }
            }
        }
    }
    Ok(())
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip.parse::<IpAddr>()?, p.parse::<u8>()?),
        None => {
            let ip = s.parse::<IpAddr>()?;
            let p = if ip.is_ipv4() { 32 } else { 128 };
            return Ok((ip, p));
        }
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!("invalid CIDR prefix in {s}");
    }
    Ok((ip, prefix))
}
fn mask4(ip: Ipv4Addr, p: u8) -> [u8; 4] {
    let mut o = ip.octets();
    mask_bytes(&mut o, p);
    o
}
fn mask6(ip: Ipv6Addr, p: u8) -> [u8; 16] {
    let mut o = ip.octets();
    mask_bytes(&mut o, p);
    o
}
fn mask_bytes(bytes: &mut [u8], prefix: u8) {
    for (i, b) in bytes.iter_mut().enumerate() {
        let start = (i * 8) as u8;
        if prefix >= start + 8 {
        } else if prefix <= start {
            *b = 0
        } else {
            *b &= 0xffu8 << (8 - (prefix - start));
        }
    }
}

fn map_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    map_command("update", map, key, Some(value))
}
fn map_delete(map: &Path, key: &[u8]) -> Result<()> {
    map_command("delete", map, key, None)
}
fn map_command(op: &str, map: &Path, key: &[u8], value: Option<&[u8]>) -> Result<()> {
    if !map.exists() {
        bail!("pinned map missing: {}", map.display());
    }
    let mut args = vec![
        "map".to_string(),
        op.into(),
        "pinned".into(),
        map.display().to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(key.iter().map(|b| format!("{b:02x}")));
    if let Some(v) = value {
        args.push("value".into());
        args.push("hex".into());
        args.extend(v.iter().map(|b| format!("{b:02x}")));
        args.push("any".into());
    }
    let out = Command::new("bpftool")
        .args(&args)
        .output()
        .context("running bpftool")?;
    if out.status.success() {
        Ok(())
    } else {
        bail!(
            "bpftool {op} {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn bpftool_rows(map: &Path) -> Result<Vec<Value>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()?;
    if !out.status.success() {
        bail!(
            "bpftool map dump {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("decoding bpftool JSON")
}

fn read_stats(map: &Path, generation: u32) -> Result<Vec<ShieldReasonStat>> {
    let mut out = Vec::new();
    for row in bpftool_rows(map)? {
        let (g, reason, action) = if let Some(Value::Object(key)) = row.get("key") {
            (
                ju(key.get("generation")).unwrap_or(0) as u32,
                ju(key.get("reason")).unwrap_or(0) as u32,
                ju(key.get("action")).unwrap_or(0) as u32,
            )
        } else {
            let Some(key) = hex(row.get("key")) else {
                continue;
            };
            if key.len() < 12 {
                continue;
            }
            (
                u32::from_ne_bytes(key[0..4].try_into().unwrap()),
                u32::from_ne_bytes(key[4..8].try_into().unwrap()),
                u32::from_ne_bytes(key[8..12].try_into().unwrap()),
            )
        };
        if g != generation {
            continue;
        }

        let (packets, bytes) = if let Some(Value::Object(value)) = row.get("value") {
            (
                ju(value.get("packets")).unwrap_or(0),
                ju(value.get("bytes")).unwrap_or(0),
            )
        } else {
            let value = hex(row.get("value")).unwrap_or_default();
            if value.len() < 16 {
                continue;
            }
            (
                u64::from_ne_bytes(value[0..8].try_into().unwrap()),
                u64::from_ne_bytes(value[8..16].try_into().unwrap()),
            )
        };
        out.push(ShieldReasonStat {
            generation: g,
            reason_code: reason,
            reason: reason_label(reason).into(),
            action_code: action,
            action: action_label(action).into(),
            packets,
            bytes,
        });
    }
    Ok(out)
}
fn reason_label(v: u32) -> &'static str {
    match v {
        0 => "pass",
        1 => "explicit-deny",
        2 => "syn-rate",
        3 => "udp-rate",
        4 => "icmp-rate",
        5 => "other-rate",
        6 => "bucket-exhausted",
        7 => "malformed",
        _ => "unknown",
    }
}
fn action_label(v: u32) -> &'static str {
    match v {
        1 => "drop",
        2 => "audit",
        _ => "pass",
    }
}
fn hex(v: Option<&Value>) -> Option<Vec<u8>> {
    match v? {
        Value::Array(a) => a
            .iter()
            .map(|x| match x {
                Value::Number(n) => n.as_u64().filter(|n| *n <= 255).map(|n| n as u8),
                Value::String(s) => u8::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
                _ => None,
            })
            .collect(),
        Value::Object(o) => o.get("bytes").and_then(|v| hex(Some(v))),
        _ => None,
    }
}
fn ju(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s
            .parse()
            .ok()
            .or_else(|| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()),
        _ => None,
    }
}
fn write_state(state: &ShieldState, root: &Path) -> Result<()> {
    fs::create_dir_all(root)?;
    let path = state_path(root, state.vm_id);
    let tmp = root.join(format!(".{}.{}.tmp", state.vm_id, std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr_masks_are_stable() {
        assert_eq!(mask4("10.1.2.3".parse().unwrap(), 8), [10, 0, 0, 0]);
        assert_eq!(
            mask6("2001:db8:1234::1".parse().unwrap(), 32)[0..4],
            [0x20, 0x01, 0x0d, 0xb8]
        );
    }
    #[test]
    fn generation_never_publishes_zero() {
        assert_eq!(next_generation(u32::MAX), 1);
        assert_eq!(next_generation(7), 8);
    }
    #[test]
    fn policy_rejects_unbounded_rates() {
        let mut p = ShieldPolicy::default();
        p.protect_all = true;
        p.syn_pps = MAX_PPS + 1;
        assert!(validate_policy(&p).is_err());
    }
}
