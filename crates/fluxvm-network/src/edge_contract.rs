// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Userspace contract for the Kairon VM-edge API.
//!
//! Kairon posts an edge spec per Machine. It is persisted under
//! `<state_dir>/network-edge/<vm>.json` and loaded into the VM's BPF maps on
//! every attach, so enforcement survives daemon restarts, VM restarts and
//! dataplane repairs. Learned addresses, drops and conntrack are read from
//! the live maps.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use fluxvm_core::config::{Config, DataplaneMode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EdgeSpec {
    pub namespace: String,
    pub machine: String,
    pub identity: u32,
    #[serde(default)]
    pub anti_spoof: bool,
    #[serde(default, rename = "learnIP")]
    pub learn_ip: bool,
    #[serde(default, rename = "assignedMAC")]
    pub assigned_mac: String,
    #[serde(default, rename = "assignedIP")]
    pub assigned_ip: String,
    #[serde(default)]
    pub policy_name: String,
    #[serde(default)]
    pub default_allow: bool,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    #[serde(default)]
    pub allow_ports: Vec<String>,
    #[serde(default, rename = "allowSNI")]
    pub allow_sni: Vec<String>,
    #[serde(default, rename = "allowDNS")]
    pub allow_dns: Vec<String>,
    #[serde(default)]
    pub allow_icmp: bool,
    #[serde(default)]
    pub qos: EdgeQos,
}

impl EdgeSpec {
    fn enforces_anything(&self) -> bool {
        self.anti_spoof
            || self.learn_ip
            || !self.allow_sni.is_empty()
            || !self.allow_dns.is_empty()
            || self.qos != EdgeQos::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EdgeQos {
    #[serde(default)]
    pub ingress_mbps: u32,
    #[serde(default)]
    pub egress_mbps: u32,
    #[serde(default)]
    pub ingress_pps: u32,
    #[serde(default)]
    pub egress_pps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConntrackEntry {
    pub proto: String,
    #[serde(rename = "srcIP")]
    pub src_ip: String,
    #[serde(rename = "dstIP")]
    pub dst_ip: String,
    #[serde(rename = "srcPort")]
    pub src_port: u16,
    #[serde(rename = "dstPort")]
    pub dst_port: u16,
    pub state: String,
    #[serde(default)]
    pub seq: u32,
    #[serde(default)]
    pub ack: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConntrackSnapshot {
    pub identity: u32,
    pub generation: u64,
    pub exported_at: String,
    #[serde(default)]
    pub entries: Vec<ConntrackEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSession {
    pub token: String,
    pub namespace: String,
    pub machine: String,
    pub seconds: u32,
    #[serde(default)]
    pub filter: String,
    pub expires_at: String,
    /// `running`, `done`, `failed` or `interrupted`; set by FluxVM.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub started_unix: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub packets: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DropEvent {
    pub namespace: String,
    pub machine: String,
    pub reason: String,
    pub policy_name: String,
    #[serde(rename = "srcIP")]
    pub src_ip: String,
    #[serde(rename = "dstIP")]
    pub dst_ip: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proto: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub dst_port: u16,
    pub direction: String,
    pub action: String,
    pub packets: u64,
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// Everything the edge keeps per VM between daemon restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EdgeState {
    #[serde(default)]
    pub edge: Option<EdgeSpec>,
    /// A restore that arrived before the VM was attached; written into the
    /// conntrack map by the next attach.
    #[serde(default)]
    pub pending_conntrack: Option<ConntrackSnapshot>,
    #[serde(default)]
    pub captures: Vec<CaptureSession>,
}

const MAX_CAPTURES: usize = 16;

/// Serializes read-modify-write of the state files within the daemon.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn state_path(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.state_dir
        .join("network-edge")
        .join(format!("{id}.json"))
}

fn captures_dir(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.state_dir
        .join("network-edge")
        .join("captures")
        .join(id.to_string())
}

pub fn load(cfg: &Config, id: Uuid) -> Result<EdgeState> {
    load_at(&state_path(cfg, id))
}

fn load_at(path: &std::path::Path) -> Result<EdgeState> {
    match fs::read(path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .with_context(|| format!("parsing VM edge state {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EdgeState::default()),
        Err(e) => Err(e).with_context(|| format!("reading VM edge state {}", path.display())),
    }
}

fn save(cfg: &Config, id: Uuid, state: &EdgeState) -> Result<()> {
    save_at(&state_path(cfg, id), state)
}

fn save_at(path: &std::path::Path, state: &EdgeState) -> Result<()> {
    let parent = path.parent().context("VM edge state path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating VM edge state directory {}", parent.display()))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("writing VM edge state {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("committing VM edge state {}", path.display()))
}

pub fn delete(cfg: &Config, id: Uuid) -> Result<()> {
    let _guard = lock();
    let _ = fs::remove_dir_all(captures_dir(cfg, id));
    let path = state_path(cfg, id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting VM edge state {}", path.display())),
    }
}

/// The persisted spec, for the attach paths in `dataplane`.
pub fn spec(cfg: &Config, id: Uuid) -> Result<Option<EdgeSpec>> {
    Ok(load(cfg, id)?.edge)
}

fn native(cfg: &Config) -> bool {
    cfg.sandbox.dataplane.mode != DataplaneMode::Legacy
}

fn attached(cfg: &Config, id: Uuid) -> bool {
    native(cfg) && crate::ebpf::edge_attached(&cfg.sandbox.dataplane, id)
}

pub fn validate(spec: &EdgeSpec) -> Result<()> {
    if spec.namespace.is_empty() || spec.machine.is_empty() {
        bail!("namespace and machine are required");
    }
    if spec.identity == 0 {
        bail!("identity is required");
    }
    crate::ebpf::validate_edge(spec)
}

/// Validates, applies to the live maps when the VM is attached, then
/// persists. A VM that is not attached picks the spec up on its next attach.
pub fn apply_edge(cfg: &Config, id: Uuid, spec: EdgeSpec) -> Result<EdgeSpec> {
    validate(&spec)?;
    if !native(cfg) && spec.enforces_anything() {
        bail!("VM edge enforcement requires sandbox.dataplane.mode=ebpf or cilium");
    }
    let _guard = lock();
    let mut state = load(cfg, id)?;
    if attached(cfg, id) {
        crate::ebpf::reconfigure_edge(&cfg.sandbox.dataplane, id, Some(&spec))?;
        if let Some(iface) = crate::ebpf::read_recorded_iface(id) {
            let _netns = crate::ebpf::vm_netns_scope(id);
            crate::edge_qos::apply(&iface, &spec.qos)?;
        }
    }
    state.edge = Some(spec.clone());
    save(cfg, id, &state)?;
    Ok(spec)
}

/// Runs after a successful attach: host-to-guest QoS lives on the device,
/// which a VM restart recreates, and a migration restore may be waiting for
/// the conntrack map to exist.
pub fn after_attach(cfg: &Config, id: Uuid, iface: &str) {
    let _guard = lock();
    let mut state = match load(cfg, id) {
        Ok(state) => state,
        Err(e) => {
            warn!(%id, error = %e, "VM edge state unreadable; edge QoS and pending conntrack skipped");
            return;
        }
    };
    {
        let _netns = crate::ebpf::vm_netns_scope(id);
        let qos = state
            .edge
            .as_ref()
            .map(|e| e.qos.clone())
            .unwrap_or_default();
        if let Err(e) = crate::edge_qos::apply(iface, &qos) {
            warn!(%id, %iface, error = %e, "applying VM edge ingress QoS failed");
        }
    }
    if let Some(snap) = state.pending_conntrack.take() {
        match crate::ebpf::restore_conntrack_entries(&cfg.sandbox.dataplane, id, &snap.entries) {
            Ok(n) => {
                tracing::info!(%id, restored = n, "restored pending VM conntrack snapshot");
                if let Err(e) = save(cfg, id, &state) {
                    warn!(%id, error = %e, "clearing restored conntrack snapshot failed");
                }
            }
            Err(e) => warn!(%id, error = %e, "restoring pending VM conntrack snapshot failed"),
        }
    }
}

/// Snapshot of the live conntrack table. A VM with no attachment, or no
/// flows, exports an empty snapshot rather than failing the migration.
pub fn export_conntrack(cfg: &Config, id: Uuid) -> Result<ConntrackSnapshot> {
    let state = load(cfg, id)?;
    let identity = state
        .edge
        .as_ref()
        .map(|e| e.identity)
        .filter(|i| *i != 0)
        .unwrap_or_else(|| crate::ebpf::identity_for(id));
    let entries = if attached(cfg, id) {
        crate::ebpf::conntrack_entries(&cfg.sandbox.dataplane, id)?
    } else {
        Vec::new()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(ConntrackSnapshot {
        identity,
        generation: now.as_nanos() as u64,
        exported_at: rfc3339(now.as_secs()),
        entries,
    })
}

pub fn restore_conntrack(
    cfg: &Config,
    id: Uuid,
    snap: ConntrackSnapshot,
) -> Result<ConntrackSnapshot> {
    if snap.identity == 0 {
        bail!("conntrack identity is required");
    }
    if snap.exported_at.is_empty() {
        bail!("conntrack export timestamp is required");
    }
    let _guard = lock();
    let mut state = load(cfg, id)?;
    if let Some(edge) = &state.edge
        && edge.identity != 0
        && edge.identity != snap.identity
    {
        bail!(
            "conntrack identity {} does not match machine identity {}",
            snap.identity,
            edge.identity
        );
    }
    if attached(cfg, id) {
        crate::ebpf::restore_conntrack_entries(&cfg.sandbox.dataplane, id, &snap.entries)?;
        if state.pending_conntrack.take().is_some() {
            save(cfg, id, &state)?;
        }
    } else {
        state.pending_conntrack = Some(snap.clone());
        save(cfg, id, &state)?;
    }
    Ok(snap)
}

/// The address the datapath learned from guest ARP or ND; otherwise the
/// caller's fallback (the DHCP lease FluxVM handed out).
pub fn learned_ip(cfg: &Config, id: Uuid, fallback: Option<(String, &str)>) -> Result<Value> {
    if native(cfg)
        && let Some((ip, source)) = crate::ebpf::learned_address(&cfg.sandbox.dataplane, id)?
    {
        return Ok(json!({"ip": ip, "source": source}));
    }
    let (ip, source) = fallback
        .map(|(ip, source)| (ip, source.to_string()))
        .unwrap_or_default();
    Ok(json!({"ip": ip, "source": source}))
}

/// Drops recorded by the datapath, named with Kairon's reason vocabulary and
/// the policy object that produced the maps.
pub fn attributed_drops(cfg: &Config, id: Uuid, limit: usize) -> Result<Vec<DropEvent>> {
    if !attached(cfg, id) {
        return Ok(Vec::new());
    }
    let edge = load(cfg, id)?.edge.unwrap_or_default();
    let limit = limit.clamp(1, 4096);
    let mut events: Vec<DropEvent> = crate::ebpf::drop_reasons(&cfg.sandbox.dataplane, id, limit)?
        .into_iter()
        .map(|r| DropEvent {
            namespace: edge.namespace.clone(),
            machine: edge.machine.clone(),
            reason: kairon_reason(r.reason_code).to_string(),
            policy_name: edge.policy_name.clone(),
            src_ip: r.source,
            dst_ip: r.destination,
            proto: proto_name(r.protocol).to_string(),
            dst_port: r.destination_port,
            direction: "egress".to_string(),
            action: r.action,
            packets: r.packets,
        })
        .collect();
    if let Some(iface) = crate::ebpf::read_recorded_iface(id) {
        let _netns = crate::ebpf::vm_netns_scope(id);
        let packets = crate::edge_qos::drops(&iface);
        if packets > 0 {
            events.push(DropEvent {
                namespace: edge.namespace.clone(),
                machine: edge.machine.clone(),
                reason: "rate_limit".to_string(),
                policy_name: edge.policy_name.clone(),
                src_ip: String::new(),
                dst_ip: String::new(),
                proto: String::new(),
                dst_port: 0,
                direction: "ingress".to_string(),
                action: "drop".to_string(),
                packets,
            });
        }
    }
    events.sort_by(|a, b| b.packets.cmp(&a.packets));
    events.truncate(limit);
    Ok(events)
}

/// Kernel reason codes (`FLUXVM_REASON_*`) in Kairon's vocabulary.
fn kairon_reason(code: u32) -> &'static str {
    match code {
        3..=6 | 12 => "policy_deny",
        7 => "rate_limit",
        8 => "default_deny",
        13 => "spoof_mac",
        14 => "spoof_ip",
        15 => "dns_deny",
        16 => "sni_deny",
        1 | 2 | 11 => "malformed",
        9 | 10 => "migration",
        _ => "unknown",
    }
}

fn proto_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        132 => "sctp",
        _ => "",
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A `running` session whose capture cannot still be alive: the daemon
/// restarted (killing tcpdump) before it could record the outcome.
fn effective_state(c: &CaptureSession, now: u64) -> &str {
    if c.state == crate::edge_capture::STATE_RUNNING
        && now > c.started_unix + u64::from(c.seconds) + 30
    {
        crate::edge_capture::STATE_INTERRUPTED
    } else {
        &c.state
    }
}

/// Starts `tcpdump` on the VM's dataplane interface for `seconds` and records
/// the session; a background thread records the outcome when it stops. One
/// capture runs per VM at a time.
pub fn start_capture(
    cfg: &Config,
    id: Uuid,
    mut session: CaptureSession,
) -> Result<CaptureSession> {
    if session.seconds < 1 || session.seconds > 30 {
        bail!("seconds must be 1-30");
    }
    if session.token.is_empty() {
        bail!("capture token is required");
    }
    crate::edge_capture::validate(&session.token, &session.filter)?;
    if !attached(cfg, id) {
        bail!("VM is not attached to the eBPF dataplane; there is no interface to capture on");
    }
    let iface =
        crate::ebpf::read_recorded_iface(id).context("VM has no recorded dataplane interface")?;
    let guard = lock();
    let mut state = load(cfg, id)?;
    let now = unix_now();
    if state
        .captures
        .iter()
        .any(|c| effective_state(c, now) == crate::edge_capture::STATE_RUNNING)
    {
        bail!("a capture is already running for this VM");
    }
    let dir = captures_dir(cfg, id);
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating capture directory {}", dir.display()))?;
    let file = dir.join(format!("{}.pcap", session.token));
    let child = {
        let _netns = crate::ebpf::vm_netns_scope(id);
        crate::edge_capture::spawn(&iface, &file, &session.filter)?
    };
    session.state = crate::edge_capture::STATE_RUNNING.to_string();
    session.started_unix = now;
    session.packets = 0;
    session.error.clear();
    state.captures.retain(|c| c.token != session.token);
    state.captures.push(session.clone());
    let excess = state.captures.len().saturating_sub(MAX_CAPTURES);
    for old in state.captures.drain(..excess) {
        let _ = fs::remove_file(dir.join(format!("{}.pcap", old.token)));
    }
    save(cfg, id, &state)?;
    drop(guard);

    let path = state_path(cfg, id);
    let token = session.token.clone();
    let seconds = session.seconds;
    std::thread::spawn(move || {
        let outcome = crate::edge_capture::wait(child, seconds);
        let _guard = lock();
        let result = load_at(&path).and_then(|mut state| {
            if let Some(c) = state.captures.iter_mut().find(|c| c.token == token) {
                c.state = outcome.state.to_string();
                c.packets = outcome.packets;
                c.error = outcome.error;
            }
            save_at(&path, &state)
        });
        if let Err(e) = result {
            warn!(%id, %token, error = %e, "recording capture outcome failed");
        }
    });
    Ok(session)
}

pub fn captures(cfg: &Config, id: Uuid) -> Result<Vec<CaptureSession>> {
    let now = unix_now();
    Ok(load(cfg, id)?
        .captures
        .into_iter()
        .map(|mut c| {
            c.state = effective_state(&c, now).to_string();
            c
        })
        .collect())
}

pub enum CaptureFile {
    Ready(PathBuf),
    Running,
    Missing,
}

/// The pcap for `token`, once its capture has stopped.
pub fn capture_file(cfg: &Config, id: Uuid, token: &str) -> Result<CaptureFile> {
    crate::edge_capture::validate(token, "")?;
    let Some(session) = captures(cfg, id)?.into_iter().find(|c| c.token == token) else {
        return Ok(CaptureFile::Missing);
    };
    if session.state == crate::edge_capture::STATE_RUNNING {
        return Ok(CaptureFile::Running);
    }
    let file = captures_dir(cfg, id).join(format!("{token}.pcap"));
    Ok(if file.is_file() {
        CaptureFile::Ready(file)
    } else {
        CaptureFile::Missing
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp; Kairon decodes it as `time.Time`.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

pub fn now_rfc3339() -> String {
    rfc3339(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> (tempfile::TempDir, Config) {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        cfg.sandbox.dataplane.pin_root = tmp.path().join("bpf");
        (tmp, cfg)
    }

    fn spec(identity: u32) -> EdgeSpec {
        EdgeSpec {
            namespace: "demo".into(),
            machine: "web".into(),
            identity,
            ..EdgeSpec::default()
        }
    }

    #[test]
    fn identity_mismatch_fails_closed() {
        let (_tmp, cfg) = test_cfg();
        let id = Uuid::new_v4();
        apply_edge(&cfg, id, spec(42)).unwrap();
        let err = restore_conntrack(
            &cfg,
            id,
            ConntrackSnapshot {
                identity: 7,
                generation: 1,
                exported_at: "2026-10-04T00:00:00Z".into(),
                entries: vec![],
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn spec_and_pending_restore_survive_reload() {
        let (_tmp, cfg) = test_cfg();
        let id = Uuid::new_v4();
        apply_edge(&cfg, id, spec(42)).unwrap();
        let entry = ConntrackEntry {
            proto: "tcp".into(),
            src_ip: "10.0.0.5".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 40000,
            dst_port: 443,
            state: "established".into(),
            seq: 0,
            ack: 0,
        };
        restore_conntrack(
            &cfg,
            id,
            ConntrackSnapshot {
                identity: 42,
                generation: 1,
                exported_at: "2026-10-04T00:00:00Z".into(),
                entries: vec![entry.clone()],
            },
        )
        .unwrap();
        let state = load(&cfg, id).unwrap();
        assert_eq!(state.edge.unwrap().identity, 42);
        assert_eq!(state.pending_conntrack.unwrap().entries, vec![entry]);
        delete(&cfg, id).unwrap();
        assert!(load(&cfg, id).unwrap().edge.is_none());
    }

    #[test]
    fn export_without_attachment_is_empty_not_an_error() {
        let (_tmp, cfg) = test_cfg();
        let id = Uuid::new_v4();
        apply_edge(&cfg, id, spec(42)).unwrap();
        let snap = export_conntrack(&cfg, id).unwrap();
        assert_eq!(snap.identity, 42);
        assert!(snap.entries.is_empty());
        assert!(snap.exported_at.ends_with('Z'));
    }

    #[test]
    fn legacy_mode_refuses_enforcement() {
        let (_tmp, mut cfg) = test_cfg();
        cfg.sandbox.dataplane.mode = DataplaneMode::Legacy;
        let mut s = spec(42);
        s.anti_spoof = true;
        let err = apply_edge(&cfg, Uuid::new_v4(), s).unwrap_err();
        assert!(err.to_string().contains("ebpf or cilium"));
    }

    #[test]
    fn rejects_bad_names_and_addresses() {
        let mut s = spec(42);
        s.allow_sni = vec!["bad name".into()];
        assert!(validate(&s).is_err());
        let mut s = spec(42);
        s.assigned_mac = "52:54:00:00:01".into();
        assert!(validate(&s).is_err());
        let mut s = spec(42);
        s.assigned_ip = "10.0.0.300".into();
        assert!(validate(&s).is_err());
        let mut s = spec(42);
        s.allow_dns = vec!["*.Example.COM.".into(), "api.test".into()];
        s.assigned_ip = "10.0.0.5/24,fd00::5".into();
        validate(&s).unwrap();
    }

    #[test]
    fn capture_rejects_long_window() {
        let (_tmp, cfg) = test_cfg();
        let err = start_capture(
            &cfg,
            Uuid::new_v4(),
            CaptureSession {
                token: "abc".into(),
                namespace: "demo".into(),
                machine: "web".into(),
                seconds: 31,
                expires_at: "2026-10-04T00:00:30Z".into(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("1-30"));
    }

    fn session(token: &str) -> CaptureSession {
        CaptureSession {
            token: token.into(),
            namespace: "demo".into(),
            machine: "web".into(),
            seconds: 5,
            expires_at: "2026-10-04T00:00:30Z".into(),
            ..Default::default()
        }
    }

    #[test]
    fn capture_rejects_unsafe_token_and_detached_vm() {
        let (_tmp, cfg) = test_cfg();
        let err = start_capture(&cfg, Uuid::new_v4(), session("../x")).unwrap_err();
        assert!(err.to_string().contains("token"));
        let err = start_capture(&cfg, Uuid::new_v4(), session("ok")).unwrap_err();
        assert!(err.to_string().contains("not attached"));
    }

    #[test]
    fn stale_running_capture_reads_interrupted() {
        let (_tmp, cfg) = test_cfg();
        let id = Uuid::new_v4();
        let now = unix_now();
        let mut fresh = session("fresh");
        fresh.state = crate::edge_capture::STATE_RUNNING.into();
        fresh.started_unix = now;
        let mut stale = session("stale");
        stale.state = crate::edge_capture::STATE_RUNNING.into();
        stale.started_unix = now - 120;
        let mut done = session("done");
        done.state = crate::edge_capture::STATE_DONE.into();
        done.started_unix = now - 120;
        save(
            &cfg,
            id,
            &EdgeState {
                captures: vec![fresh, stale, done],
                ..Default::default()
            },
        )
        .unwrap();
        let states: Vec<String> = captures(&cfg, id)
            .unwrap()
            .into_iter()
            .map(|c| c.state)
            .collect();
        assert_eq!(states, ["running", "interrupted", "done"]);
        assert!(matches!(
            capture_file(&cfg, id, "fresh").unwrap(),
            CaptureFile::Running
        ));
        assert!(matches!(
            capture_file(&cfg, id, "done").unwrap(),
            CaptureFile::Missing
        ));
        let dir = captures_dir(&cfg, id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("done.pcap"), b"pcap").unwrap();
        assert!(matches!(
            capture_file(&cfg, id, "done").unwrap(),
            CaptureFile::Ready(_)
        ));
        delete(&cfg, id).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_791_072_000), "2026-10-04T00:00:00Z");
    }

    #[test]
    fn edge_spec_decodes_kairon_field_names() {
        let spec: EdgeSpec = serde_json::from_str(
            r#"{"namespace":"demo","machine":"web","identity":42,"antiSpoof":true,
                "learnIP":true,"assignedMAC":"52:54:00:00:00:01","assignedIP":"10.0.0.5",
                "allowSNI":["*.example.com"],"allowDNS":["example.com"],"allowIcmp":true}"#,
        )
        .unwrap();
        assert!(spec.learn_ip && spec.allow_icmp);
        assert_eq!(spec.assigned_mac, "52:54:00:00:00:01");
        assert_eq!(spec.assigned_ip, "10.0.0.5");
        assert_eq!(spec.allow_sni, ["*.example.com"]);
        assert_eq!(spec.allow_dns, ["example.com"]);
    }

    #[test]
    fn kernel_reasons_map_to_kairon_vocabulary() {
        assert_eq!(kairon_reason(13), "spoof_mac");
        assert_eq!(kairon_reason(14), "spoof_ip");
        assert_eq!(kairon_reason(15), "dns_deny");
        assert_eq!(kairon_reason(16), "sni_deny");
        assert_eq!(kairon_reason(7), "rate_limit");
        assert_eq!(kairon_reason(4), "policy_deny");
        assert_eq!(kairon_reason(8), "default_deny");
    }
}
