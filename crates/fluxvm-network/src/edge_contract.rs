// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Userspace contract for the Kairon VM-edge API.
//!
//! BPF programs stay in this crate. These maps are the control-plane
//! documents Kairon posts: edge spec, conntrack move, learned IP,
//! attributed drops, and a bounded capture.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureSession {
    pub token: String,
    pub namespace: String,
    pub machine: String,
    pub seconds: u32,
    #[serde(default)]
    pub filter: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DropEvent {
    pub reason: String,
    pub policy_name: String,
    #[serde(rename = "srcIP")]
    pub src_ip: String,
    #[serde(rename = "dstIP")]
    pub dst_ip: String,
}

#[derive(Default)]
struct Slot {
    edge: Option<EdgeSpec>,
    conntrack: Option<ConntrackSnapshot>,
    learned_ip: String,
    learned_source: String,
    captures: Vec<CaptureSession>,
}

fn store() -> &'static Mutex<HashMap<Uuid, Slot>> {
    static STORE: std::sync::OnceLock<Mutex<HashMap<Uuid, Slot>>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn apply_edge(id: Uuid, spec: EdgeSpec) -> Result<EdgeSpec> {
    if spec.namespace.is_empty() || spec.machine.is_empty() {
        bail!("namespace and machine are required");
    }
    if spec.identity == 0 {
        bail!("identity is required");
    }
    let mut guard = store().lock().expect("edge store");
    let slot = guard.entry(id).or_default();
    if spec.learn_ip && !spec.assigned_ip.is_empty() && slot.learned_ip.is_empty() {
        slot.learned_ip = spec.assigned_ip.clone();
        slot.learned_source = "agent".to_string();
    }
    slot.edge = Some(spec.clone());
    Ok(spec)
}

pub fn edge(id: Uuid) -> Option<EdgeSpec> {
    store()
        .lock()
        .expect("edge store")
        .get(&id)
        .and_then(|s| s.edge.clone())
}

pub fn export_conntrack(id: Uuid) -> Result<ConntrackSnapshot> {
    let guard = store().lock().expect("edge store");
    guard
        .get(&id)
        .and_then(|s| s.conntrack.clone())
        .ok_or_else(|| anyhow::anyhow!("no conntrack snapshot for {id}"))
}

pub fn restore_conntrack(id: Uuid, snap: ConntrackSnapshot) -> Result<ConntrackSnapshot> {
    if snap.identity == 0 {
        bail!("conntrack identity is required");
    }
    if snap.exported_at.is_empty() {
        bail!("conntrack export timestamp is required");
    }
    let mut guard = store().lock().expect("edge store");
    let slot = guard.entry(id).or_default();
    if let Some(edge) = &slot.edge
        && edge.identity != 0
        && edge.identity != snap.identity
    {
        bail!(
            "conntrack identity {} does not match machine identity {}",
            snap.identity,
            edge.identity
        );
    }
    slot.conntrack = Some(snap.clone());
    Ok(snap)
}

pub fn learned_ip(id: Uuid) -> Result<Value> {
    let guard = store().lock().expect("edge store");
    let slot = guard.get(&id);
    let (ip, source) = slot
        .map(|s| (s.learned_ip.clone(), s.learned_source.clone()))
        .unwrap_or_default();
    Ok(json!({"ip": ip, "source": source}))
}

pub fn note_learned_ip(id: Uuid, ip: &str, source: &str) {
    if ip.is_empty() {
        return;
    }
    let mut guard = store().lock().expect("edge store");
    let slot = guard.entry(id).or_default();
    slot.learned_ip = ip.to_string();
    slot.learned_source = source.to_string();
}

pub fn attributed_drops(id: Uuid, limit: usize) -> Vec<DropEvent> {
    let guard = store().lock().expect("edge store");
    let Some(slot) = guard.get(&id) else {
        return Vec::new();
    };
    let Some(edge) = &slot.edge else {
        return Vec::new();
    };
    let mut events = Vec::new();
    if edge.anti_spoof {
        events.push(DropEvent {
            reason: "spoof_mac".to_string(),
            policy_name: edge.policy_name.clone(),
            src_ip: String::new(),
            dst_ip: String::new(),
        });
    }
    if !edge.allow_sni.is_empty() {
        events.push(DropEvent {
            reason: "sni_deny".to_string(),
            policy_name: edge.policy_name.clone(),
            src_ip: edge.assigned_ip.clone(),
            dst_ip: String::new(),
        });
    }
    if !edge.default_allow && events.is_empty() {
        events.push(DropEvent {
            reason: "default_deny".to_string(),
            policy_name: edge.policy_name.clone(),
            src_ip: edge.assigned_ip.clone(),
            dst_ip: String::new(),
        });
    }
    let limit = limit.clamp(1, 4096);
    events.truncate(limit);
    events
}

pub fn start_capture(id: Uuid, session: CaptureSession) -> Result<CaptureSession> {
    if session.seconds < 1 || session.seconds > 30 {
        bail!("seconds must be 1-30");
    }
    if session.token.is_empty() {
        bail!("capture token is required");
    }
    let mut guard = store().lock().expect("edge store");
    let slot = guard.entry(id).or_default();
    slot.captures.push(session.clone());
    Ok(session)
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_mismatch_fails_closed() {
        let id = Uuid::new_v4();
        apply_edge(
            id,
            EdgeSpec {
                namespace: "demo".into(),
                machine: "web".into(),
                identity: 42,
                ..EdgeSpec::default()
            },
        )
        .unwrap();
        let err = restore_conntrack(
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
    fn capture_rejects_long_window() {
        let id = Uuid::new_v4();
        let err = start_capture(
            id,
            CaptureSession {
                token: "abc".into(),
                namespace: "demo".into(),
                machine: "web".into(),
                seconds: 31,
                filter: String::new(),
                expires_at: "2026-10-04T00:00:30Z".into(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("1-30"));
    }
}
