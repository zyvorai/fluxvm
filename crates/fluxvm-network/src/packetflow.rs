// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Hubble-style packet-flow views for the FluxVM VM-edge dataplane.
//!
//! FluxVM does not speak Hubble gRPC and does not write Cilium-private maps.
//! This module turns eBPF `FlowRecord`s + endpoint identities into:
//!
//! * a structured hop path (guest → tap → TC/eBPF → uplink → peer)
//! * a one-line Hubble-like summary
//! * **color** (ANSI) and **plain** (no ANSI) text renders
//!
//! Wire JSON stays a Hubble v1 subset plus optional `hops` / `summary` fields.

use crate::ebpf::FlowRecord;
use crate::endpoint::{HubbleEndpoint, HubbleFlow};
use crate::identity::{RESERVED_HOST, RESERVED_WORLD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowOutput {
    Color,
    Plain,
    Json,
}

impl FlowOutput {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "plain" | "normal" | "nocolor" | "no-color" => Self::Plain,
            "json" => Self::Json,
            _ => Self::Color,
        }
    }

    pub fn auto() -> Self {
        match std::env::var("NO_COLOR") {
            Ok(v) if !v.is_empty() => Self::Plain,
            _ => Self::Color,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketHop {
    pub index: u8,
    pub name: String,
    pub role: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketFlowView {
    pub time: String,
    pub verdict: String,
    pub drop_reason_desc: Option<String>,
    pub direction: TrafficDirection,
    pub protocol: String,
    pub family: u8,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub source: HubbleEndpoint,
    pub destination: HubbleEndpoint,
    pub packets: u64,
    pub bytes: u64,
    pub hops: Vec<PacketHop>,
    pub summary: String,
    pub node_name: String,
    pub flow_type: String,
}

pub fn proto_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "any",
    }
}

pub fn normalize_verdict(raw: &str) -> String {
    let l = raw.to_ascii_lowercase();
    if l.contains("drop") || l.contains("deny") {
        "DROPPED".into()
    } else if l.contains("audit") {
        "AUDIT".into()
    } else {
        "FORWARDED".into()
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "fluxvm".into())
}

fn infer_direction(rec: &FlowRecord, guest_ip: Option<&str>) -> TrafficDirection {
    if let Some(ip) = guest_ip {
        let ip = ip.split('/').next().unwrap_or(ip);
        if rec.destination == ip {
            return TrafficDirection::Ingress;
        }
        if rec.source == ip {
            return TrafficDirection::Egress;
        }
    }
    TrafficDirection::Egress
}

/// Build the VM-edge hop path. Cilium coexistence is a labeled hop only —
/// FluxVM never claims to own Cilium's packet path.
pub fn build_hops(
    direction: TrafficDirection,
    verdict: &str,
    dataplane_mode: &str,
    vm_name: &str,
    proto: &str,
    dport: u16,
) -> Vec<PacketHop> {
    let policy =
        format!("FluxVM Network Fabric eBPF  proto={proto} dport={dport} verdict={verdict}");
    let cilium = matches!(dataplane_mode.to_ascii_lowercase().as_str(), "cilium");
    let mut hops = Vec::new();
    let push = |hops: &mut Vec<PacketHop>, name: &str, role: &str, detail: &str| {
        hops.push(PacketHop {
            index: hops.len() as u8,
            name: name.into(),
            role: role.into(),
            detail: detail.into(),
        });
    };

    match direction {
        TrafficDirection::Egress => {
            push(&mut hops, vm_name, "guest", "virtio-net in guest namespace");
            push(&mut hops, "tap", "l2", "host TAP/veth pair");
            push(&mut hops, "tc-clsact", "dataplane", &policy);
            if cilium {
                push(
                    &mut hops,
                    "cilium",
                    "coexist",
                    "mode=cilium — FluxVM does not write Cilium-private maps",
                );
            }
            push(&mut hops, "uplink", "host", "bridge / underlay toward peer");
            push(
                &mut hops,
                "peer",
                "identity",
                "reserved:world or remote identity",
            );
        }
        TrafficDirection::Ingress => {
            push(
                &mut hops,
                "peer",
                "identity",
                "reserved:world or remote identity",
            );
            push(&mut hops, "uplink", "host", "bridge / underlay from peer");
            if cilium {
                push(
                    &mut hops,
                    "cilium",
                    "coexist",
                    "mode=cilium — FluxVM does not write Cilium-private maps",
                );
            }
            push(&mut hops, "tc-clsact", "dataplane", &policy);
            push(&mut hops, "tap", "l2", "host TAP/veth pair");
            push(&mut hops, vm_name, "guest", "virtio-net in guest namespace");
        }
    }
    hops
}

pub fn summary_line(view: &PacketFlowView) -> String {
    format!(
        "{time} {verdict:<10} {dir:<7} {proto}/{dport} {src}:{sport} → {dst}:{dport2}  {src_id}->{dst_id}  {pkts}p/{bytes}B  {vm}",
        time = view.time,
        verdict = view.verdict,
        dir = format!("{:?}", view.direction).to_uppercase(),
        proto = view.protocol,
        dport = view.destination_port,
        src = view.source_ip,
        sport = view.source_port,
        dst = view.destination_ip,
        dport2 = view.destination_port,
        src_id = view.source.identity,
        dst_id = view.destination.identity,
        pkts = view.packets,
        bytes = view.bytes,
        vm = view.source.pod_name.as_deref().unwrap_or("-"),
    )
}

pub fn from_flow_record(
    rec: &FlowRecord,
    src_labels: &[String],
    vm_name: Option<&str>,
    guest_ip: Option<&str>,
    dataplane_mode: &str,
) -> PacketFlowView {
    let verdict = normalize_verdict(&rec.verdict);
    let protocol = proto_name(rec.protocol).to_string();
    let direction = infer_direction(rec, guest_ip);
    let name = vm_name.unwrap_or("vm");
    let hops = build_hops(
        direction,
        &verdict,
        dataplane_mode,
        name,
        &protocol,
        rec.destination_port,
    );
    let mut view = PacketFlowView {
        time: rec.last_seen_ns.to_string(),
        verdict: verdict.clone(),
        drop_reason_desc: if verdict == "DROPPED" {
            Some("POLICY_DENIED".into())
        } else {
            None
        },
        direction,
        protocol,
        family: rec.family,
        source_ip: rec.source.clone(),
        destination_ip: rec.destination.clone(),
        source_port: rec.source_port,
        destination_port: rec.destination_port,
        source: HubbleEndpoint {
            identity: rec.identity,
            labels: src_labels.to_vec(),
            pod_name: vm_name.map(str::to_string),
        },
        destination: HubbleEndpoint {
            identity: RESERVED_WORLD,
            labels: vec!["reserved:world".into()],
            pod_name: None,
        },
        packets: rec.packets,
        bytes: rec.bytes,
        hops,
        summary: String::new(),
        node_name: hostname(),
        flow_type: "L3_L4".into(),
    };
    view.summary = summary_line(&view);
    view
}

pub fn to_hubble_flow(view: &PacketFlowView) -> HubbleFlow {
    let ip_ver = if view.family == 6 { "IPv6" } else { "IPv4" };
    HubbleFlow {
        time: view.time.clone(),
        verdict: view.verdict.clone(),
        drop_reason_desc: view.drop_reason_desc.clone(),
        ethernet: None,
        ip: Some(serde_json::json!({
            "source": view.source_ip,
            "destination": view.destination_ip,
            "ipVersion": ip_ver,
        })),
        l4: Some(serde_json::json!({
            "protocol": view.protocol,
            "source_port": view.source_port,
            "destination_port": view.destination_port,
        })),
        source: view.source.clone(),
        destination: view.destination.clone(),
        flow_type: view.flow_type.clone(),
        node_name: view.node_name.clone(),
        traffic_direction: Some(format!("{:?}", view.direction).to_uppercase()),
        summary: Some(view.summary.clone()),
        packets: Some(view.packets),
        bytes: Some(view.bytes),
        hops: Some(view.hops.clone()),
    }
}

// --- ANSI ---

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";

fn paint(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

fn verdict_style(verdict: &str, color: bool) -> String {
    match verdict {
        "DROPPED" => paint(color, RED, verdict),
        "AUDIT" => paint(color, YELLOW, verdict),
        _ => paint(color, GREEN, verdict),
    }
}

/// One-line Hubble-like observe output.
pub fn render_line(view: &PacketFlowView, output: FlowOutput) -> String {
    let color = matches!(output, FlowOutput::Color);
    format!(
        "{time} {verdict:<10} {dir:<7} {proto} {src} {arrow} {dst}  {ids}  {counters}  {vm}",
        time = paint(color, DIM, &view.time),
        verdict = verdict_style(&view.verdict, color),
        dir = paint(
            color,
            MAGENTA,
            &format!("{:?}", view.direction).to_uppercase()
        ),
        proto = paint(
            color,
            CYAN,
            &format!("{}/{}", view.protocol, view.destination_port)
        ),
        src = paint(
            color,
            BOLD,
            &format!("{}:{}", view.source_ip, view.source_port)
        ),
        arrow = paint(color, BLUE, "→"),
        dst = paint(
            color,
            BOLD,
            &format!("{}:{}", view.destination_ip, view.destination_port)
        ),
        ids = paint(
            color,
            CYAN,
            &format!("{}→{}", view.source.identity, view.destination.identity)
        ),
        counters = paint(color, DIM, &format!("{}p/{}B", view.packets, view.bytes)),
        vm = view.source.pod_name.as_deref().unwrap_or("-"),
    )
}

/// Multi-line packet path (Hubble “flow details”).
pub fn render_detailed(view: &PacketFlowView, output: FlowOutput) -> String {
    let color = matches!(output, FlowOutput::Color);
    let mut out = String::new();
    out.push_str(&render_line(view, output));
    out.push('\n');
    out.push_str(&paint(
        color,
        DIM,
        &format!(
            "  node={} type={} family=IPv{} labels_src=[{}] labels_dst=[{}]",
            view.node_name,
            view.flow_type,
            view.family,
            view.source.labels.join(" "),
            view.destination.labels.join(" "),
        ),
    ));
    out.push('\n');
    if let Some(reason) = &view.drop_reason_desc {
        out.push_str("  ");
        out.push_str(&paint(color, RED, &format!("drop_reason={reason}")));
        out.push('\n');
    }
    out.push_str("  packet path:\n");
    for hop in &view.hops {
        let arrow = if hop.index + 1 == view.hops.len() as u8 {
            "└─"
        } else {
            "├─"
        };
        let name = paint(color, BOLD, &hop.name);
        let role = paint(color, BLUE, &hop.role);
        out.push_str(&format!(
            "  {arrow} [{idx}] {name} ({role})  {detail}\n",
            idx = hop.index,
            detail = hop.detail
        ));
        if hop.index + 1 != view.hops.len() as u8 {
            out.push_str(&paint(color, BLUE, "  │\n"));
        }
    }
    out.push_str(&format!(
        "  reserved: host={RESERVED_HOST} world={RESERVED_WORLD}\n"
    ));
    out
}

pub fn render_flows(views: &[PacketFlowView], output: FlowOutput, detailed: bool) -> String {
    match output {
        FlowOutput::Json => {
            let flows: Vec<HubbleFlow> = views.iter().map(to_hubble_flow).collect();
            serde_json::to_string_pretty(&flows).unwrap_or_else(|_| "[]".into())
        }
        FlowOutput::Color | FlowOutput::Plain => {
            let mut s = String::new();
            if views.is_empty() {
                s.push_str("(no flows)\n");
                return s;
            }
            for (i, v) in views.iter().enumerate() {
                if detailed {
                    if i > 0 {
                        s.push('\n');
                    }
                    s.push_str(&render_detailed(v, output));
                } else {
                    s.push_str(&render_line(v, output));
                    s.push('\n');
                }
            }
            s
        }
    }
}

pub fn filter_views(
    views: Vec<PacketFlowView>,
    verdict: Option<&str>,
    protocol: Option<&str>,
) -> Vec<PacketFlowView> {
    views
        .into_iter()
        .filter(|v| {
            if let Some(want) = verdict {
                let want = want.to_ascii_uppercase();
                if want != "ALL" && v.verdict != want {
                    return false;
                }
            }
            if let Some(want) = protocol {
                let want = want.to_ascii_lowercase();
                if want != "all" && v.protocol != want {
                    return false;
                }
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rec(verdict: &str) -> FlowRecord {
        FlowRecord {
            identity: 1042,
            family: 4,
            source: "10.0.0.2".into(),
            destination: "1.1.1.1".into(),
            source_port: 54321,
            destination_port: 443,
            protocol: 6,
            verdict: verdict.into(),
            packets: 12,
            bytes: 980,
            last_seen_ns: 1_700_000_000,
        }
    }

    #[test]
    fn builds_egress_path_with_ebpf_and_optional_cilium() {
        let rec = sample_rec("allow");
        let view = from_flow_record(
            &rec,
            &["app=web".into()],
            Some("web-1"),
            Some("10.0.0.2"),
            "ebpf",
        );
        assert_eq!(view.verdict, "FORWARDED");
        assert_eq!(view.direction, TrafficDirection::Egress);
        assert_eq!(view.protocol, "tcp");
        let names: Vec<_> = view.hops.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["web-1", "tap", "tc-clsact", "uplink", "peer"]);
        assert!(view.summary.contains("FORWARDED"));
        assert!(view.summary.contains("10.0.0.2:54321"));
    }

    #[test]
    fn ingress_when_destination_is_guest() {
        let mut rec = sample_rec("allow");
        rec.destination = "10.0.0.2".into();
        rec.source = "9.9.9.9".into();
        rec.source_port = 443;
        rec.destination_port = 8080;
        let view = from_flow_record(&rec, &[], Some("web-1"), Some("10.0.0.2"), "cilium");
        assert_eq!(view.direction, TrafficDirection::Ingress);
        let names: Vec<_> = view.hops.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(
            names,
            ["peer", "uplink", "cilium", "tc-clsact", "tap", "web-1"]
        );
    }

    #[test]
    fn color_has_ansi_plain_does_not() {
        let rec = sample_rec("drop");
        let view = from_flow_record(&rec, &[], Some("web-1"), None, "ebpf");
        assert_eq!(view.verdict, "DROPPED");
        let color = render_detailed(&view, FlowOutput::Color);
        let plain = render_detailed(&view, FlowOutput::Plain);
        assert!(color.contains("\x1b["), "color mode must emit ANSI");
        assert!(
            !plain.contains("\x1b["),
            "plain/normal mode must be raw text"
        );
        assert!(plain.contains("packet path:"));
        assert!(plain.contains("tc-clsact"));
        assert!(plain.contains("POLICY_DENIED"));
    }

    #[test]
    fn json_round_trip_includes_hops() {
        let rec = sample_rec("allow");
        let view = from_flow_record(&rec, &["app=web".into()], Some("web-1"), None, "ebpf");
        let json = render_flows(&[view], FlowOutput::Json, false);
        assert!(json.contains("\"verdict\": \"FORWARDED\""));
        assert!(json.contains("tc-clsact"));
        assert!(json.contains("source_port"));
    }

    #[test]
    fn filters_verdict_and_protocol() {
        let a = from_flow_record(&sample_rec("allow"), &[], Some("a"), None, "ebpf");
        let mut drop_rec = sample_rec("drop");
        drop_rec.protocol = 17;
        drop_rec.destination_port = 53;
        let b = from_flow_record(&drop_rec, &[], Some("b"), None, "ebpf");
        let only_drop = filter_views(vec![a.clone(), b.clone()], Some("DROPPED"), Some("all"));
        assert_eq!(only_drop.len(), 1);
        assert_eq!(only_drop[0].verdict, "DROPPED");
        let only_tcp = filter_views(vec![a, b], Some("all"), Some("tcp"));
        assert_eq!(only_tcp.len(), 1);
        assert_eq!(only_tcp[0].protocol, "tcp");
    }

    #[test]
    fn output_aliases() {
        assert_eq!(FlowOutput::parse("normal"), FlowOutput::Plain);
        assert_eq!(FlowOutput::parse("plain"), FlowOutput::Plain);
        assert_eq!(FlowOutput::parse("color"), FlowOutput::Color);
        assert_eq!(FlowOutput::parse("json"), FlowOutput::Json);
    }
}
