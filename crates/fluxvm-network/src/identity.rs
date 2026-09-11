// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Reserved numeric identities for entity expansion and observe.
//!
//! Values match the common reserved identity space (`world=2`, `host=1`, …)
//! so `toEntities` and flow telemetry share stable numbers. FluxVM still
//! never writes foreign CNI private maps.

use serde::{Deserialize, Serialize};

pub const RESERVED_UNKNOWN: u32 = 0;
pub const RESERVED_HOST: u32 = 1;
pub const RESERVED_WORLD: u32 = 2;
pub const RESERVED_UNMANAGED: u32 = 3;
pub const RESERVED_HEALTH: u32 = 4;
pub const RESERVED_INIT: u32 = 5;
pub const RESERVED_REMOTE_NODE: u32 = 6;
pub const RESERVED_KUBE_APISERVER: u32 = 7;
pub const RESERVED_INGRESS: u32 = 8;
pub const RESERVED_WORLD_IPV4: u32 = 19;
pub const RESERVED_WORLD_IPV6: u32 = 20;
pub const MIN_LOCAL_IDENTITY: u32 = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityInfo {
    pub id: u32,
    pub name: String,
    pub labels: Vec<String>,
    pub reserved: bool,
}

pub fn reserved_identities() -> Vec<IdentityInfo> {
    vec![
        info(RESERVED_UNKNOWN, "reserved:unknown", &["reserved:unknown"]),
        info(RESERVED_HOST, "reserved:host", &["reserved:host"]),
        info(RESERVED_WORLD, "reserved:world", &["reserved:world"]),
        info(
            RESERVED_UNMANAGED,
            "reserved:unmanaged",
            &["reserved:unmanaged"],
        ),
        info(RESERVED_HEALTH, "reserved:health", &["reserved:health"]),
        info(RESERVED_INIT, "reserved:init", &["reserved:init"]),
        info(
            RESERVED_REMOTE_NODE,
            "reserved:remote-node",
            &["reserved:remote-node"],
        ),
        info(
            RESERVED_KUBE_APISERVER,
            "reserved:kube-apiserver",
            &["reserved:kube-apiserver"],
        ),
        info(RESERVED_INGRESS, "reserved:ingress", &["reserved:ingress"]),
        info(
            RESERVED_WORLD_IPV4,
            "reserved:world-ipv4",
            &["reserved:world-ipv4"],
        ),
        info(
            RESERVED_WORLD_IPV6,
            "reserved:world-ipv6",
            &["reserved:world-ipv6"],
        ),
    ]
}

fn info(id: u32, name: &str, labels: &[&str]) -> IdentityInfo {
    IdentityInfo {
        id,
        name: name.into(),
        labels: labels.iter().map(|s| (*s).to_string()).collect(),
        reserved: true,
    }
}

pub fn parse_entity(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "world" | "reserved:world" => Some("world"),
        "world-ipv4" | "reserved:world-ipv4" => Some("world-ipv4"),
        "world-ipv6" | "reserved:world-ipv6" => Some("world-ipv6"),
        "host" | "reserved:host" => Some("host"),
        "cluster" | "reserved:cluster" => Some("cluster"),
        "remote-node" | "reserved:remote-node" => Some("remote-node"),
        "unmanaged" | "reserved:unmanaged" => Some("unmanaged"),
        "kube-apiserver" | "reserved:kube-apiserver" => Some("kube-apiserver"),
        "ingress" | "reserved:ingress" => Some("ingress"),
        "unknown" | "reserved:unknown" => Some("unknown"),
        "health" | "reserved:health" => Some("health"),
        "init" | "reserved:init" => Some("init"),
        _ => None,
    }
}

pub fn entity_cidrs(entity: &str) -> Vec<String> {
    match entity {
        "world" => vec!["0.0.0.0/0".into(), "::/0".into()],
        "world-ipv4" => vec!["0.0.0.0/0".into()],
        "world-ipv6" => vec!["::/0".into()],
        "host" => vec![
            "127.0.0.0/8".into(),
            "169.254.0.0/16".into(),
            "fe80::/10".into(),
        ],
        "cluster" | "remote-node" | "unmanaged" => vec![
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "fd00::/8".into(),
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_space_matches_well_known() {
        assert_eq!(RESERVED_HOST, 1);
        assert_eq!(RESERVED_WORLD, 2);
        assert_eq!(RESERVED_KUBE_APISERVER, 7);
        assert_eq!(parse_entity("WORLD").unwrap(), "world");
        assert!(entity_cidrs("world").iter().any(|c| c == "0.0.0.0/0"));
    }
}
