// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::{
    shield::{self, ShieldSnapshot},
    tcpintel::{self, TcpIntelSnapshot},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkIntelligenceSnapshot {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub shield: Option<ShieldSnapshot>,
    pub tcp: Option<TcpIntelSnapshot>,
}

pub fn snapshot(
    id: Uuid,
    shield_pin: &Path,
    shield_state: &Path,
    tcp_pin: &Path,
    tcp_state: &Path,
    flow_limit: usize,
) -> NetworkIntelligenceSnapshot {
    NetworkIntelligenceSnapshot {
        schema_version: 1,
        vm_id: id,
        shield: shield::snapshot(id, shield_pin, shield_state).ok(),
        tcp: tcpintel::snapshot(id, tcp_pin, tcp_state, flow_limit).ok(),
    }
}

pub fn list_ids(shield_state: &Path, tcp_state: &Path) -> Vec<Uuid> {
    let mut ids = BTreeSet::new();
    for root in [shield_state, tcp_state] {
        let Ok(rd) = fs::read_dir(root) else { continue };
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let stem = name.strip_suffix(".json").unwrap_or(&name);
            if let Ok(id) = stem.parse() {
                ids.insert(id);
            }
        }
    }
    ids.into_iter().collect()
}

pub fn prometheus(
    shield_pin: &Path,
    shield_state: &Path,
    tcp_pin: &Path,
    tcp_state: &Path,
) -> String {
    let mut out = String::from("# FluxVM Set 6 network intelligence\n");
    for id in list_ids(shield_state, tcp_state) {
        if let Ok(s) = shield::snapshot(id, shield_pin, shield_state) {
            out.push_str(&shield::prometheus(&s));
        }
        if let Ok(t) = tcpintel::snapshot(id, tcp_pin, tcp_state, 1) {
            out.push_str(&tcpintel::prometheus(&t));
        }
    }
    out
}
