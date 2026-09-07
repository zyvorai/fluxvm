// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Control-plane ipcache: guest IP → FluxVM identity.
//! Analogous to an ipcache, stored under state_dir (not foreign CNI maps).

use anyhow::Result;
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcacheEntry {
    pub ip: String,
    pub identity: u32,
    pub vm_id: Uuid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    entries: BTreeMap<String, IpcacheEntry>,
}

fn path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-groups").join("ipcache.json")
}

fn load(cfg: &Config) -> Result<Store> {
    let p = path(cfg);
    if !p.exists() {
        return Ok(Store::default());
    }
    Ok(serde_json::from_str(&fs::read_to_string(p)?)?)
}

fn save(cfg: &Config, store: &Store) -> Result<()> {
    let p = path(cfg);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = p.with_extension("json.tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(serde_json::to_vec_pretty(store)?.as_slice())?;
    f.sync_all()?;
    fs::rename(tmp, p)?;
    Ok(())
}

pub fn upsert(cfg: &Config, ip: &str, identity: u32, vm_id: Uuid) -> Result<()> {
    let ip = ip.split('/').next().unwrap_or(ip).to_string();
    if ip.is_empty() {
        return Ok(());
    }
    let mut store = load(cfg)?;
    store.entries.insert(
        ip.clone(),
        IpcacheEntry {
            ip,
            identity,
            vm_id,
        },
    );
    save(cfg, &store)
}

pub fn remove_vm(cfg: &Config, vm_id: Uuid) -> Result<()> {
    let mut store = load(cfg)?;
    store.entries.retain(|_, e| e.vm_id != vm_id);
    save(cfg, &store)
}

pub fn list(cfg: &Config) -> Result<Vec<IpcacheEntry>> {
    Ok(load(cfg)?.entries.into_values().collect())
}
