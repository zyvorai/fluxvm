// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Control-plane ipcache: guest IP → FluxVM identity.
//! Analogous to an ipcache, stored under state_dir (not foreign CNI maps).
//!
//! Remote (ClusterMesh-like) entries use [`Uuid::nil`] as `vm_id` so Fabric can
//! fan peer CIDRs into local compile without a local VM.

use anyhow::{Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, net::IpAddr, path::PathBuf};
use uuid::Uuid;

/// Sentinel `vm_id` for Fabric-reconciled remote identity rows.
pub fn remote_vm_id() -> Uuid {
    Uuid::nil()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpcacheEntry {
    pub ip: String,
    pub identity: u32,
    pub vm_id: Uuid,
}

impl IpcacheEntry {
    pub fn is_remote(&self) -> bool {
        self.vm_id.is_nil()
    }
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

fn normalize_host(ip_or_cidr: &str) -> Result<String> {
    let host = ip_or_cidr
        .split('/')
        .next()
        .unwrap_or(ip_or_cidr)
        .trim()
        .to_string();
    if host.is_empty() {
        bail!("empty ipcache address");
    }
    let _: IpAddr = host
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid ipcache address {host:?}: {e}"))?;
    Ok(host)
}

pub fn upsert(cfg: &Config, ip: &str, identity: u32, vm_id: Uuid) -> Result<()> {
    let ip = ip.split('/').next().unwrap_or(ip).trim().to_string();
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

/// Replace all remote rows for `identity` with hosts derived from `cidrs`.
/// Each CIDR contributes its address part (prefix length is not stored; service
/// policy sid maps are exact-IP). Prefer `/32` / `/128` peer publishes.
pub fn upsert_remote(cfg: &Config, identity: u32, cidrs: &[String]) -> Result<usize> {
    if identity == 0 {
        bail!("identity 0 is reserved/unresolved");
    }
    let mut hosts = Vec::with_capacity(cidrs.len());
    for c in cidrs {
        hosts.push(normalize_host(c)?);
    }
    hosts.sort();
    hosts.dedup();

    let mut store = load(cfg)?;
    store
        .entries
        .retain(|_, e| !(e.identity == identity && e.vm_id.is_nil()));
    let remote = remote_vm_id();
    for ip in &hosts {
        store.entries.insert(
            ip.clone(),
            IpcacheEntry {
                ip: ip.clone(),
                identity,
                vm_id: remote,
            },
        );
    }
    save(cfg, &store)?;
    Ok(hosts.len())
}

/// Remove remote (nil-`vm_id`) rows for `identity`. Local VM rows are kept.
pub fn remove_remote_identity(cfg: &Config, identity: u32) -> Result<usize> {
    let mut store = load(cfg)?;
    let before = store.entries.len();
    store
        .entries
        .retain(|_, e| !(e.identity == identity && e.vm_id.is_nil()));
    let removed = before.saturating_sub(store.entries.len());
    if removed > 0 {
        save(cfg, &store)?;
    }
    Ok(removed)
}

pub fn remove_vm(cfg: &Config, vm_id: Uuid) -> Result<()> {
    if vm_id.is_nil() {
        bail!("refusing to remove_vm for nil remote sentinel; use remove_remote_identity");
    }
    let mut store = load(cfg)?;
    store.entries.retain(|_, e| e.vm_id != vm_id);
    save(cfg, &store)
}

pub fn list(cfg: &Config) -> Result<Vec<IpcacheEntry>> {
    Ok(load(cfg)?.entries.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::config::Config;
    use tempfile::tempdir;

    fn cfg_at(dir: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        cfg.state_dir = dir.to_path_buf();
        cfg
    }

    #[test]
    fn remote_upsert_replace_and_delete() {
        let dir = tempdir().unwrap();
        let cfg = cfg_at(dir.path());
        let n = upsert_remote(&cfg, 1001, &["10.1.0.5/32".into(), "10.1.0.6/32".into()]).unwrap();
        assert_eq!(n, 2);
        let listed = list(&cfg).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|e| e.is_remote() && e.identity == 1001));

        // Replace set.
        upsert_remote(&cfg, 1001, &["10.1.0.7/32".into()]).unwrap();
        let listed = list(&cfg).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].ip, "10.1.0.7");

        assert_eq!(remove_remote_identity(&cfg, 1001).unwrap(), 1);
        assert!(list(&cfg).unwrap().is_empty());
    }

    #[test]
    fn remote_delete_preserves_local_vm_rows() {
        let dir = tempdir().unwrap();
        let cfg = cfg_at(dir.path());
        let vm = Uuid::new_v4();
        upsert(&cfg, "10.2.0.1", 1001, vm).unwrap();
        upsert_remote(&cfg, 1001, &["10.2.0.2/32".into()]).unwrap();
        assert_eq!(list(&cfg).unwrap().len(), 2);
        assert_eq!(remove_remote_identity(&cfg, 1001).unwrap(), 1);
        let left = list(&cfg).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].vm_id, vm);
    }
}
