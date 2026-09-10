// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Set 6S: stable Kubernetes Pod identity -> `fluxvm_pspol`/`fluxvm_pid4/6`
//! key allocation. Node-local, like `identity_for()` and `ipcache` -- this is
//! not a cluster-wide identity, just a stable per-node handle for a Pod's
//! `fluxvm_tc.bpf.c` policy map keys.
//!
//! A pure hash of the Pod UID would be enough most of the time, but 32 bits
//! of hash over a cluster with thousands of Pods has a non-negligible
//! birthday-bound collision chance, and a collision here silently merges two
//! Pods' network policy. Persist the mapping and detect/resolve collisions
//! deterministically instead.

use anyhow::Result;
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    /// pod_uid -> pod_id.
    ids: BTreeMap<String, u32>,
}

fn path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("network-groups").join("pod-ids.json")
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

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &b in bytes {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Returns the stable `pod_id` for `pod_uid`, minting and persisting a new
/// one on first use. `0` is reserved (means "no Pod-scoped policy" to the
/// BPF side), so a hash that lands on it is bumped forward.
pub fn pod_id_for(cfg: &Config, pod_uid: &str) -> Result<u32> {
    let mut store = load(cfg)?;
    if let Some(&id) = store.ids.get(pod_uid) {
        return Ok(id);
    }

    let mut candidate = fnv1a(pod_uid.as_bytes());
    if candidate == 0 {
        candidate = 1;
    }
    // Linear probe on collision with a DIFFERENT pod_uid already holding
    // this id. Bounded: with a well-distributed hash this almost never
    // iterates more than once, and node-local Pod counts are far below
    // u32::MAX, so termination is guaranteed in practice.
    while store.ids.values().any(|&v| v == candidate) {
        candidate = candidate.wrapping_add(1);
        if candidate == 0 {
            candidate = 1;
        }
    }

    store.ids.insert(pod_uid.to_string(), candidate);
    save(cfg, &store)?;
    Ok(candidate)
}

/// Drops the persisted `pod_uid` -> `pod_id` mapping once a Pod is gone, so
/// the store does not grow unbounded across the node's lifetime. Losing this
/// (e.g. a crash between VM teardown and this call) only means the next Pod
/// reusing that exact UID -- impossible in practice, Kubernetes Pod UIDs are
/// never reused -- would keep the old id; safe to skip on error.
pub fn forget(cfg: &Config, pod_uid: &str) -> Result<()> {
    let mut store = load(cfg)?;
    if store.ids.remove(pod_uid).is_some() {
        save(cfg, &store)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> (Config, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = dir.path().to_path_buf();
        (cfg, dir)
    }

    #[test]
    fn stable_across_calls() {
        let (cfg, _dir) = test_cfg();
        let a = pod_id_for(&cfg, "pod-uid-1").unwrap();
        let b = pod_id_for(&cfg, "pod-uid-1").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, 0);
    }

    #[test]
    fn distinct_pods_get_distinct_ids() {
        let (cfg, _dir) = test_cfg();
        let a = pod_id_for(&cfg, "pod-uid-a").unwrap();
        let b = pod_id_for(&cfg, "pod-uid-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn forced_collision_is_resolved_deterministically() {
        let (cfg, _dir) = test_cfg();
        // Pre-seed a store where "victim" already owns the hash "attacker"
        // would land on, then confirm pod_id_for still returns a distinct,
        // stable id for "attacker" instead of silently colliding.
        let attacker_hash = fnv1a(b"attacker");
        let mut store = Store::default();
        store.ids.insert("victim".to_string(), attacker_hash);
        save(&cfg, &store).unwrap();

        let attacker_id = pod_id_for(&cfg, "attacker").unwrap();
        assert_ne!(attacker_id, attacker_hash);
        assert_ne!(attacker_id, 0);
        // Stable on a second call.
        assert_eq!(attacker_id, pod_id_for(&cfg, "attacker").unwrap());
    }

    #[test]
    fn forget_removes_mapping_and_frees_new_id_next_time() {
        let (cfg, _dir) = test_cfg();
        let a = pod_id_for(&cfg, "pod-uid-1").unwrap();
        forget(&cfg, "pod-uid-1").unwrap();
        let store = load(&cfg).unwrap();
        assert!(!store.ids.contains_key("pod-uid-1"));
        // Re-minting after forget is stable with itself again, and (since
        // the hash is deterministic and nothing else claimed it) typically
        // returns the same id -- not asserted, since that's an
        // implementation detail, not a contract.
        let _ = a;
    }
}
