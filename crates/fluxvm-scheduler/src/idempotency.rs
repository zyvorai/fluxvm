// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Durable store behind the API's `Idempotency-Key` header
//! (`<state_dir>/idempotency/<sha256(tenant, route, key)>.json`).
//!
//! A client that loses the response to a create, delete, snapshot or fork
//! retries with the same key and gets the stored response back instead of a
//! second VM (or a 404 for the delete that already worked). Records are
//! fsynced before the response is released, expire after [`TTL_SECS`], and a
//! key reused with a different request is a conflict, never a replay.

use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// How long a stored response stays replayable.
pub const TTL_SECS: i64 = 24 * 60 * 60;

/// A response captured for replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Stored {
    /// Unix seconds when the response was stored.
    pub created_at: i64,
    /// Hash of method, path and body of the request that produced it.
    pub fingerprint: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Response body, base64.
    pub body_b64: String,
}

impl Stored {
    pub fn new(
        now: i64,
        fingerprint: String,
        status: u16,
        content_type: Option<String>,
        body: &[u8],
    ) -> Self {
        Self {
            created_at: now,
            fingerprint,
            status,
            content_type,
            body_b64: base64::engine::general_purpose::STANDARD.encode(body),
        }
    }

    pub fn body(&self) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.body_b64)
            .unwrap_or_default()
    }
}

/// What the store knows about a key.
#[derive(Debug, PartialEq)]
pub enum Lookup {
    /// Never seen (or expired): run the request.
    Miss,
    /// Seen with the same request: send this back.
    Replay(Stored),
    /// Seen with a different request.
    Conflict,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Identity of a key: scoped by tenant (or caller) and route, so two callers
/// that pick the same key never see each other's responses.
pub fn key_hash(tenant: &str, route: &str, key: &str) -> String {
    let mut h = Sha256::new();
    for part in [tenant, route, key] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex(&h.finalize())
}

/// Identity of a request: method, path and the exact body bytes.
pub fn fingerprint(method: &str, path: &str, body: &[u8]) -> String {
    let mut h = Sha256::new();
    for part in [method.as_bytes(), path.as_bytes(), body] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    hex(&h.finalize())
}

fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("idempotency")
}

fn path_for(state_dir: &Path, key_hash: &str) -> PathBuf {
    dir(state_dir).join(format!("{key_hash}.json"))
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Looks `key_hash` up. An expired record counts as a miss and is removed.
pub fn lookup(state_dir: &Path, key_hash: &str, fingerprint: &str, now: i64) -> Lookup {
    if !is_hash(key_hash) {
        return Lookup::Miss;
    }
    let path = path_for(state_dir, key_hash);
    let Ok(raw) = fs::read(&path) else {
        return Lookup::Miss;
    };
    let Ok(stored) = serde_json::from_slice::<Stored>(&raw) else {
        // Unreadable (torn by something other than our own atomic rename):
        // behave as if the key was never used.
        return Lookup::Miss;
    };
    if now - stored.created_at >= TTL_SECS {
        let _ = fs::remove_file(&path);
        return Lookup::Miss;
    }
    if stored.fingerprint == fingerprint {
        Lookup::Replay(stored)
    } else {
        Lookup::Conflict
    }
}

/// Durably stores `stored`; returns only once it is on disk.
pub fn store(state_dir: &Path, key_hash: &str, stored: &Stored) -> Result<()> {
    anyhow::ensure!(is_hash(key_hash), "malformed idempotency key hash");
    let d = dir(state_dir);
    fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    let path = path_for(state_dir, key_hash);
    let tmp = path.with_extension("json.tmp");
    fluxvm_storage::write_durable(&tmp, &path, &serde_json::to_vec(stored)?)
        .with_context(|| format!("writing {}", path.display()))
}

/// Removes expired records (and stray temp files older than the TTL).
/// Returns how many files were removed.
pub fn purge_expired(state_dir: &Path, now: i64) -> usize {
    let Ok(rd) = fs::read_dir(dir(state_dir)) else {
        return 0;
    };
    let mut removed = 0;
    for e in rd.flatten() {
        let path = e.path();
        let expired = match path.extension().and_then(|x| x.to_str()) {
            Some("json") => fs::read(&path)
                .ok()
                .and_then(|raw| serde_json::from_slice::<Stored>(&raw).ok())
                .is_none_or(|s| now - s.created_at >= TTL_SECS),
            Some("tmp") => e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .is_none_or(|t| now - t.as_secs() as i64 >= TTL_SECS),
            _ => false,
        };
        if expired && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn sample(fp: &str, at: i64) -> Stored {
        Stored::new(
            at,
            fp.into(),
            201,
            Some("application/json".into()),
            br#"{"id":"x"}"#,
        )
    }

    #[test]
    fn key_is_scoped_by_tenant_route_and_key() {
        let a = key_hash("acme", "POST /v1/vms", "k1");
        assert_eq!(a, key_hash("acme", "POST /v1/vms", "k1"));
        assert_ne!(a, key_hash("other", "POST /v1/vms", "k1"));
        assert_ne!(a, key_hash("acme", "DELETE /v1/vms/x", "k1"));
        assert_ne!(a, key_hash("acme", "POST /v1/vms", "k2"));
        // Field boundaries are part of the hash.
        assert_ne!(key_hash("ab", "c", "d"), key_hash("a", "bc", "d"));
        assert!(is_hash(&a));
    }

    #[test]
    fn miss_then_replay_then_conflict() {
        let td = tempfile::tempdir().unwrap();
        let k = key_hash("t", "POST /v1/vms", "abc");
        let fp = fingerprint("POST", "/v1/vms", b"{\"name\":\"a\"}");
        assert_eq!(lookup(td.path(), &k, &fp, NOW), Lookup::Miss);

        store(td.path(), &k, &sample(&fp, NOW)).unwrap();
        match lookup(td.path(), &k, &fp, NOW + 60) {
            Lookup::Replay(s) => {
                assert_eq!(s.status, 201);
                assert_eq!(s.body(), br#"{"id":"x"}"#.to_vec());
                assert_eq!(s.content_type.as_deref(), Some("application/json"));
            }
            other => panic!("expected replay, got {other:?}"),
        }

        let other_body = fingerprint("POST", "/v1/vms", b"{\"name\":\"b\"}");
        assert_eq!(
            lookup(td.path(), &k, &other_body, NOW + 60),
            Lookup::Conflict
        );
    }

    #[test]
    fn records_expire_after_the_ttl() {
        let td = tempfile::tempdir().unwrap();
        let k = key_hash("t", "r", "k");
        store(td.path(), &k, &sample("fp", NOW)).unwrap();
        assert!(matches!(
            lookup(td.path(), &k, "fp", NOW + TTL_SECS - 1),
            Lookup::Replay(_)
        ));
        assert_eq!(lookup(td.path(), &k, "fp", NOW + TTL_SECS), Lookup::Miss);
        // The expired record is gone, so a different body is no longer a conflict.
        assert_eq!(lookup(td.path(), &k, "other", NOW + TTL_SECS), Lookup::Miss);
    }

    #[test]
    fn purge_removes_only_expired_and_unreadable_records() {
        let td = tempfile::tempdir().unwrap();
        let old = key_hash("t", "r", "old");
        let fresh = key_hash("t", "r", "fresh");
        store(td.path(), &old, &sample("fp", NOW - TTL_SECS - 1)).unwrap();
        store(td.path(), &fresh, &sample("fp", NOW - 10)).unwrap();
        fs::write(
            path_for(td.path(), &key_hash("t", "r", "junk")),
            b"not json",
        )
        .unwrap();
        assert_eq!(purge_expired(td.path(), NOW), 2);
        assert!(matches!(
            lookup(td.path(), &fresh, "fp", NOW),
            Lookup::Replay(_)
        ));
        assert_eq!(purge_expired(td.path(), NOW), 0);
        // No directory at all is fine.
        assert_eq!(purge_expired(&td.path().join("missing"), NOW), 0);
    }

    #[test]
    fn malformed_hashes_never_touch_the_filesystem() {
        let td = tempfile::tempdir().unwrap();
        assert_eq!(
            lookup(td.path(), "../../etc/passwd", "fp", NOW),
            Lookup::Miss
        );
        assert!(store(td.path(), "../x", &sample("fp", NOW)).is_err());
    }
}
