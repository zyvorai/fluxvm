// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Multi-node sandbox metadata index.
//!
//! Set `FLUXVM_SANDBOX_STATE_URL` (e.g. `redis://127.0.0.1:6379`) to use Redis;
//! otherwise state is in-process (single node) and `fluxvm-agent` handles fleets.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxIndexEntry {
    pub id: String,
    pub node: String,
    pub status: String,
}

#[derive(Clone)]
enum Backend {
    Local(Arc<RwLock<HashMap<String, SandboxIndexEntry>>>),
    Redis(redis::aio::ConnectionManager),
}

#[derive(Clone)]
pub struct SharedSandboxIndex {
    backend: Backend,
}

impl Default for SharedSandboxIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedSandboxIndex {
    pub fn new() -> Self {
        Self {
            backend: Backend::Local(Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    pub async fn from_env() -> Result<Self> {
        match std::env::var("FLUXVM_SANDBOX_STATE_URL") {
            Ok(url) if !url.is_empty() => {
                let client = redis::Client::open(url.as_str()).context("parse Redis URL")?;
                let mgr = redis::aio::ConnectionManager::new(client)
                    .await
                    .context("connect Redis")?;
                tracing::info!(%url, "sandbox shared state using Redis");
                Ok(Self {
                    backend: Backend::Redis(mgr),
                })
            }
            _ => Ok(Self::new()),
        }
    }

    pub async fn upsert(&self, entry: SandboxIndexEntry) -> Result<()> {
        match &self.backend {
            Backend::Local(map) => {
                map.write().await.insert(entry.id.clone(), entry);
                Ok(())
            }
            Backend::Redis(mgr) => {
                let mut conn = mgr.clone();
                let key = format!("fluxvm:sandbox:{}", entry.id);
                let val = serde_json::to_string(&entry)?;
                redis::cmd("SET")
                    .arg(&key)
                    .arg(val)
                    .query_async::<()>(&mut conn)
                    .await
                    .context("redis SET")?;
                redis::cmd("SADD")
                    .arg("fluxvm:sandboxes")
                    .arg(&entry.id)
                    .query_async::<()>(&mut conn)
                    .await
                    .context("redis SADD")?;
                Ok(())
            }
        }
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        match &self.backend {
            Backend::Local(map) => {
                map.write().await.remove(id);
                Ok(())
            }
            Backend::Redis(mgr) => {
                let mut conn = mgr.clone();
                let key = format!("fluxvm:sandbox:{id}");
                let _: () = redis::cmd("DEL").arg(&key).query_async(&mut conn).await?;
                let _: () = redis::cmd("SREM")
                    .arg("fluxvm:sandboxes")
                    .arg(id)
                    .query_async(&mut conn)
                    .await?;
                Ok(())
            }
        }
    }

    pub async fn list(&self) -> Result<Vec<SandboxIndexEntry>> {
        match &self.backend {
            Backend::Local(map) => Ok(map.read().await.values().cloned().collect()),
            Backend::Redis(mgr) => {
                let mut conn = mgr.clone();
                let ids: Vec<String> = redis::cmd("SMEMBERS")
                    .arg("fluxvm:sandboxes")
                    .query_async(&mut conn)
                    .await
                    .unwrap_or_default();
                let mut out = Vec::new();
                for id in ids {
                    if let Some(e) = self.get(&id).await? {
                        out.push(e);
                    }
                }
                Ok(out)
            }
        }
    }

    pub async fn get(&self, id: &str) -> Result<Option<SandboxIndexEntry>> {
        match &self.backend {
            Backend::Local(map) => Ok(map.read().await.get(id).cloned()),
            Backend::Redis(mgr) => {
                let mut conn = mgr.clone();
                let key = format!("fluxvm:sandbox:{id}");
                let val: Option<String> = redis::cmd("GET")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(None);
                Ok(val.and_then(|v| serde_json::from_str(&v).ok()))
            }
        }
    }

    pub async fn export_json(&self) -> Result<String> {
        let items = self.list().await?;
        Ok(serde_json::to_string_pretty(&items)?)
    }
}
