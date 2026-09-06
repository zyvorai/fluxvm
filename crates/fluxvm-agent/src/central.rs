// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Central fleet registry + proxy. Deliberately doesn't depend on
//! `fluxvm-core` — it treats `CreateVmRequest`/`VmRecord` bodies as opaque
//! JSON and just forwards them to the right node's own `fluxvm serve`,
//! the same way `fluxvm-kube`'s client does. This keeps the binary small
//! and means it never goes stale against the request/record schema; the
//! cost is no server-side validation beyond "is this valid JSON" — a node's
//! own `fluxvm serve` still does the real validation.

use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    os::unix::io::AsRawFd,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

/// A node is considered unhealthy (excluded from placement, and reported
/// but flagged in `GET /fleet/nodes`) once its last heartbeat is older
/// than this — generous relative to the node agent's own default 10s
/// heartbeat interval, so a couple of missed beats under load doesn't
/// falsely evict a node that's still fine.
const HEALTHY_WINDOW_SECS: i64 = 30;

/// Default vCPU/memory assumed per existing VM when estimating residual
/// capacity for placement (used when the create body omits sizes).
const DEFAULT_VM_VCPUS: u32 = 2;
const DEFAULT_VM_MEMORY_MIB: u64 = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub name: String,
    pub fluxvm_url: String,
    pub vcpus_total: u32,
    pub memory_mib_total: u64,
    pub vm_count: usize,
    pub last_seen: DateTime<Utc>,
}

impl NodeInfo {
    fn healthy(&self) -> bool {
        (Utc::now() - self.last_seen).num_seconds() < HEALTHY_WINDOW_SECS
    }

    fn estimated_used_vcpus(&self) -> u32 {
        (self.vm_count as u32).saturating_mul(DEFAULT_VM_VCPUS)
    }

    fn estimated_used_memory_mib(&self) -> u64 {
        (self.vm_count as u64).saturating_mul(DEFAULT_VM_MEMORY_MIB)
    }

    fn free_vcpus(&self) -> u32 {
        self.vcpus_total.saturating_sub(self.estimated_used_vcpus())
    }

    fn free_memory_mib(&self) -> u64 {
        self.memory_mib_total
            .saturating_sub(self.estimated_used_memory_mib())
    }

    /// Higher is better. Prefer residual capacity fraction; tie-break fewer
    /// VMs then lexicographic name (stable, deterministic).
    fn capacity_score(
        &self,
        request_vcpus: u32,
        request_mem: u64,
    ) -> Option<(i64, i64, i64, String)> {
        if !self.healthy() {
            return None;
        }
        if self.free_vcpus() < request_vcpus || self.free_memory_mib() < request_mem {
            // Still eligible if totals are tiny / estimates pessimistic —
            // fall through with low score rather than hard-exclude when
            // vm_count estimate overshoots; only exclude if totals themselves
            // cannot fit a single request.
            if self.vcpus_total < request_vcpus || self.memory_mib_total < request_mem {
                return None;
            }
        }
        let vcpu_frac = if self.vcpus_total == 0 {
            0
        } else {
            (self.free_vcpus() as i64 * 10_000) / self.vcpus_total as i64
        };
        let mem_frac = if self.memory_mib_total == 0 {
            0
        } else {
            (self.free_memory_mib() as i64 * 10_000) / self.memory_mib_total as i64
        };
        let residual = vcpu_frac.min(mem_frac);
        // Sort key for max: residual desc, -vm_count, -name (via reverse min)
        Some((residual, -(self.vm_count as i64), 0, self.name.clone()))
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub fluxvm_url: String,
    pub vcpus_total: u32,
    pub memory_mib_total: u64,
    pub vm_count: usize,
}

struct AppError(StatusCode, String);
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl<E: std::fmt::Display> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(StatusCode::BAD_GATEWAY, e.to_string())
    }
}

#[derive(Clone)]
struct Fleet {
    nodes: Arc<Mutex<HashMap<String, NodeInfo>>>,
    http: reqwest::Client,
    persist_path: Option<PathBuf>,
    lock_path: Option<PathBuf>,
    /// Shared secret; when `Some`, all `/fleet/*` routes require Bearer.
    token: Option<String>,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn auth_middleware(State(fleet): State<Fleet>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    let Some(expected) = fleet.token.as_deref() else {
        return next.run(req).await;
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    match presented {
        Some(t) if constant_time_eq(t, expected) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing or invalid bearer token"})),
        )
            .into_response(),
    }
}

fn load_persisted(path: &FsPath) -> HashMap<String, NodeInfo> {
    if !path.exists() {
        return HashMap::new();
    }
    match fs::read_to_string(path) {
        Ok(raw) if raw.trim().is_empty() => HashMap::new(),
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::warn!(error = %e, path = %path.display(), "failed to parse fleet registry; starting empty");
            HashMap::new()
        }),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "failed to read fleet registry");
            HashMap::new()
        }
    }
}

fn persist_nodes(path: &FsPath, lock_path: &FsPath, nodes: &HashMap<String, NodeInfo>) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let lock_file = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "opening fleet lock");
            return;
        }
    };
    if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "locking fleet registry"
        );
        return;
    }
    let tmp = path.with_extension("json.tmp");
    match serde_json::to_vec_pretty(nodes) {
        Ok(bytes) => {
            if let Err(e) = fs::write(&tmp, &bytes) {
                tracing::warn!(error = %e, "writing fleet registry tmp");
                return;
            }
            if let Err(e) = fs::rename(&tmp, path) {
                tracing::warn!(error = %e, "renaming fleet registry");
            }
        }
        Err(e) => tracing::warn!(error = %e, "serializing fleet registry"),
    }
}

pub struct CentralConfig {
    pub state_dir: PathBuf,
    pub token: Option<String>,
}

pub fn router(cfg: CentralConfig) -> Router {
    let persist_path = cfg.state_dir.join("fleet-nodes.json");
    let lock_path = cfg.state_dir.join("fleet-nodes.lock");
    let _ = fs::create_dir_all(&cfg.state_dir);
    let initial = load_persisted(&persist_path);
    tracing::info!(
        path = %persist_path.display(),
        nodes = initial.len(),
        "loaded fleet registry"
    );
    let fleet = Fleet {
        nodes: Arc::new(Mutex::new(initial)),
        http: reqwest::Client::new(),
        persist_path: Some(persist_path),
        lock_path: Some(lock_path),
        token: cfg.token,
    };
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
        .route("/fleet/register", post(register))
        .route("/fleet/nodes", get(list_nodes))
        .route("/fleet/vms", post(create_vm).get(list_vms))
        .route("/fleet/vms/{node}/{id}", axum::routing::delete(delete_vm))
        .layer(middleware::from_fn_with_state(
            fleet.clone(),
            auth_middleware,
        ))
        .with_state(fleet)
}

async fn register(State(fleet): State<Fleet>, Json(req): Json<RegisterRequest>) -> Json<Value> {
    let mut nodes = fleet.nodes.lock().await;
    nodes.insert(
        req.name.clone(),
        NodeInfo {
            name: req.name,
            fluxvm_url: req.fluxvm_url,
            vcpus_total: req.vcpus_total,
            memory_mib_total: req.memory_mib_total,
            vm_count: req.vm_count,
            last_seen: Utc::now(),
        },
    );
    if let (Some(path), Some(lock)) = (&fleet.persist_path, &fleet.lock_path) {
        persist_nodes(path, lock, &nodes);
    }
    Json(json!({"ok": true}))
}

async fn list_nodes(State(fleet): State<Fleet>) -> Json<Value> {
    let nodes = fleet.nodes.lock().await;
    let items: Vec<Value> = nodes
        .values()
        .map(|n| {
            json!({
                "name": n.name,
                "fluxvm_url": n.fluxvm_url,
                "vcpus_total": n.vcpus_total,
                "memory_mib_total": n.memory_mib_total,
                "vm_count": n.vm_count,
                "last_seen": n.last_seen,
                "healthy": n.healthy(),
                "free_vcpus": n.free_vcpus(),
                "free_memory_mib": n.free_memory_mib(),
            })
        })
        .collect();
    Json(json!({"items": items}))
}

/// Residual-capacity placement: prefer the healthy node with the highest
/// free CPU/memory fraction that can fit the request; tie-break by fewest
/// VMs then name.
fn pick_best_capacity(
    nodes: &HashMap<String, NodeInfo>,
    request_vcpus: u32,
    request_mem: u64,
) -> Option<NodeInfo> {
    nodes
        .values()
        .filter_map(|n| {
            n.capacity_score(request_vcpus, request_mem)
                .map(|score| (score, n))
        })
        .max_by(|(a, _), (b, _)| {
            a.0.cmp(&b.0)
                .then(a.1.cmp(&b.1))
                .then(a.3.cmp(&b.3).reverse())
        })
        .map(|(_, n)| n.clone())
}

fn request_sizes(body: &Value) -> (u32, u64) {
    let vcpus = body
        .get("vcpus")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(DEFAULT_VM_VCPUS);
    let mem = body
        .get("memory_mib")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_VM_MEMORY_MIB);
    (vcpus, mem)
}

/// `POST /fleet/vms`. Body is a normal `CreateVmRequest` JSON, optionally
/// with a top-level `"node"` field naming an exact node to target — when
/// absent, residual-capacity placement picks a healthy node.
async fn create_vm(
    State(fleet): State<Fleet>,
    Json(mut body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let requested_node = body
        .as_object_mut()
        .and_then(|o| o.remove("node"))
        .and_then(|v| v.as_str().map(str::to_string));

    let (req_vcpus, req_mem) = request_sizes(&body);

    let target = {
        let nodes = fleet.nodes.lock().await;
        match requested_node {
            Some(name) => nodes.get(&name).cloned().ok_or_else(|| {
                AppError(
                    StatusCode::BAD_REQUEST,
                    format!("no registered node named '{name}'"),
                )
            })?,
            None => pick_best_capacity(&nodes, req_vcpus, req_mem).ok_or_else(|| {
                AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no healthy nodes registered".into(),
                )
            })?,
        }
    };

    let resp = fleet
        .http
        .post(format!("{}/v1/vms", target.fluxvm_url))
        .json(&body)
        .send()
        .await?;
    let status = resp.status();
    let record: Value = resp.json().await?;
    if !status.is_success() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            format!("node '{}' rejected create: {record}", target.name),
        ));
    }
    Ok(Json(json!({"node": target.name, "vm": record})))
}

async fn list_vms(State(fleet): State<Fleet>) -> Json<Value> {
    let targets: Vec<NodeInfo> = {
        fleet
            .nodes
            .lock()
            .await
            .values()
            .filter(|n| n.healthy())
            .cloned()
            .collect()
    };
    let mut items = Vec::new();
    for node in targets {
        match fleet
            .http
            .get(format!("{}/v1/vms", node.fluxvm_url))
            .send()
            .await
        {
            Ok(resp) => match resp.json::<Value>().await {
                Ok(body) => {
                    if let Some(node_items) = body.get("items").and_then(|v| v.as_array()) {
                        for mut vm in node_items.clone() {
                            if let Some(obj) = vm.as_object_mut() {
                                obj.insert("node".into(), json!(node.name));
                            }
                            items.push(vm);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(node = %node.name, error = %e, "failed to parse node's VM list")
                }
            },
            Err(e) => {
                tracing::warn!(node = %node.name, error = %e, "failed to reach node for fleet-wide list")
            }
        }
    }
    Json(json!({"items": items}))
}

async fn delete_vm(
    State(fleet): State<Fleet>,
    Path((node, id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    let target = {
        let nodes = fleet.nodes.lock().await;
        nodes.get(&node).cloned().ok_or_else(|| {
            AppError(
                StatusCode::BAD_REQUEST,
                format!("no registered node named '{node}'"),
            )
        })?
    };
    let resp = fleet
        .http
        .delete(format!("{}/v1/vms/{}", target.fluxvm_url, id))
        .send()
        .await?;
    let status = resp.status();
    if status.is_success() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(AppError(
            StatusCode::BAD_GATEWAY,
            format!("node '{node}' rejected delete: {body}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, vm_count: usize, age_secs: i64) -> NodeInfo {
        NodeInfo {
            name: name.into(),
            fluxvm_url: format!("http://{name}"),
            vcpus_total: 8,
            memory_mib_total: 16384,
            vm_count,
            last_seen: Utc::now() - chrono::Duration::seconds(age_secs),
        }
    }

    fn node_cap(name: &str, vm_count: usize, vcpus: u32, mem: u64) -> NodeInfo {
        NodeInfo {
            name: name.into(),
            fluxvm_url: format!("http://{name}"),
            vcpus_total: vcpus,
            memory_mib_total: mem,
            vm_count,
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn picks_node_with_more_residual_capacity() {
        let mut nodes = HashMap::new();
        // a: 1 VM → ~2/8 vCPU used; b: 3 VMs → ~6/8 used
        nodes.insert("a".to_string(), node("a", 1, 0));
        nodes.insert("b".to_string(), node("b", 3, 0));
        let picked = pick_best_capacity(&nodes, 2, 2048).unwrap();
        assert_eq!(picked.name, "a");
    }

    #[test]
    fn prefers_host_that_can_fit_when_other_is_saturated() {
        let mut nodes = HashMap::new();
        // small: 2 vCPU total, already 1 VM (est. 2 used) → can't fit another 2-vCPU request by totals
        // large: plenty of room
        nodes.insert("small".to_string(), node_cap("small", 1, 2, 2048));
        nodes.insert("large".to_string(), node_cap("large", 1, 64, 131072));
        let picked = pick_best_capacity(&nodes, 2, 2048).unwrap();
        assert_eq!(picked.name, "large");
    }

    #[test]
    fn skips_stale_nodes() {
        let mut nodes = HashMap::new();
        nodes.insert(
            "stale".to_string(),
            node("stale", 0, HEALTHY_WINDOW_SECS + 5),
        );
        nodes.insert("fresh".to_string(), node("fresh", 5, 0));
        let picked = pick_best_capacity(&nodes, 2, 2048).unwrap();
        assert_eq!(picked.name, "fresh");
    }

    #[test]
    fn returns_none_when_no_node_is_healthy() {
        let mut nodes = HashMap::new();
        nodes.insert(
            "stale".to_string(),
            node("stale", 0, HEALTHY_WINDOW_SECS + 5),
        );
        assert!(pick_best_capacity(&nodes, 2, 2048).is_none());
    }

    #[test]
    fn ties_break_by_name_for_determinism() {
        let mut nodes = HashMap::new();
        nodes.insert("z".to_string(), node("z", 1, 0));
        nodes.insert("a".to_string(), node("a", 1, 0));
        let picked = pick_best_capacity(&nodes, 2, 2048).unwrap();
        assert_eq!(picked.name, "a");
    }

    #[test]
    fn request_sizes_defaults() {
        assert_eq!(request_sizes(&json!({})), (2, 2048));
        assert_eq!(
            request_sizes(&json!({"vcpus": 4, "memory_mib": 4096})),
            (4, 4096)
        );
    }
}
