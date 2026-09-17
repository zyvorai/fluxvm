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
    /// Operator-set maintenance flag (`POST /fleet/nodes/{name}/cordon`):
    /// excludes this node from automatic (residual-capacity) placement in
    /// `pick_best_capacity` without deregistering it or touching any VM
    /// already on it — same "stop scheduling here, don't evict anything"
    /// semantics as `kubectl cordon`. `#[serde(default)]` so a
    /// `fleet-nodes.json` written before this field existed still loads
    /// cleanly (as `false`, the honest "never cordoned" value).
    #[serde(default)]
    pub cordoned: bool,
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
        if !self.healthy() || self.cordoned {
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

#[derive(Debug)]
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
        .route(
            "/fleet/nodes/{name}",
            axum::routing::delete(deregister_node),
        )
        .route("/fleet/nodes/{name}/cordon", post(cordon_node))
        .route("/fleet/nodes/{name}/uncordon", post(uncordon_node))
        .route("/fleet/vms", post(create_vm).get(list_vms))
        .route("/fleet/nodes/{name}/vms", get(node_vms))
        .route("/fleet/vms/{node}/{id}", axum::routing::delete(delete_vm))
        .layer(middleware::from_fn_with_state(
            fleet.clone(),
            auth_middleware,
        ))
        .with_state(fleet)
}

/// Insert/update a node from a heartbeat. A brand-new node starts
/// uncordoned; a node that's already registered keeps whatever `cordoned`
/// state an operator previously set on it — a node agent has no idea
/// cordoning exists and its heartbeat body carries no such field, so a
/// naive overwrite-on-every-beat would silently un-cordon a node the very
/// next time its own agent reported in, seconds after an operator cordoned
/// it for maintenance.
fn apply_register(nodes: &mut HashMap<String, NodeInfo>, req: RegisterRequest) {
    let cordoned = nodes.get(&req.name).map(|n| n.cordoned).unwrap_or(false);
    nodes.insert(
        req.name.clone(),
        NodeInfo {
            name: req.name,
            fluxvm_url: req.fluxvm_url,
            vcpus_total: req.vcpus_total,
            memory_mib_total: req.memory_mib_total,
            vm_count: req.vm_count,
            last_seen: Utc::now(),
            cordoned,
        },
    );
}

async fn register(State(fleet): State<Fleet>, Json(req): Json<RegisterRequest>) -> Json<Value> {
    let mut nodes = fleet.nodes.lock().await;
    apply_register(&mut nodes, req);
    if let (Some(path), Some(lock)) = (&fleet.persist_path, &fleet.lock_path) {
        persist_nodes(path, lock, &nodes);
    }
    Json(json!({"ok": true}))
}

fn node_json(n: &NodeInfo) -> Value {
    json!({
        "name": n.name,
        "fluxvm_url": n.fluxvm_url,
        "vcpus_total": n.vcpus_total,
        "memory_mib_total": n.memory_mib_total,
        "vm_count": n.vm_count,
        "last_seen": n.last_seen,
        "healthy": n.healthy(),
        "cordoned": n.cordoned,
        "free_vcpus": n.free_vcpus(),
        "free_memory_mib": n.free_memory_mib(),
    })
}

async fn list_nodes(State(fleet): State<Fleet>) -> Json<Value> {
    let nodes = fleet.nodes.lock().await;
    let items: Vec<Value> = nodes.values().map(node_json).collect();
    Json(json!({"items": items}))
}

/// Set (or clear) a node's cordoned flag. Returns `None` if no node by
/// that name is registered — cordoning an unregistered name is a no-op
/// error, not a way to pre-seed a node record.
fn set_cordoned(nodes: &mut HashMap<String, NodeInfo>, name: &str, cordoned: bool) -> Option<()> {
    let node = nodes.get_mut(name)?;
    node.cordoned = cordoned;
    Some(())
}

async fn cordon_node(
    State(fleet): State<Fleet>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    set_node_cordoned(fleet, name, true).await
}

async fn uncordon_node(
    State(fleet): State<Fleet>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    set_node_cordoned(fleet, name, false).await
}

async fn set_node_cordoned(
    fleet: Fleet,
    name: String,
    cordoned: bool,
) -> Result<Json<Value>, AppError> {
    let mut nodes = fleet.nodes.lock().await;
    if set_cordoned(&mut nodes, &name, cordoned).is_none() {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            format!("no registered node named '{name}'"),
        ));
    }
    let updated = node_json(nodes.get(&name).expect("just set"));
    if let (Some(path), Some(lock)) = (&fleet.persist_path, &fleet.lock_path) {
        persist_nodes(path, lock, &nodes);
    }
    Ok(Json(updated))
}

/// Outcome of attempting to permanently remove a node's registry entry.
/// Kept as its own enum (rather than folding into `set_cordoned`'s
/// `Option<()>`) because deregistration has a second failure mode —
/// refusing to touch a node that's still heartbeating — that needs its own
/// HTTP status, not just "found or not".
enum DeregisterOutcome {
    Removed,
    NotFound,
    StillHealthy,
}

/// Remove a node's entry entirely, but only once its heartbeat has already
/// gone stale. Deliberately narrower than cordoning: cordoning suppresses
/// *future* automatic placement while leaving the record (and its
/// `cordoned` flag) intact forever; this erases the record outright, which
/// is only safe once nothing will resurrect it with the wrong state. If
/// the node were still healthy, `apply_register` would treat its very next
/// heartbeat as a brand-new node and re-insert it uncordoned (see
/// `apply_register`'s doc comment) — silently undoing any cordon an
/// operator had set and defeating the maintenance workflow cordon exists
/// for. Requiring staleness first means an operator decommissioning a live
/// host has one unambiguous path: stop that host's `fluxvm-agent node`
/// process (or otherwise let its heartbeat lapse) and wait past
/// `HEALTHY_WINDOW_SECS`, then deregister — never a race between "delete"
/// and "the next heartbeat wins".
fn deregister(nodes: &mut HashMap<String, NodeInfo>, name: &str) -> DeregisterOutcome {
    match nodes.get(name) {
        None => DeregisterOutcome::NotFound,
        Some(n) if n.healthy() => DeregisterOutcome::StillHealthy,
        Some(_) => {
            nodes.remove(name);
            DeregisterOutcome::Removed
        }
    }
}

/// `DELETE /fleet/nodes/{name}` — permanently forget a decommissioned or
/// retired node, so it stops appearing in `GET /fleet/nodes` forever (a
/// stale node otherwise sits in the registry indefinitely, excluded from
/// placement by its own staleness but never actually cleaned up). Returns
/// `404` for a name that was never registered, and `409` for a node whose
/// heartbeat is still fresh — see `deregister`'s doc comment for why a
/// live node can't be deregistered directly.
async fn deregister_node(
    State(fleet): State<Fleet>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut nodes = fleet.nodes.lock().await;
    match deregister(&mut nodes, &name) {
        DeregisterOutcome::Removed => {
            if let (Some(path), Some(lock)) = (&fleet.persist_path, &fleet.lock_path) {
                persist_nodes(path, lock, &nodes);
            }
            Ok(StatusCode::NO_CONTENT)
        }
        DeregisterOutcome::NotFound => Err(AppError(
            StatusCode::NOT_FOUND,
            format!("no registered node named '{name}'"),
        )),
        DeregisterOutcome::StillHealthy => Err(AppError(
            StatusCode::CONFLICT,
            format!(
                "node '{name}' is still heartbeating; stop its fluxvm-agent node process (or otherwise let its heartbeat lapse) and wait for it to go stale before deregistering, or its next heartbeat will simply re-register it"
            ),
        )),
    }
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

/// Resolve which node a `POST /fleet/vms` should land on. An explicit
/// `"node"` name bypasses placement entirely — including a cordoned
/// node — the same way a Kubernetes Pod with `spec.nodeName` set bypasses
/// the scheduler and can still land on a cordoned node: cordoning only
/// ever removes a node from *automatic* placement's candidate set, it was
/// never a per-node admission check. Automatic (no `"node"` given)
/// placement excludes cordoned nodes via `pick_best_capacity` ->
/// `capacity_score` regardless of how much free capacity they have.
fn resolve_target(
    nodes: &HashMap<String, NodeInfo>,
    requested_node: Option<String>,
    req_vcpus: u32,
    req_mem: u64,
) -> Result<NodeInfo, AppError> {
    match requested_node {
        Some(name) => nodes.get(&name).cloned().ok_or_else(|| {
            AppError(
                StatusCode::BAD_REQUEST,
                format!("no registered node named '{name}'"),
            )
        }),
        None => pick_best_capacity(nodes, req_vcpus, req_mem).ok_or_else(|| {
            AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                "no healthy, uncordoned nodes registered".into(),
            )
        }),
    }
}

/// `POST /fleet/vms`. Body is a normal `CreateVmRequest` JSON, optionally
/// with a top-level `"node"` field naming an exact node to target — when
/// absent, residual-capacity placement picks a healthy, uncordoned node.
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
        resolve_target(&nodes, requested_node, req_vcpus, req_mem)?
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

/// `GET /fleet/vms` — the fleet-wide aggregate. Every node this couldn't
/// account for (excluded up front as unhealthy, or one whose query failed
/// partway through) is named in `"unreachable_nodes"` alongside a short
/// reason, instead of being silently absent from `"items"` with only a
/// server-side `tracing::warn!` the caller never sees — the same
/// surface-don't-hide fix `GET /fleet/nodes/{name}/vms` already applies to
/// the single-node case, extended to the aggregate. A caller that cares
/// whether the list it just got is complete can check this field is empty;
/// one that doesn't can ignore it exactly like before.
async fn list_vms(State(fleet): State<Fleet>) -> Json<Value> {
    let (targets, mut unreachable): (Vec<NodeInfo>, Vec<Value>) = {
        let nodes = fleet.nodes.lock().await;
        let mut targets = Vec::new();
        let mut unreachable = Vec::new();
        for node in nodes.values() {
            if node.healthy() {
                targets.push(node.clone());
            } else {
                unreachable.push(json!({
                    "node": node.name,
                    "reason": "unhealthy (stale heartbeat)",
                }));
            }
        }
        (targets, unreachable)
    };
    let mut items = Vec::new();
    for node in targets {
        match fleet
            .http
            .get(format!("{}/v1/vms", node.fluxvm_url))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                match resp.json::<Value>().await {
                    Ok(body) => {
                        if !status.is_success() {
                            tracing::warn!(node = %node.name, %status, body = %body, "node rejected fleet-wide list");
                            unreachable.push(json!({
                                "node": node.name,
                                "reason": format!("node rejected list ({status}): {body}"),
                            }));
                            continue;
                        }
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
                        tracing::warn!(node = %node.name, error = %e, "failed to parse node's VM list");
                        unreachable.push(json!({
                            "node": node.name,
                            "reason": format!("failed to parse node's VM list: {e}"),
                        }));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(node = %node.name, error = %e, "failed to reach node for fleet-wide list");
                unreachable.push(json!({
                    "node": node.name,
                    "reason": format!("unreachable: {e}"),
                }));
            }
        }
    }
    Json(json!({"items": items, "unreachable_nodes": unreachable}))
}

/// `GET /fleet/nodes/{name}/vms` — the VMs on exactly one node, queried
/// directly against that node's own `fluxvm serve` rather than the
/// fleet-wide aggregate `GET /fleet/vms` produces. Two reasons this earns
/// its own route instead of leaving callers to filter the fleet-wide list
/// client-side: it works even when *other* nodes in the fleet are
/// unreachable or stale — the fleet-wide list no longer silently drops a
/// node it can't reach (it names every such node in its own
/// `"unreachable_nodes"` field), but still requires every *other* node to
/// answer too just to learn about this one; this route needs none of them
/// — and it surfaces a failure to reach *this* node as a hard `502` instead
/// of a field in an otherwise-200 response the caller has to remember to
/// check. This is the natural "what's actually running here?" check before
/// cordoning a node for maintenance (or before deciding a cordon is safe to
/// lift) — cordoning alone only tells you whether a node *is* excluded from
/// new placement, not what's already on it.
async fn node_vms(
    State(fleet): State<Fleet>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    let target = {
        let nodes = fleet.nodes.lock().await;
        nodes.get(&name).cloned().ok_or_else(|| {
            AppError(
                StatusCode::BAD_REQUEST,
                format!("no registered node named '{name}'"),
            )
        })?
    };
    let resp = fleet
        .http
        .get(format!("{}/v1/vms", target.fluxvm_url))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await?;
    if !status.is_success() {
        return Err(AppError(
            StatusCode::BAD_GATEWAY,
            format!("node '{name}' rejected list: {body}"),
        ));
    }
    let mut items: Vec<Value> = body
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for vm in items.iter_mut() {
        if let Some(obj) = vm.as_object_mut() {
            obj.insert("node".into(), json!(target.name));
        }
    }
    Ok(Json(json!({"node": target.name, "items": items})))
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
            cordoned: false,
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
            cordoned: false,
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

    #[test]
    fn cordoned_node_excluded_from_automatic_placement() {
        let mut nodes = HashMap::new();
        let mut a = node("a", 0, 0); // most free capacity, but cordoned
        a.cordoned = true;
        nodes.insert("a".to_string(), a);
        nodes.insert("b".to_string(), node("b", 3, 0));
        let picked = pick_best_capacity(&nodes, 2, 2048).unwrap();
        assert_eq!(picked.name, "b");
    }

    #[test]
    fn cordoning_the_only_node_leaves_nothing_placeable() {
        let mut nodes = HashMap::new();
        let mut a = node("a", 0, 0);
        a.cordoned = true;
        nodes.insert("a".to_string(), a);
        assert!(pick_best_capacity(&nodes, 2, 2048).is_none());
    }

    #[test]
    fn uncordoning_restores_eligibility() {
        let mut nodes = HashMap::new();
        let mut a = node("a", 0, 0);
        a.cordoned = true;
        nodes.insert("a".to_string(), a);
        assert!(pick_best_capacity(&nodes, 2, 2048).is_none());
        set_cordoned(&mut nodes, "a", false).unwrap();
        let picked = pick_best_capacity(&nodes, 2, 2048).unwrap();
        assert_eq!(picked.name, "a");
    }

    #[test]
    fn set_cordoned_reports_none_for_unknown_node() {
        let mut nodes = HashMap::new();
        nodes.insert("a".to_string(), node("a", 0, 0));
        assert!(set_cordoned(&mut nodes, "nonexistent", true).is_none());
    }

    #[test]
    fn heartbeat_preserves_existing_cordoned_state() {
        let mut nodes = HashMap::new();
        nodes.insert("a".to_string(), node("a", 0, 0));
        set_cordoned(&mut nodes, "a", true).unwrap();
        assert!(nodes["a"].cordoned);

        // A fresh heartbeat carries no cordon information at all — it must
        // not silently un-cordon the node.
        apply_register(
            &mut nodes,
            RegisterRequest {
                name: "a".into(),
                fluxvm_url: "http://a".into(),
                vcpus_total: 8,
                memory_mib_total: 16384,
                vm_count: 1,
            },
        );
        assert!(nodes["a"].cordoned);
        assert_eq!(nodes["a"].vm_count, 1); // other fields still update
    }

    #[test]
    fn first_ever_heartbeat_registers_uncordoned() {
        let mut nodes = HashMap::new();
        apply_register(
            &mut nodes,
            RegisterRequest {
                name: "new".into(),
                fluxvm_url: "http://new".into(),
                vcpus_total: 4,
                memory_mib_total: 8192,
                vm_count: 0,
            },
        );
        assert!(!nodes["new"].cordoned);
    }

    #[test]
    fn explicit_node_targeting_bypasses_cordon() {
        let mut nodes = HashMap::new();
        let mut a = node("a", 0, 0);
        a.cordoned = true;
        nodes.insert("a".to_string(), a);
        // Automatic placement finds nothing...
        assert!(pick_best_capacity(&nodes, 2, 2048).is_none());
        // ...but an explicit "node":"a" still resolves, same as a
        // Kubernetes Pod with spec.nodeName bypassing the scheduler.
        let target = resolve_target(&nodes, Some("a".to_string()), 2, 2048).unwrap();
        assert_eq!(target.name, "a");
    }

    #[test]
    fn explicit_node_targeting_unknown_name_still_errors() {
        let nodes: HashMap<String, NodeInfo> = HashMap::new();
        let err = resolve_target(&nodes, Some("ghost".to_string()), 2, 2048).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn automatic_placement_skips_cordoned_even_with_more_capacity() {
        let mut nodes = HashMap::new();
        let mut roomy = node_cap("roomy", 0, 64, 131072);
        roomy.cordoned = true;
        nodes.insert("roomy".to_string(), roomy);
        nodes.insert("tight".to_string(), node_cap("tight", 1, 4, 8192));
        let target = resolve_target(&nodes, None, 2, 2048).unwrap();
        assert_eq!(target.name, "tight");
    }

    // --- DELETE /fleet/nodes/{name} ---

    #[test]
    fn deregister_removes_a_stale_node() {
        let mut nodes = HashMap::new();
        nodes.insert(
            "stale".to_string(),
            node("stale", 0, HEALTHY_WINDOW_SECS + 5),
        );
        assert!(matches!(
            deregister(&mut nodes, "stale"),
            DeregisterOutcome::Removed
        ));
        assert!(!nodes.contains_key("stale"));
    }

    #[test]
    fn deregister_refuses_a_healthy_node() {
        let mut nodes = HashMap::new();
        nodes.insert("fresh".to_string(), node("fresh", 0, 0));
        assert!(matches!(
            deregister(&mut nodes, "fresh"),
            DeregisterOutcome::StillHealthy
        ));
        // Refused — the record must still be there afterward.
        assert!(nodes.contains_key("fresh"));
    }

    #[test]
    fn deregister_unknown_node_is_not_found() {
        let mut nodes: HashMap<String, NodeInfo> = HashMap::new();
        assert!(matches!(
            deregister(&mut nodes, "ghost"),
            DeregisterOutcome::NotFound
        ));
    }

    #[test]
    fn deregister_then_new_heartbeat_recreates_uncordoned() {
        // Documents the exact hazard `deregister` refusing a healthy node
        // guards against: once a record is actually gone, the next
        // heartbeat for that name is indistinguishable from a brand-new
        // node and re-registers uncordoned, regardless of what the erased
        // record's `cordoned` flag used to say.
        let mut nodes = HashMap::new();
        let mut a = node("a", 0, HEALTHY_WINDOW_SECS + 5);
        a.cordoned = true;
        nodes.insert("a".to_string(), a);
        assert!(matches!(
            deregister(&mut nodes, "a"),
            DeregisterOutcome::Removed
        ));
        apply_register(
            &mut nodes,
            RegisterRequest {
                name: "a".into(),
                fluxvm_url: "http://a".into(),
                vcpus_total: 8,
                memory_mib_total: 16384,
                vm_count: 0,
            },
        );
        assert!(!nodes["a"].cordoned);
    }

    #[tokio::test]
    async fn deregister_node_http_removes_a_stale_node() {
        let mut nodes = HashMap::new();
        nodes.insert(
            "stale".to_string(),
            node("stale", 0, HEALTHY_WINDOW_SECS + 5),
        );
        let fleet = test_fleet(nodes);
        let status = deregister_node(State(fleet.clone()), Path("stale".to_string()))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!fleet.nodes.lock().await.contains_key("stale"));
    }

    #[tokio::test]
    async fn deregister_node_http_conflicts_on_a_healthy_node() {
        let mut nodes = HashMap::new();
        nodes.insert("fresh".to_string(), node("fresh", 0, 0));
        let fleet = test_fleet(nodes);
        let err = deregister_node(State(fleet.clone()), Path("fresh".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert!(fleet.nodes.lock().await.contains_key("fresh"));
    }

    #[tokio::test]
    async fn deregister_node_http_not_found_for_unknown_node() {
        let fleet = test_fleet(HashMap::new());
        let err = deregister_node(State(fleet), Path("ghost".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    // --- GET /fleet/nodes/{name}/vms ---

    fn test_fleet(nodes: HashMap<String, NodeInfo>) -> Fleet {
        Fleet {
            nodes: Arc::new(Mutex::new(nodes)),
            http: reqwest::Client::new(),
            persist_path: None,
            lock_path: None,
            token: None,
        }
    }

    /// Spawns a real, minimal HTTP server on an OS-assigned loopback port
    /// that answers `GET /v1/vms` with a fixed body/status, so `node_vms`
    /// (which proxies via a real `reqwest` call, not something mockable
    /// in-process) has a real node to talk to. Returns the `http://` base
    /// URL to hand to a `NodeInfo.fluxvm_url`.
    async fn spawn_fake_node(status: StatusCode, body: Value) -> String {
        let app = Router::new().route(
            "/v1/vms",
            get(move || {
                let body = body.clone();
                async move { (status, Json(body)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn node_vms_returns_only_that_nodes_vms_tagged_with_its_name() {
        let url = spawn_fake_node(
            StatusCode::OK,
            json!({"items": [{"id": "vm-1"}, {"id": "vm-2"}]}),
        )
        .await;
        let mut nodes = HashMap::new();
        nodes.insert(
            "a".to_string(),
            NodeInfo {
                fluxvm_url: url,
                ..node("a", 2, 0)
            },
        );
        nodes.insert("b".to_string(), node("b", 5, 0)); // never contacted
        let fleet = test_fleet(nodes);

        let Json(resp) = node_vms(State(fleet), Path("a".to_string())).await.unwrap();
        assert_eq!(resp["node"], "a");
        let items = resp["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["id"], "vm-1");
        assert_eq!(items[0]["node"], "a");
        assert_eq!(items[1]["node"], "a");
    }

    #[tokio::test]
    async fn node_vms_unknown_node_is_bad_request() {
        let fleet = test_fleet(HashMap::new());
        let err = node_vms(State(fleet), Path("ghost".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_vms_surfaces_unreachable_node_as_an_error_instead_of_hiding_it() {
        // Bind then immediately drop a listener: nothing is listening on
        // this port any more, so a connection to it fails fast — unlike
        // the fleet-wide list, which would just warn server-side and
        // silently omit this node.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);

        let mut nodes = HashMap::new();
        nodes.insert(
            "a".to_string(),
            NodeInfo {
                fluxvm_url: format!("http://{dead_addr}"),
                ..node("a", 1, 0)
            },
        );
        let fleet = test_fleet(nodes);
        let err = node_vms(State(fleet), Path("a".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn node_vms_propagates_the_nodes_own_error_status() {
        let url = spawn_fake_node(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "local fluxvm serve is unhappy"}),
        )
        .await;
        let mut nodes = HashMap::new();
        nodes.insert(
            "a".to_string(),
            NodeInfo {
                fluxvm_url: url,
                ..node("a", 1, 0)
            },
        );
        let fleet = test_fleet(nodes);
        let err = node_vms(State(fleet), Path("a".to_string()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
        assert!(err.1.contains("local fluxvm serve is unhappy"));
    }

    #[tokio::test]
    async fn node_vms_handles_a_node_with_no_vms() {
        let url = spawn_fake_node(StatusCode::OK, json!({"items": []})).await;
        let mut nodes = HashMap::new();
        nodes.insert(
            "a".to_string(),
            NodeInfo {
                fluxvm_url: url,
                ..node("a", 0, 0)
            },
        );
        let fleet = test_fleet(nodes);
        let Json(resp) = node_vms(State(fleet), Path("a".to_string())).await.unwrap();
        assert_eq!(resp["items"].as_array().unwrap().len(), 0);
    }

    // --- GET /fleet/vms (fleet-wide aggregate) ---

    #[tokio::test]
    async fn list_vms_all_healthy_and_reachable_reports_no_unreachable_nodes() {
        let url = spawn_fake_node(StatusCode::OK, json!({"items": [{"id": "vm-1"}]})).await;
        let mut nodes = HashMap::new();
        nodes.insert(
            "a".to_string(),
            NodeInfo {
                fluxvm_url: url,
                ..node("a", 1, 0)
            },
        );
        let fleet = test_fleet(nodes);
        let Json(resp) = list_vms(State(fleet)).await;
        let items = resp["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["node"], "a");
        assert_eq!(resp["unreachable_nodes"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_vms_names_a_node_it_cannot_connect_to_instead_of_silently_dropping_it() {
        // Same dead-listener trick as node_vms's unreachable test: bind then
        // drop, so nothing answers and the connection fails fast.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);

        let good_url = spawn_fake_node(StatusCode::OK, json!({"items": [{"id": "vm-ok"}]})).await;
        let mut nodes = HashMap::new();
        nodes.insert(
            "dead".to_string(),
            NodeInfo {
                fluxvm_url: format!("http://{dead_addr}"),
                ..node("dead", 3, 0)
            },
        );
        nodes.insert(
            "up".to_string(),
            NodeInfo {
                fluxvm_url: good_url,
                ..node("up", 1, 0)
            },
        );
        let fleet = test_fleet(nodes);
        let Json(resp) = list_vms(State(fleet)).await;

        // The reachable node's VM still comes through...
        let items = resp["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], "vm-ok");

        // ...and the unreachable one is named, not just missing.
        let unreachable = resp["unreachable_nodes"].as_array().unwrap();
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0]["node"], "dead");
        assert!(
            unreachable[0]["reason"]
                .as_str()
                .unwrap()
                .contains("unreachable")
        );
    }

    #[tokio::test]
    async fn list_vms_names_a_stale_heartbeat_node_as_unreachable_without_contacting_it() {
        // 300s old is well past HEALTHY_WINDOW_SECS (30s) — excluded from
        // placement the same way, but previously vanished from the
        // fleet-wide list with no trace at all.
        let mut nodes = HashMap::new();
        nodes.insert("stale".to_string(), node("stale", 2, 300));
        let fleet = test_fleet(nodes);
        let Json(resp) = list_vms(State(fleet)).await;

        assert_eq!(resp["items"].as_array().unwrap().len(), 0);
        let unreachable = resp["unreachable_nodes"].as_array().unwrap();
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0]["node"], "stale");
        assert!(
            unreachable[0]["reason"]
                .as_str()
                .unwrap()
                .contains("unhealthy")
        );
    }

    #[tokio::test]
    async fn list_vms_names_a_node_that_rejects_the_list_call_as_unreachable() {
        let url = spawn_fake_node(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "local fluxvm serve is unhappy"}),
        )
        .await;
        let mut nodes = HashMap::new();
        nodes.insert(
            "cranky".to_string(),
            NodeInfo {
                fluxvm_url: url,
                ..node("cranky", 1, 0)
            },
        );
        let fleet = test_fleet(nodes);
        let Json(resp) = list_vms(State(fleet)).await;

        assert_eq!(resp["items"].as_array().unwrap().len(), 0);
        let unreachable = resp["unreachable_nodes"].as_array().unwrap();
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0]["node"], "cranky");
        assert!(
            unreachable[0]["reason"]
                .as_str()
                .unwrap()
                .contains("local fluxvm serve is unhappy")
        );
    }
}
