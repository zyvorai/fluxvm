// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use fluxvm_core::model::{VmRecord, VmStatus};
use fluxvm_intelligence::memprof::{self, MemoryProfileSnapshot};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::RwLock};
use uuid::Uuid;

fn usage() -> &'static str {
    "usage:\n\
     fluxvm-memprof load [--replace-links]\n\
     fluxvm-memprof probe\n\
     fluxvm-memprof snapshot <uuid> <pid> [cgroup-path]\n\
     fluxvm-memprof mark <uuid> <guest-ready|pause-request|paused|resume-request|resumed|snapshot-begin|snapshot-end|restore-begin|restore-end>\n\
     fluxvm-memprof clear <uuid>\n\
     fluxvm-memprof events <uuid> [seconds=5] [limit=128]\n\
     fluxvm-memprof serve [127.0.0.1:7793]"
}

#[derive(Clone)]
struct Config {
    api_url: String,
    api_token: Option<String>,
    pin_root: PathBuf,
    marker_root: PathBuf,
    sync_every: Duration,
}

#[derive(Clone)]
struct ApiState {
    cfg: Config,
    snapshots: Arc<RwLock<BTreeMap<Uuid, MemoryProfileSnapshot>>>,
}

#[derive(Deserialize)]
struct MarkRequest {
    phase: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let pin_root = memprof::default_pin_root();
    let marker_root = memprof::default_marker_root();
    match args.get(1).map(String::as_str) {
        Some("load") => {
            let replace = args.get(2).map(String::as_str) == Some("--replace-links");
            if args.len() > 3 || (args.len() == 3 && !replace) {
                bail!(usage());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&memprof::load(&pin_root, replace)?)?
            );
            Ok(())
        }
        Some("probe") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&memprof::probe(&pin_root))?
            );
            Ok(())
        }
        Some("snapshot") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            let pid: u32 = args.get(3).context(usage())?.parse()?;
            let cgroup = args.get(4).map(PathBuf::from);
            if args.len() > 5 {
                bail!(usage());
            }
            let row = memprof::snapshot_raw(id, pid, cgroup.as_deref(), &pin_root, &marker_root)?;
            println!("{}", serde_json::to_string_pretty(&row)?);
            Ok(())
        }
        Some("mark") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            let phase = args.get(3).context(usage())?;
            if args.len() > 4 {
                bail!(usage());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&memprof::mark(id, phase, &marker_root)?)?
            );
            Ok(())
        }
        Some("clear") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            if args.len() > 3 {
                bail!(usage());
            }
            memprof::clear_markers(id, &marker_root)?;
            println!("{}", json!({"ok":true,"vm_id":id}));
            Ok(())
        }
        Some("events") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            let seconds = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(5);
            let limit = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(128);
            if args.len() > 5 {
                bail!(usage());
            }
            for event in memprof::events(id, &pin_root, seconds, limit)? {
                println!("{}", serde_json::to_string(&event)?);
            }
            Ok(())
        }
        Some("serve") => {
            let addr: SocketAddr = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("127.0.0.1:7793")
                .parse()?;
            if args.len() > 3 {
                bail!(usage());
            }
            serve(addr, pin_root, marker_root).await
        }
        _ => bail!(usage()),
    }
}

async fn serve(addr: SocketAddr, pin_root: PathBuf, marker_root: PathBuf) -> Result<()> {
    let cfg = Config {
        api_url: env::var("FLUXVM_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:7788".into())
            .trim_end_matches('/')
            .to_string(),
        api_token: env::var("FLUXVM_API_TOKEN").ok().filter(|v| !v.is_empty()),
        pin_root,
        marker_root,
        sync_every: Duration::from_millis(
            env::var("FLUXVM_MEMPROF_SYNC_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2000),
        ),
    };
    let state = ApiState {
        cfg: cfg.clone(),
        snapshots: Arc::new(RwLock::new(BTreeMap::new())),
    };
    let bg = state.clone();
    tokio::spawn(async move {
        loop {
            if let Err(err) = sync_once(&bg).await {
                eprintln!("fluxvm-memprof sync: {err:#}");
            }
            tokio::time::sleep(bg.cfg.sync_every).await;
        }
    });
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/memprof/status", get(status))
        .route("/v1/memprof/vms", get(list))
        .route("/v1/memprof/vms/{id}", get(get_vm))
        .route("/v1/memprof/vms/{id}/mark", post(mark_vm))
        .route("/metrics", get(metrics))
        .with_state(state);
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn sync_once(state: &ApiState) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client.get(format!("{}/v1/vms", state.cfg.api_url));
    if let Some(token) = &state.cfg.api_token {
        request = request.bearer_auth(token);
    }
    let vms: Vec<VmRecord> = request.send().await?.error_for_status()?.json().await?;
    let mut next = BTreeMap::new();
    for vm in &vms {
        if !matches!(vm.status, VmStatus::Running | VmStatus::Paused) || vm.pid.is_none() {
            continue;
        }
        match memprof::snapshot_record(vm, &state.cfg.pin_root, &state.cfg.marker_root) {
            Ok(row) => {
                next.insert(vm.id, row);
            }
            Err(err) => eprintln!("fluxvm-memprof vm {}: {err:#}", vm.id),
        }
    }
    *state.snapshots.write().await = next;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok":true}))
}
async fn status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "probe": memprof::probe(&state.cfg.pin_root),
        "vm_count": state.snapshots.read().await.len(),
    }))
}
async fn list(State(state): State<ApiState>) -> Json<Vec<MemoryProfileSnapshot>> {
    Json(state.snapshots.read().await.values().cloned().collect())
}
async fn get_vm(State(state): State<ApiState>, AxPath(id): AxPath<Uuid>) -> Response {
    match state.snapshots.read().await.get(&id).cloned() {
        Some(row) => Json(row).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"memory profile unavailable"})),
        )
            .into_response(),
    }
}
async fn mark_vm(
    State(state): State<ApiState>,
    AxPath(id): AxPath<Uuid>,
    Json(req): Json<MarkRequest>,
) -> Response {
    match memprof::mark(id, &req.phase, &state.cfg.marker_root) {
        Ok(v) => Json(json!(v)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":format!("{err:#}")})),
        )
            .into_response(),
    }
}
async fn metrics(State(state): State<ApiState>) -> Response {
    let rows: Vec<_> = state.snapshots.read().await.values().cloned().collect();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        memprof::prometheus(&rows),
    )
        .into_response()
}
