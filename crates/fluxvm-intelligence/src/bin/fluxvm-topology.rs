// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use fluxvm_intelligence::topology::{self, TopologySnapshot};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap, env, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration,
};
use tokio::{net::TcpListener, sync::RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
struct VmDto {
    id: Uuid,
    #[serde(default)]
    name: String,
    pid: Option<u32>,
}

#[derive(Clone)]
struct Config {
    api_url: String,
    api_token: Option<String>,
    pin_root: PathBuf,
    sync_every: Duration,
}

#[derive(Clone)]
struct ApiState {
    cfg: Config,
    snapshots: Arc<RwLock<BTreeMap<Uuid, TopologySnapshot>>>,
}

fn usage() -> &'static str {
    "usage:\n  fluxvm-topology load\n  fluxvm-topology unload\n  fluxvm-topology probe\n  fluxvm-topology register <uuid> <vmm-pid>\n  fluxvm-topology unregister <uuid> <vmm-pid>\n  fluxvm-topology snapshot <uuid> <vmm-pid> [interface]\n  fluxvm-topology plan <uuid> <vmm-pid> [interface] [output.json]\n  fluxvm-topology apply <plan.json>\n  fluxvm-topology rollback <uuid>\n  fluxvm-topology events <uuid> [seconds] [limit]\n  fluxvm-topology serve [listen]"
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let pin_root = PathBuf::from(
        env::var("FLUXVM_TOPOLOGY_PIN_ROOT")
            .unwrap_or_else(|_| topology::DEFAULT_TOPOLOGY_PIN_ROOT.into()),
    );
    let state_root = PathBuf::from(
        env::var("FLUXVM_TOPOLOGY_STATE_ROOT")
            .unwrap_or_else(|_| topology::DEFAULT_TOPOLOGY_STATE_ROOT.into()),
    );
    match args.get(1).map(String::as_str) {
        Some("load") => {
            if args.len() != 2 {
                bail!(usage());
            }
            topology::load(&pin_root)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&topology::probe(&pin_root))?
            );
        }
        Some("unload") => {
            if args.len() != 2 {
                bail!(usage());
            }
            topology::unload(&pin_root)?;
        }
        Some("probe") => {
            if args.len() != 2 {
                bail!(usage());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&topology::probe(&pin_root))?
            );
        }
        Some("register") => {
            let id = parse_id(args.get(2))?;
            let pid = parse_u32(args.get(3), "vmm-pid")?;
            if args.len() != 4 {
                bail!(usage());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&topology::register(id, pid, &pin_root)?)?
            );
        }
        Some("unregister") => {
            let id = parse_id(args.get(2))?;
            let pid = parse_u32(args.get(3), "vmm-pid")?;
            if args.len() != 4 {
                bail!(usage());
            }
            topology::unregister(id, pid, &pin_root)?;
        }
        Some("snapshot") => {
            let id = parse_id(args.get(2))?;
            let pid = parse_u32(args.get(3), "vmm-pid")?;
            let iface = args.get(4).map(String::as_str);
            if args.len() > 5 {
                bail!(usage());
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&topology::snapshot(id, pid, iface, &pin_root)?)?
            );
        }
        Some("plan") => {
            let id = parse_id(args.get(2))?;
            let pid = parse_u32(args.get(3), "vmm-pid")?;
            let iface = args
                .get(4)
                .filter(|v| !v.ends_with(".json"))
                .map(String::as_str);
            let output = if iface.is_some() {
                args.get(5)
            } else {
                args.get(4)
            };
            if args.len() > 6 {
                bail!(usage());
            }
            let snap = topology::snapshot(id, pid, iface, &pin_root)?;
            let plan = topology::plan(&snap)?;
            let bytes = serde_json::to_vec_pretty(&plan)?;
            if let Some(path) = output {
                fs::write(path, &bytes)?;
                eprintln!("wrote {path}");
            }
            println!("{}", String::from_utf8(bytes)?);
        }
        Some("apply") => {
            let path = args.get(2).ok_or_else(|| anyhow::anyhow!(usage()))?;
            if args.len() != 3 {
                bail!(usage());
            }
            let plan = serde_json::from_slice(&fs::read(path)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&topology::apply_plan(&plan, &state_root)?)?
            );
        }
        Some("rollback") => {
            let id = parse_id(args.get(2))?;
            if args.len() != 3 {
                bail!(usage());
            }
            topology::rollback(id, &state_root)?;
            println!("{{\"ok\":true}}");
        }
        Some("events") => {
            let id = parse_id(args.get(2))?;
            let sec = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(5);
            let limit = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(128);
            if args.len() > 5 {
                bail!(usage());
            }
            topology::stream_events(id, &pin_root, sec, limit)?;
        }
        Some("serve") => {
            let addr: SocketAddr = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("127.0.0.1:7794")
                .parse()?;
            if args.len() > 3 {
                bail!(usage());
            }
            serve(addr, pin_root).await?;
        }
        _ => bail!(usage()),
    }
    Ok(())
}

fn parse_id(v: Option<&String>) -> Result<Uuid> {
    Ok(v.ok_or_else(|| anyhow::anyhow!(usage()))?.parse()?)
}
fn parse_u32(v: Option<&String>, name: &str) -> Result<u32> {
    v.ok_or_else(|| anyhow::anyhow!(usage()))?
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid {name}: {e}"))
}

async fn serve(addr: SocketAddr, pin_root: PathBuf) -> Result<()> {
    let cfg = Config {
        api_url: env::var("FLUXVM_API_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:7788".into())
            .trim_end_matches('/')
            .to_string(),
        api_token: env::var("FLUXVM_API_TOKEN").ok().filter(|v| !v.is_empty()),
        pin_root,
        sync_every: Duration::from_millis(
            env::var("FLUXVM_TOPOLOGY_SYNC_MS")
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
            if let Err(e) = sync_once(&bg).await {
                eprintln!("fluxvm-topology sync: {e:#}");
            }
            tokio::time::sleep(bg.cfg.sync_every).await;
        }
    });
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/topology/status", get(status))
        .route("/v1/topology/vms", get(list))
        .route("/v1/topology/vms/{id}", get(get_vm))
        .route("/metrics", get(metrics))
        .with_state(state);
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn sync_once(state: &ApiState) -> Result<()> {
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}/v1/vms", state.cfg.api_url));
    if let Some(t) = &state.cfg.api_token {
        req = req.bearer_auth(t);
    }
    let vms: Vec<VmDto> = req.send().await?.error_for_status()?.json().await?;
    let mut next = BTreeMap::new();
    for vm in vms {
        let Some(pid) = vm.pid else {
            continue;
        };
        match topology::snapshot(vm.id, pid, None, &state.cfg.pin_root) {
            Ok(s) => {
                next.insert(vm.id, s);
            }
            Err(e) => eprintln!("fluxvm-topology vm {} {}: {e:#}", vm.id, vm.name),
        }
    }
    *state.snapshots.write().await = next;
    Ok(())
}
async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok":true}))
}
async fn status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(
        json!({"ok":true,"probe":topology::probe(&state.cfg.pin_root),"vm_count":state.snapshots.read().await.len()}),
    )
}
async fn list(State(state): State<ApiState>) -> Json<Vec<TopologySnapshot>> {
    Json(state.snapshots.read().await.values().cloned().collect())
}
async fn get_vm(State(state): State<ApiState>, AxPath(id): AxPath<Uuid>) -> Response {
    match state.snapshots.read().await.get(&id).cloned() {
        Some(v) => Json(v).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"topology snapshot unavailable"})),
        )
            .into_response(),
    }
}
async fn metrics(State(state): State<ApiState>) -> Response {
    let rows: Vec<_> = state.snapshots.read().await.values().cloned().collect();
    let mut out = String::new();
    for s in rows {
        out.push_str(&topology::prometheus(&s));
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
        .into_response()
}
