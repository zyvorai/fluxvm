// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, anyhow, bail};
use axum::{
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use fluxvm_intelligence::scx::{self, ScxClass, ScxPlan, ScxStatus};
use serde_json::json;
use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone)]
struct ApiState {
    pin_root: Arc<PathBuf>,
    state_root: Arc<PathBuf>,
}

fn usage() -> &'static str {
    "usage:\n  fluxvm-scx probe\n  fluxvm-scx verify\n  fluxvm-scx plan <uuid> <vmm-pid> [--class latency|balanced|throughput|background] [--weight 25..400] [--slice-us 100..10000] [--latency-target-us N] [--output plan.json]\n  fluxvm-scx apply <plan.json>\n  fluxvm-scx rollback <uuid>\n  fluxvm-scx reconcile\n  fluxvm-scx status <uuid>\n  fluxvm-scx events <uuid> [seconds] [limit]\n  fluxvm-scx metrics <uuid>\n  fluxvm-scx serve [listen]"
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let pin_root = PathBuf::from(env::var("FLUXVM_SCX_PIN_ROOT").unwrap_or_else(|_| scx::DEFAULT_SCX_PIN_ROOT.into()));
    let state_root = PathBuf::from(env::var("FLUXVM_SCX_STATE_ROOT").unwrap_or_else(|_| scx::DEFAULT_SCX_STATE_ROOT.into()));

    match args.get(1).map(String::as_str) {
        Some("probe") if args.len() == 2 => {
            println!("{}", serde_json::to_string_pretty(&scx::probe(&pin_root))?);
        }
        Some("verify") if args.len() == 2 => {
            scx::verify_object()?;
            println!("{{\"verified\":true}}");
        }
        Some("plan") => {
            let id = parse_id(args.get(2))?;
            let pid = parse_u32(args.get(3), "vmm-pid")?;
            let mut class = ScxClass::Balanced;
            let mut weight = None;
            let mut slice_us = None;
            let mut latency_target_us = None;
            let mut output: Option<PathBuf> = None;
            let mut i = 4;
            while i < args.len() {
                match args[i].as_str() {
                    "--class" => { i += 1; class = ScxClass::parse(args.get(i).ok_or_else(|| anyhow!(usage()))?)?; }
                    "--weight" => { i += 1; weight = Some(parse_u32(args.get(i), "weight")?); }
                    "--slice-us" => { i += 1; slice_us = Some(parse_u64(args.get(i), "slice-us")?); }
                    "--latency-target-us" => { i += 1; latency_target_us = Some(parse_u64(args.get(i), "latency-target-us")?); }
                    "--output" => { i += 1; output = Some(PathBuf::from(args.get(i).ok_or_else(|| anyhow!(usage()))?)); }
                    _ => bail!(usage()),
                }
                i += 1;
            }
            let plan = scx::build_plan(id, pid, class, weight, slice_us, latency_target_us)?;
            let bytes = serde_json::to_vec_pretty(&plan)?;
            if let Some(path) = output {
                fs::write(&path, &bytes)?;
                eprintln!("wrote {}", path.display());
            }
            println!("{}", String::from_utf8(bytes)?);
        }
        Some("apply") if args.len() == 3 => {
            let plan: ScxPlan = serde_json::from_slice(&fs::read(&args[2])?)?;
            println!("{}", serde_json::to_string_pretty(&scx::apply_plan(&plan, &pin_root, &state_root)?)?);
        }
        Some("rollback") if args.len() == 3 => {
            scx::rollback(args[2].parse()?, &pin_root, &state_root)?;
            println!("{{\"ok\":true}}");
        }
        Some("reconcile") if args.len() == 2 => {
            println!("{{\"cleaned\":{}}}", scx::reconcile(&pin_root, &state_root)?);
        }
        Some("status") if args.len() == 3 => {
            let id: Uuid = args[2].parse()?;
            println!("{}", serde_json::to_string_pretty(&scx::status(id, &pin_root, &state_root)?)?);
        }
        Some("events") => {
            let id = parse_id(args.get(2))?;
            let seconds = args.get(3).map(|v| v.parse()).transpose()?.unwrap_or(5);
            let limit = args.get(4).map(|v| v.parse()).transpose()?.unwrap_or(128);
            if args.len() > 5 { bail!(usage()); }
            scx::stream_events(id, &pin_root, seconds, limit)?;
        }
        Some("metrics") if args.len() == 3 => {
            print!("{}", scx::prometheus(args[2].parse()?, &pin_root)?);
        }
        Some("serve") if args.len() <= 3 => {
            let addr: SocketAddr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7797").parse()?;
            serve(addr, pin_root, state_root).await?;
        }
        _ => bail!(usage()),
    }
    Ok(())
}

fn parse_id(value: Option<&String>) -> Result<Uuid> {
    Ok(value.ok_or_else(|| anyhow!(usage()))?.parse()?)
}
fn parse_u32(value: Option<&String>, name: &str) -> Result<u32> {
    value.ok_or_else(|| anyhow!(usage()))?.parse().map_err(|e| anyhow!("invalid {name}: {e}"))
}
fn parse_u64(value: Option<&String>, name: &str) -> Result<u64> {
    value.ok_or_else(|| anyhow!(usage()))?.parse().map_err(|e| anyhow!("invalid {name}: {e}"))
}

async fn serve(addr: SocketAddr, pin_root: PathBuf, state_root: PathBuf) -> Result<()> {
    let state = ApiState { pin_root: Arc::new(pin_root), state_root: Arc::new(state_root) };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/scx/status", get(kernel_status))
        .route("/v1/scx/vms", get(list_vms))
        .route("/v1/scx/vms/{id}", get(vm_status))
        .route("/metrics", get(metrics))
        .with_state(state);
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true}))
}

async fn kernel_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(json!({"ok": true, "probe": scx::probe(&state.pin_root)}))
}

async fn list_vms(State(state): State<ApiState>) -> Response {
    let ids = match scx::active_ids(&state.state_root) {
        Ok(v) => v,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": err.to_string()}))).into_response(),
    };
    let rows: Vec<ScxStatus> = ids.into_iter()
        .filter_map(|id| scx::status(id, &state.pin_root, &state.state_root).ok())
        .collect();
    Json(rows).into_response()
}

async fn vm_status(State(state): State<ApiState>, AxPath(id): AxPath<Uuid>) -> Response {
    match scx::status(id, &state.pin_root, &state.state_root) {
        Ok(value) => Json(value).into_response(),
        Err(err) => (StatusCode::NOT_FOUND, Json(json!({"error": err.to_string()}))).into_response(),
    }
}

async fn metrics(State(state): State<ApiState>) -> Response {
    let mut body = String::new();
    match scx::active_ids(&state.state_root) {
        Ok(ids) => {
            for id in ids {
                if let Ok(text) = scx::prometheus(id, &state.pin_root) {
                    body.push_str(&text);
                }
            }
            (StatusCode::OK, [("content-type", "text/plain; version=0.0.4; charset=utf-8")], body).into_response()
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": err.to_string()}))).into_response(),
    }
}
