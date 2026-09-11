// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use fluxvm_intelligence::afxdp::{self, AfxdpMode, AfxdpPlan};
use serde_json::json;
use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone)]
struct ApiState {
    state_root: Arc<PathBuf>,
}
fn usage() -> &'static str {
    "usage:\n  fluxvm-afxdp probe\n  fluxvm-afxdp plan <uuid> <iface-a> <queue-a> <iface-b> <queue-b> <auto|copy|zerocopy> --dedicated [plan.json]\n  fluxvm-afxdp start <plan.json>\n  fluxvm-afxdp status <uuid>\n  fluxvm-afxdp stop <uuid>\n  fluxvm-afxdp metrics <uuid>\n  fluxvm-afxdp events <uuid> [seconds] [limit]\n  fluxvm-afxdp serve [listen]"
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    let pin = PathBuf::from(
        env::var("FLUXVM_AFXDP_PIN_ROOT").unwrap_or_else(|_| afxdp::DEFAULT_AFXDP_PIN_ROOT.into()),
    );
    let state = PathBuf::from(
        env::var("FLUXVM_AFXDP_STATE_ROOT")
            .unwrap_or_else(|_| afxdp::DEFAULT_AFXDP_STATE_ROOT.into()),
    );
    match a.get(1).map(String::as_str) {
        Some("probe") => {
            if a.len() != 2 {
                bail!(usage())
            }
            println!("{}", serde_json::to_string_pretty(&afxdp::probe())?);
        }
        Some("plan") => {
            if a.len() < 9 || a.len() > 10 || a.get(8).map(String::as_str) != Some("--dedicated") {
                bail!(usage())
            }
            let id = parse_id(a.get(2))?;
            let qa = parse_q(a.get(4))?;
            let qb = parse_q(a.get(6))?;
            let mode = AfxdpMode::parse(a.get(7).ok_or_else(|| anyhow!(usage()))?)?;
            let p =
                afxdp::build_plan(id, a.get(3).unwrap(), qa, a.get(5).unwrap(), qb, mode, true)?;
            let b = serde_json::to_vec_pretty(&p)?;
            if let Some(out) = a.get(9) {
                fs::write(out, &b)?;
            }
            println!("{}", String::from_utf8(b)?);
        }
        Some("start") => {
            if a.len() != 3 {
                bail!(usage())
            }
            let p: AfxdpPlan = serde_json::from_slice(&fs::read(a.get(2).unwrap())?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&afxdp::start(&p, &pin, &state)?)?
            );
        }
        Some("status") => {
            if a.len() != 3 {
                bail!(usage())
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&afxdp::status(parse_id(a.get(2))?, &state)?)?
            );
        }
        Some("stop") => {
            if a.len() != 3 {
                bail!(usage())
            }
            afxdp::stop(parse_id(a.get(2))?, &state)?;
            println!("{{\"ok\":true}}");
        }
        Some("metrics") => {
            if a.len() != 3 {
                bail!(usage())
            }
            print!(
                "{}",
                afxdp::prometheus(&afxdp::status(parse_id(a.get(2))?, &state)?)
            );
        }
        Some("events") => {
            if a.len() > 5 || a.len() < 3 {
                bail!(usage())
            }
            let id = parse_id(a.get(2))?;
            let seconds = a.get(3).and_then(|v| v.parse().ok()).unwrap_or(5);
            let limit = a.get(4).and_then(|v| v.parse().ok()).unwrap_or(128);
            afxdp::stream_events(id, seconds, limit, &state)?;
        }
        Some("serve") => {
            if a.len() > 3 {
                bail!(usage())
            }
            let addr: SocketAddr = a
                .get(2)
                .map(String::as_str)
                .unwrap_or("127.0.0.1:7795")
                .parse()?;
            serve(addr, state).await?;
        }
        _ => bail!(usage()),
    }
    Ok(())
}
fn parse_id(v: Option<&String>) -> Result<Uuid> {
    Ok(v.ok_or_else(|| anyhow!(usage()))?.parse()?)
}
fn parse_q(v: Option<&String>) -> Result<u32> {
    let q: u32 = v.ok_or_else(|| anyhow!(usage()))?.parse()?;
    if q > afxdp::MAX_QUEUE_ID {
        bail!("queue must be 0..={}", afxdp::MAX_QUEUE_ID)
    }
    Ok(q)
}

async fn serve(addr: SocketAddr, state_root: PathBuf) -> Result<()> {
    let state = ApiState {
        state_root: Arc::new(state_root),
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/afxdp/status", get(status_all))
        .route("/v1/afxdp/vms/{id}", get(status_one))
        .route("/metrics", get(metrics))
        .with_state(state);
    let l = TcpListener::bind(addr).await?;
    axum::serve(l, app).await?;
    Ok(())
}
async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok":true,"probe":afxdp::probe()}))
}
async fn status_all(State(s): State<ApiState>) -> Response {
    match afxdp::list_statuses(&s.state_root) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":e.to_string()})),
        )
            .into_response(),
    }
}
async fn status_one(State(s): State<ApiState>, AxPath(id): AxPath<Uuid>) -> Response {
    match afxdp::status(id, &s.state_root) {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error":e.to_string()}))).into_response(),
    }
}
async fn metrics(State(s): State<ApiState>) -> Response {
    match afxdp::list_statuses(&s.state_root) {
        Ok(rows) => {
            let mut out = String::new();
            for r in rows {
                out.push_str(&afxdp::prometheus(&r));
            }
            (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                out,
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
