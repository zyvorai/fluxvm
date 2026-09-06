// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! The per-host half: periodically reports this node's identity, capacity,
//! and current VM count to a central `fluxvm-agent central` registry.
//! Runs alongside a local `fluxvm serve` — it never touches VMs directly,
//! only reads `GET /v1/vms` off the local REST API to count them.

use anyhow::{Context, Result};
use serde_json::json;
use std::time::Duration;

pub struct NodeConfig {
    pub name: String,
    pub central_url: String,
    /// Address this agent itself uses to reach the local `fluxvm serve`
    /// for counting VMs — almost always a loopback address
    /// (`http://127.0.0.1:7788`).
    pub fluxvm_url: String,
    /// Address a REMOTE central registry should use to reach this same
    /// `fluxvm serve` — this has to be this host's real, externally
    /// routable address, not `fluxvm_url` unchanged.
    pub advertise_url: String,
    pub interval: Duration,
    /// Bearer token shared with `fluxvm-agent central --token`.
    pub token: Option<String>,
}

/// Runs forever, heartbeating every `cfg.interval`. Logs and keeps going on
/// a failed beat (the central registry marking this node stale after
/// `HEALTHY_WINDOW_SECS` is the correct outcome of a *sustained* outage —
/// a node agent that gave up after one failed request would make a
/// transient network blip permanently evict an otherwise-fine node).
pub async fn run(cfg: NodeConfig) {
    let http = reqwest::Client::new();
    let mut tick = tokio::time::interval(cfg.interval);
    loop {
        tick.tick().await;
        if let Err(e) = beat(&http, &cfg).await {
            tracing::warn!(error = %e, "heartbeat failed, will retry next tick");
        } else {
            tracing::debug!(node = %cfg.name, "heartbeat sent");
        }
    }
}

async fn beat(http: &reqwest::Client, cfg: &NodeConfig) -> Result<()> {
    let vm_count = local_vm_count(http, &cfg.fluxvm_url)
        .await
        .context("counting local VMs")?;
    let vcpus_total = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
    let memory_mib_total = total_memory_mib().unwrap_or(0);

    let body = json!({
        "name": cfg.name,
        "fluxvm_url": cfg.advertise_url,
        "vcpus_total": vcpus_total,
        "memory_mib_total": memory_mib_total,
        "vm_count": vm_count,
    });
    let mut req = http.post(format!("{}/fleet/register", cfg.central_url));
    if let Some(t) = &cfg.token {
        req = req.bearer_auth(t);
    }
    let resp = req.json(&body).send().await.context("sending heartbeat")?;
    if !resp.status().is_success() {
        anyhow::bail!("central rejected heartbeat: {}", resp.status());
    }
    Ok(())
}

async fn local_vm_count(http: &reqwest::Client, fluxvm_url: &str) -> Result<usize> {
    let resp = http
        .get(format!("{fluxvm_url}/v1/vms"))
        .send()
        .await
        .context("GET /v1/vms")?;
    let body: serde_json::Value = resp.json().await.context("parsing /v1/vms response")?;
    Ok(body
        .get("items")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0))
}

/// Real total RAM off `/proc/meminfo` (`MemTotal:` is always the first
/// line) — this project is Linux-only throughout, same as every other
/// host-introspection call in it (cgroups, `/proc/uptime`, ...).
fn total_memory_mib() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = content.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}
