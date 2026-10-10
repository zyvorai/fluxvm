// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! The per-host half: periodically reports this node's identity, capacity,
//! and current VM count to a central `fluxvm-agent central` registry.
//! Runs alongside a local `fluxctl serve` — it never touches VMs directly,
//! only reads `GET /v1/vms` off the local REST API to count them.

use anyhow::{Context, Result};
use fluxvm_core::security::{HostCapabilities, NodeSecurityCapabilities};
use fluxvm_scheduler::apple_placement::AppleHostCaps;
use serde_json::json;
use std::{collections::HashMap, time::Duration};

pub struct NodeConfig {
    pub name: String,
    pub central_url: String,
    /// Address this agent itself uses to reach the local `fluxctl serve`
    /// for counting VMs — almost always a loopback address
    /// (`http://127.0.0.1:7788`).
    pub fluxvm_url: String,
    /// Address a REMOTE central registry should use to reach this same
    /// `fluxctl serve` — this has to be this host's real, externally
    /// routable address, not `fluxvm_url` unchanged.
    pub advertise_url: String,
    pub interval: Duration,
    /// Bearer token shared with `fluxvm-agent central --token`.
    pub token: Option<String>,
    /// Operator-set labels (`--label key=value`, repeatable) carried on
    /// every heartbeat -- see `central::NodeInfo::labels` for what they're
    /// used for (`nodeSelector`-based placement).
    pub labels: HashMap<String, String>,
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
    let local = local_vm_stats(http, &cfg.fluxvm_url)
        .await
        .context("reading local VM inventory")?;
    let vm_count = local.count;
    let vcpus_total = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
    let memory_mib_total = total_memory_mib().unwrap_or(0);
    let security = fetch_node_security(http, &cfg.fluxvm_url).await;
    let density = fetch_density(http, &cfg.fluxvm_url).await;
    let apple = fetch_apple_caps(vcpus_total, memory_mib_total, local).await;

    let body = json!({
        "name": cfg.name,
        "fluxvm_url": cfg.advertise_url,
        "vcpus_total": vcpus_total,
        "memory_mib_total": memory_mib_total,
        "vm_count": vm_count,
        "labels": cfg.labels,
        "security": security,
        "density": density,
        "apple": apple,
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

async fn fetch_node_security(http: &reqwest::Client, fluxvm_url: &str) -> NodeSecurityCapabilities {
    match http
        .get(format!("{fluxvm_url}/v1/security/capabilities"))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<HostCapabilities>().await {
            Ok(caps) => NodeSecurityCapabilities::from(caps),
            Err(_) => NodeSecurityCapabilities::standard_only(),
        },
        _ => NodeSecurityCapabilities::standard_only(),
    }
}

/// Memory pressure, warm slots and sandbox counts for fleet placement; `None` when the daemon does not serve them.
async fn fetch_density(
    http: &reqwest::Client,
    fluxvm_url: &str,
) -> Option<fluxvm_core::agent_density::DensityReport> {
    let resp = http
        .get(format!("{fluxvm_url}/v1/sandboxes/density"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json().await.ok()
}

#[derive(Debug, Clone, Copy, Default)]
struct LocalVmStats {
    count: usize,
    macos_guests: u32,
}

async fn local_vm_stats(http: &reqwest::Client, fluxvm_url: &str) -> Result<LocalVmStats> {
    let resp = http
        .get(format!("{fluxvm_url}/v1/vms"))
        .send()
        .await
        .context("GET /v1/vms")?;
    let body: serde_json::Value = resp.json().await.context("parsing /v1/vms response")?;
    let items = body
        .get("items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let macos_guests = items
        .iter()
        .filter(|vm| {
            let active = vm
                .get("state")
                .and_then(|v| v.as_str())
                .is_some_and(|s| matches!(s, "running" | "paused" | "starting"));
            let request = vm.get("request").unwrap_or(vm);
            let mac = request
                .get("apple")
                .and_then(|a| a.get("guest_os"))
                .and_then(|v| v.as_str())
                == Some("macos");
            active && mac
        })
        .count() as u32;
    Ok(LocalVmStats {
        count: items.len(),
        macos_guests,
    })
}

#[cfg(target_os = "macos")]
async fn fetch_apple_caps(
    vcpus_total: u32,
    memory_mib_total: u64,
    local: LocalVmStats,
) -> Option<AppleHostCaps> {
    let caps = tokio::task::spawn_blocking(fluxvm_apple::host_capabilities)
        .await
        .ok()?
        .ok()?;
    Some(AppleHostCaps {
        free_cpu: vcpus_total.saturating_sub((local.count as u32).saturating_mul(2)),
        free_memory_mib: memory_mib_total.saturating_sub((local.count as u64).saturating_mul(2048)),
        nested_virtualization: caps.nested_virtualization,
        vmnet: caps.vmnet_custom_networks && caps.vmnet_serialization,
        custom_virtio: caps.custom_virtio_queue_backend && caps.guest_memory_mapping,
        bridged_interfaces: caps.bridged_interfaces,
        macos_guests: local.macos_guests,
        secure_boot: caps.efi_secure_boot,
        rosetta: caps.rosetta == "installed",
    })
}

#[cfg(not(target_os = "macos"))]
async fn fetch_apple_caps(
    _vcpus_total: u32,
    _memory_mib_total: u64,
    _local: LocalVmStats,
) -> Option<AppleHostCaps> {
    None
}

/// Real total RAM off `/proc/meminfo` (`MemTotal:` is always the first
/// line) — this project is Linux-only throughout, same as every other
/// host-introspection call in it (cgroups, `/proc/uptime`, ...).
#[cfg(target_os = "linux")]
fn total_memory_mib() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = content.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

#[cfg(target_os = "macos")]
fn total_memory_mib() -> Option<u64> {
    let mut value: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    let name = b"hw.memsize\0";
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast(),
            (&mut value as *mut u64).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0).then_some(value / 1_048_576)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn total_memory_mib() -> Option<u64> {
    None
}
