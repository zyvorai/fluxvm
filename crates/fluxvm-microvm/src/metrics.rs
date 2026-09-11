// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Prometheus text metrics for MicroVM schedule→Running latency.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Fixed histogram buckets (seconds) for schedule→Running / create→Scheduled.
const BUCKETS_S: &[f64] = &[0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0];

struct Hist {
    counts: [AtomicU64; 9],
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl Hist {
    const fn new() -> Self {
        Self {
            counts: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe_ms(&self, ms: u64) {
        let secs = ms as f64 / 1000.0;
        for (i, &b) in BUCKETS_S.iter().enumerate() {
            if secs <= b {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

static CREATE_TO_SCHEDULED: Hist = Hist::new();
static SCHEDULE_TO_RUNNING: Hist = Hist::new();
static CREATE_TO_RUNNING: Hist = Hist::new();
static RUNNING_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn observe_create_to_scheduled(d: Duration) {
    CREATE_TO_SCHEDULED.observe_ms(d.as_millis() as u64);
}

pub fn observe_schedule_to_running(d: Duration) {
    SCHEDULE_TO_RUNNING.observe_ms(d.as_millis() as u64);
}

pub fn observe_create_to_running(d: Duration) {
    CREATE_TO_RUNNING.observe_ms(d.as_millis() as u64);
    RUNNING_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_failed() {
    FAILED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

fn render_hist(name: &str, help: &str, h: &Hist) -> String {
    let mut out = String::new();
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for (i, &b) in BUCKETS_S.iter().enumerate() {
        let cumulative = h.counts[i].load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"{b}\"}} {cumulative}\n"));
    }
    let count = h.count.load(Ordering::Relaxed);
    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
    let sum_s = h.sum_ms.load(Ordering::Relaxed) as f64 / 1000.0;
    out.push_str(&format!("{name}_sum {sum_s}\n"));
    out.push_str(&format!("{name}_count {count}\n"));
    out
}

pub fn render() -> String {
    let mut out = String::new();
    out.push_str(&render_hist(
        "fluxvm_microvm_create_to_scheduled_seconds",
        "Wall time from MicroVM creationTimestamp to phase=Scheduled",
        &CREATE_TO_SCHEDULED,
    ));
    out.push_str(&render_hist(
        "fluxvm_microvm_schedule_to_running_seconds",
        "Wall time from phase=Scheduled to phase=Running (node agent)",
        &SCHEDULE_TO_RUNNING,
    ));
    out.push_str(&render_hist(
        "fluxvm_microvm_create_to_running_seconds",
        "Wall time from MicroVM creationTimestamp to phase=Running",
        &CREATE_TO_RUNNING,
    ));
    out.push_str("# HELP fluxvm_microvm_running_total MicroVMs that reached Running\n");
    out.push_str("# TYPE fluxvm_microvm_running_total counter\n");
    out.push_str(&format!(
        "fluxvm_microvm_running_total {}\n",
        RUNNING_TOTAL.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP fluxvm_microvm_failed_total MicroVM reconciles that set Failed\n");
    out.push_str("# TYPE fluxvm_microvm_failed_total counter\n");
    out.push_str(&format!(
        "fluxvm_microvm_failed_total {}\n",
        FAILED_TOTAL.load(Ordering::Relaxed)
    ));
    out
}

/// Serve Prometheus text on `addr` (e.g. `127.0.0.1:9108`).
pub async fn serve(addr: &str) -> anyhow::Result<()> {
    use axum::{Router, routing::get};
    let app = Router::new().route("/metrics", get(|| async { render() }));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "MicroVM Prometheus metrics listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_renders_buckets() {
        observe_create_to_running(Duration::from_millis(1500));
        let body = render();
        assert!(body.contains("fluxvm_microvm_create_to_running_seconds_count 1"));
        assert!(body.contains("le=\"2.5\""));
    }
}
