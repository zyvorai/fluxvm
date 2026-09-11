// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::{FlightRecorderSnapshot, VmRuntimeSnapshot};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QosAssessment {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub state: String,
    pub runnable_p95_ns: Option<u64>,
    pub block_p95_ns: Option<u64>,
    pub cpu_pressure_avg10: Option<f64>,
    pub io_pressure_avg10: Option<f64>,
    pub network_drop_ratio: Option<f64>,
    pub current_cpu_weight: Option<u32>,
    pub current_io_weight: Option<u32>,
    pub recommended_cpu_weight: u32,
    pub recommended_io_weight: u32,
    pub network_signal: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QosApplyResult {
    pub cpu_weight: Option<u32>,
    pub io_weight: Option<u32>,
}

pub fn assess(snapshot: &VmRuntimeSnapshot, cgroup: &Path) -> Result<QosAssessment> {
    let cpu_pressure = read_pressure_avg10(&cgroup.join("cpu.pressure"), "some")
        .ok()
        .flatten();
    let io_pressure = read_pressure_avg10(&cgroup.join("io.pressure"), "full")
        .ok()
        .flatten();
    let runnable_p95 = snapshot
        .flight
        .as_ref()
        .and_then(|f| quantile_ns(f, "runnable", 0.95));
    let block_p95 = snapshot
        .flight
        .as_ref()
        .and_then(|f| quantile_ns(f, "block-io", 0.95));
    let current_cpu = read_weight(&cgroup.join("cpu.weight"));
    let current_io = read_weight(&cgroup.join("io.weight"));
    let mut cpu = current_cpu.unwrap_or(100).clamp(1, 10_000);
    let mut io = current_io.unwrap_or(100).clamp(1, 10_000);
    let mut reasons = Vec::new();
    let cpu_hot = runnable_p95.unwrap_or(0) >= 10_000_000 || cpu_pressure.unwrap_or(0.0) >= 20.0;
    let io_hot = block_p95.unwrap_or(0) >= 20_000_000 || io_pressure.unwrap_or(0.0) >= 1.0;
    if cpu_hot {
        cpu = boost(cpu);
        reasons.push("vCPU runnable latency/CPU pressure is elevated".into());
    }
    if io_hot {
        io = boost(io);
        reasons.push("VM-attributed block latency/I/O pressure is elevated".into());
    }
    let drop_ratio = snapshot.network.as_ref().and_then(|n| {
        let total = n.allowed_packets.saturating_add(n.dropped_packets);
        if total == 0 {
            None
        } else {
            Some(n.dropped_packets as f64 / total as f64)
        }
    });
    let network_signal = match drop_ratio {
        Some(r) if r >= 0.05 && !cpu_hot && !io_hot => "review-network-policy-or-rate-limit",
        Some(r) if r >= 0.05 => "host-pressure-plus-network-drops",
        _ => "hold",
    }
    .to_string();
    if network_signal != "hold" {
        reasons.push(format!(
            "network drop ratio is {:.2}%",
            drop_ratio.unwrap_or(0.0) * 100.0
        ));
    }
    let state = if cpu_hot && io_hot {
        "cpu-and-io-pressure"
    } else if cpu_hot {
        "cpu-pressure"
    } else if io_hot {
        "io-pressure"
    } else {
        "healthy"
    }
    .to_string();
    Ok(QosAssessment {
        schema_version: 1,
        vm_id: snapshot.vm_id,
        state,
        runnable_p95_ns: runnable_p95,
        block_p95_ns: block_p95,
        cpu_pressure_avg10: cpu_pressure,
        io_pressure_avg10: io_pressure,
        network_drop_ratio: drop_ratio,
        current_cpu_weight: current_cpu,
        current_io_weight: current_io,
        recommended_cpu_weight: cpu,
        recommended_io_weight: io,
        network_signal,
        reasons,
    })
}

pub fn apply(cgroup: &Path, assessment: &QosAssessment) -> Result<QosApplyResult> {
    let cpu = write_weight_if_present(
        &cgroup.join("cpu.weight"),
        assessment.recommended_cpu_weight,
    )?;
    let io = write_weight_if_present(&cgroup.join("io.weight"), assessment.recommended_io_weight)?;
    if cpu.is_none() && io.is_none() {
        bail!(
            "neither cpu.weight nor io.weight is available in {}",
            cgroup.display()
        );
    }
    Ok(QosApplyResult {
        cpu_weight: cpu,
        io_weight: io,
    })
}

pub fn cgroup_for_pid(pid: u32) -> Result<PathBuf> {
    crate::guard::cgroup_for_pid(pid)
}

fn boost(current: u32) -> u32 {
    let step = ((current as u64 * 5 + 3) / 4) as u32;
    step.max(current.saturating_add(25)).clamp(100, 1000)
}
fn read_weight(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}
fn write_weight_if_present(path: &Path, value: u32) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    };
    let value = value.clamp(1, 10_000);
    fs::write(path, value.to_string()).with_context(|| format!("writing {}", path.display()))?;
    Ok(Some(value))
}

fn read_pressure_avg10(path: &Path, row: &str) -> Result<Option<f64>> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        if it.next() != Some(row) {
            continue;
        }
        for f in it {
            if let Some(v) = f.strip_prefix("avg10=") {
                return Ok(v.parse().ok());
            }
        }
    }
    Ok(None)
}

fn quantile_ns(f: &FlightRecorderSnapshot, kind: &str, q: f64) -> Option<u64> {
    let mut buckets: [u64; 25] = [0; 25];
    for b in f.latency.iter().filter(|b| b.kind == kind) {
        if let Some(slot) = buckets.get_mut(b.bucket as usize) {
            *slot = slot.saturating_add(b.count)
        }
    }
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return None;
    }
    let target = ((total as f64 * q).ceil() as u64).max(1);
    let mut seen = 0u64;
    for (i, c) in buckets.iter().enumerate() {
        seen = seen.saturating_add(*c);
        if seen >= target {
            return Some(1000u64.saturating_mul(1u64 << i.min(24)));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boost_is_bounded() {
        assert_eq!(boost(100), 125);
        assert_eq!(boost(900), 1000);
        assert_eq!(boost(1000), 1000);
    }
    #[test]
    fn quantile_uses_histogram() {
        let mut f = FlightRecorderSnapshot::default();
        f.latency.push(crate::LatencyBucket {
            kind: "runnable".into(),
            bucket: 10,
            le_ns: Some(1_024_000),
            count: 95,
            total_ns: 0,
            max_ns: 0,
        });
        f.latency.push(crate::LatencyBucket {
            kind: "runnable".into(),
            bucket: 14,
            le_ns: Some(16_384_000),
            count: 5,
            total_ns: 0,
            max_ns: 0,
        });
        assert_eq!(quantile_ns(&f, "runnable", 0.95), Some(1_024_000));
    }
}
