// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Sizing and reporting for many small agent sandboxes on one host (Mac mini / Mac Studio in particular).
//!
//! * [`AgentProfile`]: named sandbox sizes, so callers ask for `tiny` instead of hand-picking vCPUs and memory.
//! * [`DensityReport`]: what `GET /v1/sandboxes/density` returns.
//! * Warm-pool hit / miss counters for `/metrics`.
//!
//! Admission on real host pressure lives in [`crate::pressure_admission`]; idle pause, hibernate and balloon reclaim in the
//! scheduler's AutoPause loop.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// A named sandbox size. An explicit `vcpus` / `memory_mib` on the request still wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentProfile {
    /// 1 vCPU, 512 MiB: shell-and-files agents; the densest.
    Tiny,
    /// 1 vCPU, 1 GiB: light coding agents.
    Small,
    /// 2 vCPUs, 2 GiB: the default sandbox shape (and the shape warm slots have).
    #[default]
    Standard,
}

impl AgentProfile {
    pub fn vcpus(self) -> u8 {
        match self {
            Self::Tiny | Self::Small => 1,
            Self::Standard => 2,
        }
    }

    pub fn memory_mib(self) -> u64 {
        match self {
            Self::Tiny => 512,
            Self::Small => 1024,
            Self::Standard => 2048,
        }
    }

    /// The `(vcpus, memory_mib)` a sandbox gets: explicit values win, then the profile. `Standard` (or no profile) leaves
    /// both unset so the default shape, and with it the warm pool, still applies.
    pub fn resolve(
        profile: Option<Self>,
        vcpus: Option<u8>,
        memory_mib: Option<u64>,
    ) -> (Option<u8>, Option<u64>) {
        let p = profile.filter(|p| *p != Self::Standard);
        (
            vcpus.or(p.map(Self::vcpus)),
            memory_mib.or(p.map(Self::memory_mib)),
        )
    }
}

/// `GET /v1/sandboxes/density`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DensityReport {
    /// `sandbox.warm_slots`.
    pub warm_slots_configured: usize,
    /// Stopped warm slots ready to be claimed.
    pub warm_slots_ready: usize,
    /// Default-shaped sandbox creates served from / not served from a warm slot since the daemon started.
    pub warm_hits: u64,
    pub warm_misses: u64,
    pub active_sandboxes: usize,
    pub paused_sandboxes: usize,
    /// Snapshotted and stopped by idle hibernate; the next request restores them.
    pub hibernated_sandboxes: usize,
    /// Configured memory of running and paused sandboxes, MiB (a paused VM keeps its memory).
    pub resident_estimate_mib: u64,
    pub host_mem_available_mib: Option<u64>,
    pub host_mem_total_mib: Option<u64>,
    /// `normal`, `warn` or `critical` (macOS); `None` where the host has no such signal.
    pub host_pressure_level: Option<crate::pressure_admission::PressureLevel>,
}

/// `POST /v1/sandboxes/warm`.
#[derive(Debug, Clone, Deserialize)]
pub struct WarmRequest {
    /// How many warm slots to have ready (at least `sandbox.warm_slots`).
    pub count: usize,
}

/// Upper bound for one warm request; each slot is a stopped 2 GiB VM plus its saved memory on disk.
pub const MAX_WARM_SLOTS: usize = 64;

static WARM_HITS: AtomicU64 = AtomicU64::new(0);
static WARM_MISSES: AtomicU64 = AtomicU64::new(0);

pub fn record_warm_claim(hit: bool) {
    if hit {
        WARM_HITS.fetch_add(1, Ordering::Relaxed);
    } else {
        WARM_MISSES.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn warm_hits() -> u64 {
    WARM_HITS.load(Ordering::Relaxed)
}

pub fn warm_misses() -> u64 {
    WARM_MISSES.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_have_the_documented_sizes() {
        assert_eq!(
            (AgentProfile::Tiny.vcpus(), AgentProfile::Tiny.memory_mib()),
            (1, 512)
        );
        assert_eq!(
            (
                AgentProfile::Small.vcpus(),
                AgentProfile::Small.memory_mib()
            ),
            (1, 1024)
        );
        assert_eq!(
            (
                AgentProfile::Standard.vcpus(),
                AgentProfile::Standard.memory_mib()
            ),
            (2, 2048)
        );
        let p: AgentProfile = serde_json::from_str(r#""tiny""#).unwrap();
        assert_eq!(p, AgentProfile::Tiny);
    }

    #[test]
    fn explicit_sizes_win_and_standard_keeps_the_default_shape() {
        use AgentProfile::*;
        assert_eq!(
            AgentProfile::resolve(Some(Tiny), None, None),
            (Some(1), Some(512))
        );
        assert_eq!(
            AgentProfile::resolve(Some(Tiny), Some(2), None),
            (Some(2), Some(512))
        );
        assert_eq!(
            AgentProfile::resolve(Some(Small), None, Some(768)),
            (Some(1), Some(768))
        );
        assert_eq!(
            AgentProfile::resolve(Some(Standard), None, None),
            (None, None)
        );
        assert_eq!(AgentProfile::resolve(None, None, None), (None, None));
    }

    #[test]
    fn shipped_density_config_parses() {
        let cfg: crate::config::Config =
            toml::from_str(include_str!("../../../examples/fluxvm-density.toml")).unwrap();
        assert_eq!(cfg.sandbox.hibernate_idle_secs, 900);
        assert_eq!(cfg.sandbox.warm_slots, 4);
        assert_eq!(
            cfg.policy.deny_host_pressure_level,
            Some(crate::pressure_admission::PressureLevel::Warn)
        );
        assert!(crate::pressure_admission::is_enabled(&cfg.policy));
    }

    #[test]
    fn warm_counters_count() {
        let (h, m) = (warm_hits(), warm_misses());
        record_warm_claim(true);
        record_warm_claim(false);
        record_warm_claim(false);
        assert!(warm_hits() > h);
        assert!(warm_misses() >= m + 2);
    }
}
