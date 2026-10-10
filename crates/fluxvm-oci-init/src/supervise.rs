// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Keeping the container's process running: the restart policy and the health check, as pure decisions that `main.rs`
//! acts on, plus the console markers they leave for the host (`FLUXVM-RESTART`, `FLUXVM-HEALTH`).

use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const RESTART_MARKER: &str = "FLUXVM-RESTART";
pub const HEALTH_MARKER: &str = "FLUXVM-HEALTH";
/// The first restart waits this long; each later one twice as long, up to [`MAX_BACKOFF`].
pub const FIRST_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How long an unhealthy process gets between `SIGTERM` and `SIGKILL`.
pub const STOP_GRACE: Duration = Duration::from_secs(10);

/// When to start the process again after it exits. Docker's names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    No,
    /// After a non-zero exit, a signal, or being stopped as unhealthy.
    OnFailure,
    /// After any exit.
    Always,
}

fn default_interval() -> u64 {
    30
}
fn default_timeout() -> u64 {
    5
}
fn default_retries() -> u32 {
    3
}

/// A command run inside the sandbox, as the process's user with its environment; exit 0 is healthy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    /// argv, run without a shell (`["wget", "-q", "-O", "/dev/null", "http://127.0.0.1"]`).
    pub command: Vec<String>,
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Consecutive failures before the process is unhealthy.
    #[serde(default = "default_retries")]
    pub retries: u32,
    /// Failures in this window after a (re)start do not count.
    #[serde(default)]
    pub start_period_seconds: u64,
}

impl HealthCheck {
    pub fn validate(&self) -> Result<(), String> {
        if self.command.first().is_none_or(|c| c.is_empty()) {
            return Err("healthcheck.command is empty".into());
        }
        if self.interval_seconds == 0 || self.timeout_seconds == 0 || self.retries == 0 {
            return Err(
                "healthcheck interval_seconds, timeout_seconds and retries must be at least 1"
                    .into(),
            );
        }
        Ok(())
    }
}

/// How long to wait before starting the process again, or `None` to leave it exited. `restarts` is how many restarts
/// already happened; `unhealthy` says init stopped it for failing its health check.
pub fn restart_delay(
    policy: RestartPolicy,
    max_restarts: Option<u32>,
    restarts: u32,
    exit_code: i32,
    unhealthy: bool,
) -> Option<Duration> {
    let wanted = match policy {
        RestartPolicy::No => false,
        RestartPolicy::OnFailure => exit_code != 0 || unhealthy,
        RestartPolicy::Always => true,
    };
    if !wanted || max_restarts.is_some_and(|m| restarts >= m) {
        return None;
    }
    let factor = 1u32.checked_shl(restarts.min(16)).unwrap_or(u32::MAX);
    Some(FIRST_BACKOFF.saturating_mul(factor).min(MAX_BACKOFF))
}

/// What one health check result changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEvent {
    Unchanged,
    Healthy,
    Unhealthy,
}

/// Consecutive-failure counting, reported only on a change (so the console gets one line per transition).
#[derive(Debug, Clone, Default)]
pub struct HealthState {
    failures: u32,
    healthy: Option<bool>,
}

impl HealthState {
    /// `counts` is false inside the start period, where a failure is ignored (a success still counts).
    pub fn record(&mut self, ok: bool, counts: bool, retries: u32) -> HealthEvent {
        if ok {
            self.failures = 0;
            if self.healthy != Some(true) {
                self.healthy = Some(true);
                return HealthEvent::Healthy;
            }
            return HealthEvent::Unchanged;
        }
        if !counts {
            return HealthEvent::Unchanged;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= retries && self.healthy != Some(false) {
            self.healthy = Some(false);
            return HealthEvent::Unhealthy;
        }
        HealthEvent::Unchanged
    }

    /// A restarted process starts over.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// `FLUXVM-RESTART <n> <exit code>`.
pub fn restart_line(n: u32, exit_code: i32) -> String {
    format!("{RESTART_MARKER} {n} {exit_code}")
}

/// `FLUXVM-HEALTH healthy|unhealthy`.
pub fn health_line(healthy: bool) -> String {
    format!(
        "{HEALTH_MARKER} {}",
        if healthy { "healthy" } else { "unhealthy" }
    )
}

/// How many times the process was restarted, from the console log.
pub fn restarts_from_log(log: &str) -> u32 {
    log.lines()
        .rev()
        .find_map(|l| {
            l.trim()
                .strip_prefix(RESTART_MARKER)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

/// The last reported health (`"healthy"` or `"unhealthy"`), if the sandbox has a health check that has run.
pub fn health_from_log(log: &str) -> Option<String> {
    log.lines().rev().find_map(|l| {
        let s = l.trim().strip_prefix(HEALTH_MARKER)?.trim();
        matches!(s, "healthy" | "unhealthy").then(|| s.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_policy_follows_docker() {
        use RestartPolicy::*;
        assert_eq!(restart_delay(No, None, 0, 1, false), None);
        assert_eq!(restart_delay(OnFailure, None, 0, 0, false), None);
        assert_eq!(
            restart_delay(OnFailure, None, 0, 0, true),
            Some(FIRST_BACKOFF)
        );
        assert_eq!(
            restart_delay(OnFailure, None, 0, 137, false),
            Some(FIRST_BACKOFF)
        );
        assert_eq!(
            restart_delay(Always, None, 0, 0, false),
            Some(FIRST_BACKOFF)
        );
    }

    #[test]
    fn backoff_doubles_up_to_a_ceiling_and_max_restarts_stops() {
        use RestartPolicy::Always;
        assert_eq!(
            restart_delay(Always, None, 1, 1, false),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            restart_delay(Always, None, 3, 1, false),
            Some(Duration::from_secs(8))
        );
        assert_eq!(restart_delay(Always, None, 40, 1, false), Some(MAX_BACKOFF));
        assert_eq!(
            restart_delay(Always, Some(3), 2, 1, false),
            Some(Duration::from_secs(4))
        );
        assert_eq!(restart_delay(Always, Some(3), 3, 1, false), None);
        assert_eq!(restart_delay(Always, Some(0), 0, 1, false), None);
    }

    #[test]
    fn health_reports_transitions_only() {
        let mut h = HealthState::default();
        assert_eq!(h.record(false, false, 2), HealthEvent::Unchanged);
        assert_eq!(h.record(false, true, 2), HealthEvent::Unchanged);
        assert_eq!(h.record(false, true, 2), HealthEvent::Unhealthy);
        assert_eq!(h.record(false, true, 2), HealthEvent::Unchanged);
        assert_eq!(h.record(true, true, 2), HealthEvent::Healthy);
        assert_eq!(h.record(true, true, 2), HealthEvent::Unchanged);
        assert_eq!(h.record(false, true, 2), HealthEvent::Unchanged);
        h.reset();
        assert_eq!(h.record(true, false, 2), HealthEvent::Healthy);
    }

    #[test]
    fn markers_round_trip_through_the_log() {
        let log = format!(
            "boot\n{}\n{}\napp output\n{}\n{}\n",
            health_line(true),
            restart_line(1, 3),
            restart_line(2, 137),
            health_line(false)
        );
        assert_eq!(restarts_from_log(&log), 2);
        assert_eq!(health_from_log(&log).as_deref(), Some("unhealthy"));
        assert_eq!(restarts_from_log("nothing"), 0);
        assert_eq!(health_from_log("FLUXVM-HEALTH maybe"), None);
    }

    #[test]
    fn healthchecks_need_a_command_and_positive_timings() {
        let ok: HealthCheck =
            serde_json::from_value(serde_json::json!({"command": ["true"]})).unwrap();
        assert_eq!(
            (ok.interval_seconds, ok.timeout_seconds, ok.retries),
            (30, 5, 3)
        );
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.command.clear();
        assert!(bad.validate().is_err());
        let mut bad = ok;
        bad.retries = 0;
        assert!(bad.validate().is_err());
    }
}
