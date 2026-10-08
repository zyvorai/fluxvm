// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Pressure-aware create admission.
//!
//! `policy::enforce_host_totals` only compares requested sizes against
//! declared quotas. This module adds an optional second gate that looks at
//! what the host is actually doing: `MemAvailable` from `/proc/meminfo` and
//! memory PSI from `/proc/pressure/memory`. Every threshold defaults to off
//! (see `config::Policy`), so an unconfigured host behaves as before.
//!
//! The decision itself ([`check_pressure`]) is a pure function of a
//! [`HostPressure`] sample so it can be unit tested without a live host.

use crate::config::Policy;
use std::path::Path;

/// One sample of host memory state. A field is `None` when the host does not
/// expose it (no PSI in the kernel, non-Linux, unreadable file); a threshold
/// whose input is `None` is skipped rather than failing every create.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostPressure {
    pub mem_available_mib: Option<u64>,
    pub mem_total_mib: Option<u64>,
    /// `some avg10` of `/proc/pressure/memory`, percent.
    pub psi_some_avg10: Option<f64>,
    /// `full avg10` of `/proc/pressure/memory`, percent.
    pub psi_full_avg10: Option<f64>,
}

/// Why admission was refused. `Display` is the message returned to the caller
/// and recorded in the `quota.deny` audit event.
#[derive(Debug, Clone, PartialEq)]
pub enum PressureDeny {
    LowMemory {
        available_mib: u64,
        requested_mib: u64,
        reserve_mib: u64,
    },
    PsiSome {
        avg10: f64,
        max: f64,
    },
    PsiFull {
        avg10: f64,
        max: f64,
    },
}

impl std::fmt::Display for PressureDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LowMemory {
                available_mib,
                requested_mib,
                reserve_mib,
            } => write!(
                f,
                "host under memory pressure: {available_mib} MiB available, {requested_mib} MiB \
                 requested, policy.min_host_mem_available_mib reserve is {reserve_mib} MiB"
            ),
            Self::PsiSome { avg10, max } => write!(
                f,
                "host under memory pressure: PSI some avg10 {avg10:.2} exceeds \
                 policy.max_host_mem_psi_some_avg10 ({max:.2})"
            ),
            Self::PsiFull { avg10, max } => write!(
                f,
                "host under memory pressure: PSI full avg10 {avg10:.2} exceeds \
                 policy.max_host_mem_psi_full_avg10 ({max:.2})"
            ),
        }
    }
}

impl std::error::Error for PressureDeny {}

/// Pure admission decision. `Ok` when every configured threshold holds.
///
/// The memory reserve is checked against `available - requested`: a create
/// must leave at least `min_host_mem_available_mib` free after it lands.
pub fn check_pressure(
    requested_mib: u64,
    policy: &Policy,
    host: &HostPressure,
) -> Result<(), PressureDeny> {
    if let Some(reserve) = policy.min_host_mem_available_mib
        && let Some(avail) = host.mem_available_mib
        && avail.saturating_sub(requested_mib) < reserve
    {
        return Err(PressureDeny::LowMemory {
            available_mib: avail,
            requested_mib,
            reserve_mib: reserve,
        });
    }
    if let Some(max) = policy.max_host_mem_psi_some_avg10
        && let Some(avg10) = host.psi_some_avg10
        && avg10 > max
    {
        return Err(PressureDeny::PsiSome { avg10, max });
    }
    if let Some(max) = policy.max_host_mem_psi_full_avg10
        && let Some(avg10) = host.psi_full_avg10
        && avg10 > max
    {
        return Err(PressureDeny::PsiFull { avg10, max });
    }
    Ok(())
}

/// True when any pressure threshold is configured.
pub fn is_enabled(policy: &Policy) -> bool {
    policy.min_host_mem_available_mib.is_some()
        || policy.max_host_mem_psi_some_avg10.is_some()
        || policy.max_host_mem_psi_full_avg10.is_some()
}

/// Parse `/proc/meminfo` text into `(MemAvailable, MemTotal)` in MiB.
pub fn parse_meminfo(text: &str) -> (Option<u64>, Option<u64>) {
    let mut avail = None;
    let mut total = None;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let kib = rest
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u64>().ok());
        match key {
            "MemAvailable" => avail = kib.map(|k| k / 1024),
            "MemTotal" => total = kib.map(|k| k / 1024),
            _ => {}
        }
    }
    (avail, total)
}

/// Sample the host from `/proc`. Missing or unreadable inputs stay `None`.
pub fn sample_host() -> HostPressure {
    sample_from(
        Path::new("/proc/meminfo"),
        Path::new("/proc/pressure/memory"),
    )
}

/// [`sample_host`] with explicit paths, for tests.
pub fn sample_from(meminfo: &Path, psi: &Path) -> HostPressure {
    let mut out = HostPressure::default();
    if let Ok(text) = std::fs::read_to_string(meminfo) {
        let (avail, total) = parse_meminfo(&text);
        out.mem_available_mib = avail;
        out.mem_total_mib = total;
    }
    if let Ok(text) = std::fs::read_to_string(psi)
        && let Ok(stats) = fluxvm_cgroup::pressure::parse_pressure(psi, &text)
    {
        out.psi_some_avg10 = Some(stats.some.avg10);
        out.psi_full_avg10 = stats.full.map(|f| f.avg10);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            min_host_mem_available_mib: Some(1024),
            max_host_mem_psi_some_avg10: Some(10.0),
            max_host_mem_psi_full_avg10: Some(2.0),
            ..Policy::default()
        }
    }

    fn calm() -> HostPressure {
        HostPressure {
            mem_available_mib: Some(8192),
            mem_total_mib: Some(16384),
            psi_some_avg10: Some(0.5),
            psi_full_avg10: Some(0.0),
        }
    }

    #[test]
    fn everything_off_admits_anything() {
        let hot = HostPressure {
            mem_available_mib: Some(1),
            mem_total_mib: Some(1),
            psi_some_avg10: Some(99.0),
            psi_full_avg10: Some(99.0),
        };
        assert!(!is_enabled(&Policy::default()));
        assert!(check_pressure(4096, &Policy::default(), &hot).is_ok());
    }

    #[test]
    fn calm_host_is_admitted() {
        assert!(is_enabled(&policy()));
        assert!(check_pressure(2048, &policy(), &calm()).is_ok());
    }

    #[test]
    fn reserve_counts_the_requested_size() {
        // 8192 - 7168 = 1024 left: exactly the reserve, allowed.
        assert!(check_pressure(7168, &policy(), &calm()).is_ok());
        // One MiB more dips below the reserve.
        let err = check_pressure(7169, &policy(), &calm()).unwrap_err();
        assert!(matches!(err, PressureDeny::LowMemory { .. }));
        assert!(err.to_string().contains("min_host_mem_available_mib"));
    }

    #[test]
    fn psi_thresholds_deny_above_and_admit_at_the_limit() {
        let mut h = calm();
        h.psi_some_avg10 = Some(10.0);
        assert!(check_pressure(1, &policy(), &h).is_ok());
        h.psi_some_avg10 = Some(10.01);
        assert!(matches!(
            check_pressure(1, &policy(), &h).unwrap_err(),
            PressureDeny::PsiSome { .. }
        ));
        let mut h = calm();
        h.psi_full_avg10 = Some(2.5);
        assert!(matches!(
            check_pressure(1, &policy(), &h).unwrap_err(),
            PressureDeny::PsiFull { .. }
        ));
    }

    #[test]
    fn missing_inputs_skip_their_threshold() {
        assert!(check_pressure(1 << 20, &policy(), &HostPressure::default()).is_ok());
    }

    #[test]
    fn parses_meminfo() {
        let text = "MemTotal:       16384000 kB\nMemFree:  100 kB\nMemAvailable:    8192000 kB\n";
        assert_eq!(parse_meminfo(text), (Some(8000), Some(16000)));
        assert_eq!(parse_meminfo("garbage"), (None, None));
    }

    #[test]
    fn samples_from_files() {
        let dir = tempfile::tempdir().unwrap();
        let mi = dir.path().join("meminfo");
        let psi = dir.path().join("memory");
        std::fs::write(&mi, "MemTotal: 2048 kB\nMemAvailable: 1024 kB\n").unwrap();
        std::fs::write(
            &psi,
            "some avg10=3.00 avg60=0.00 avg300=0.00 total=1\nfull avg10=1.50 avg60=0.00 avg300=0.00 total=1\n",
        )
        .unwrap();
        let s = sample_from(&mi, &psi);
        assert_eq!(s.mem_available_mib, Some(1));
        assert_eq!(s.psi_some_avg10, Some(3.0));
        assert_eq!(s.psi_full_avg10, Some(1.5));
        let none = sample_from(&dir.path().join("x"), &dir.path().join("y"));
        assert_eq!(none, HostPressure::default());
    }
}
