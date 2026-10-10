// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Pressure-aware create admission.
//!
//! `policy::enforce_host_totals` only compares requested sizes against
//! declared quotas. This module adds an optional second gate that looks at
//! what the host is actually doing: `MemAvailable` from `/proc/meminfo` and
//! memory PSI from `/proc/pressure/memory` on Linux; on macOS, available
//! memory from `vm_stat` and the kernel's memory-pressure level
//! (`kern.memorystatus_vm_pressure_level`). Every threshold defaults to off
//! (see `config::Policy`), so an unconfigured host behaves as before.
//!
//! The decision itself ([`check_pressure`]) is a pure function of a
//! [`HostPressure`] sample so it can be unit tested without a live host.

use crate::config::Policy;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The macOS kernel's own memory-pressure verdict, ordered from calm to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PressureLevel {
    Normal,
    Warn,
    Critical,
}

impl PressureLevel {
    /// `kern.memorystatus_vm_pressure_level`: 1 normal, 2 warn, 4 critical.
    pub fn from_sysctl(v: i64) -> Option<Self> {
        match v {
            1 => Some(Self::Normal),
            2 => Some(Self::Warn),
            4 => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Warn => "warn",
            Self::Critical => "critical",
        })
    }
}

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
    /// macOS memory-pressure level.
    pub level: Option<PressureLevel>,
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
    Level {
        level: PressureLevel,
        deny_at: PressureLevel,
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
            Self::Level { level, deny_at } => write!(
                f,
                "host under memory pressure: level {level} reaches \
                 policy.deny_host_pressure_level ({deny_at})"
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
    if let Some(deny_at) = policy.deny_host_pressure_level
        && let Some(level) = host.level
        && level >= deny_at
    {
        return Err(PressureDeny::Level { level, deny_at });
    }
    Ok(())
}

/// True when any pressure threshold is configured.
pub fn is_enabled(policy: &Policy) -> bool {
    policy.min_host_mem_available_mib.is_some()
        || policy.max_host_mem_psi_some_avg10.is_some()
        || policy.max_host_mem_psi_full_avg10.is_some()
        || policy.deny_host_pressure_level.is_some()
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

/// Parse `vm_stat` output into available MiB: free + inactive + speculative +
/// purgeable pages, which the kernel can hand out without swapping.
pub fn parse_vm_stat(text: &str) -> Option<u64> {
    let mut lines = text.lines();
    let page_size: u64 = lines
        .next()?
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let mut pages = 0u64;
    let mut seen = false;
    for line in lines {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        if matches!(
            key.trim(),
            "Pages free" | "Pages inactive" | "Pages speculative" | "Pages purgeable"
        ) && let Ok(n) = val.trim().trim_end_matches('.').parse::<u64>()
        {
            pages += n;
            seen = true;
        }
    }
    seen.then(|| pages * page_size / (1024 * 1024))
}

/// Sample the host: `/proc` on Linux, `vm_stat` + sysctl on macOS. Missing or
/// unreadable inputs stay `None`.
pub fn sample_host() -> HostPressure {
    #[cfg(target_os = "macos")]
    {
        sample_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        sample_from(
            Path::new("/proc/meminfo"),
            Path::new("/proc/pressure/memory"),
        )
    }
}

#[cfg(target_os = "macos")]
fn sysctl_int(name: &str) -> Option<i64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = [0u8; 8];
    let mut len = buf.len();
    // SAFETY: `buf` outlives the call and `len` is its size; sysctlbyname
    // writes at most `len` bytes and stores the written length back.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    match (rc, len) {
        (0, 4) => Some(i32::from_ne_bytes(buf[..4].try_into().ok()?) as i64),
        (0, 8) => Some(i64::from_ne_bytes(buf)),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn sample_macos() -> HostPressure {
    let available = std::process::Command::new("/usr/bin/vm_stat")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_vm_stat(&String::from_utf8_lossy(&o.stdout)));
    HostPressure {
        mem_available_mib: available,
        mem_total_mib: sysctl_int("hw.memsize").map(|b| b as u64 / (1024 * 1024)),
        level: sysctl_int("kern.memorystatus_vm_pressure_level")
            .and_then(PressureLevel::from_sysctl),
        ..HostPressure::default()
    }
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
            level: Some(PressureLevel::Normal),
        }
    }

    #[test]
    fn everything_off_admits_anything() {
        let hot = HostPressure {
            mem_available_mib: Some(1),
            mem_total_mib: Some(1),
            psi_some_avg10: Some(99.0),
            psi_full_avg10: Some(99.0),
            level: Some(PressureLevel::Critical),
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
    fn pressure_level_denies_at_or_above_the_threshold() {
        let p = Policy {
            deny_host_pressure_level: Some(PressureLevel::Warn),
            ..Policy::default()
        };
        assert!(is_enabled(&p));
        let mut h = calm();
        assert!(check_pressure(1, &p, &h).is_ok());
        h.level = Some(PressureLevel::Warn);
        let err = check_pressure(1, &p, &h).unwrap_err();
        assert!(err.to_string().contains("deny_host_pressure_level"));
        h.level = Some(PressureLevel::Critical);
        assert!(check_pressure(1, &p, &h).is_err());
        h.level = None;
        assert!(check_pressure(1, &p, &h).is_ok());
        assert_eq!(PressureLevel::from_sysctl(4), Some(PressureLevel::Critical));
        assert_eq!(PressureLevel::from_sysctl(3), None);
        let lvl: PressureLevel = serde_json::from_str(r#""warn""#).unwrap();
        assert_eq!(lvl, PressureLevel::Warn);
    }

    #[test]
    fn parses_vm_stat() {
        let text = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
                    Pages free:                                   105261.\n\
                    Pages active:                                 225308.\n\
                    Pages inactive:                               222161.\n\
                    Pages speculative:                              4295.\n\
                    Pages wired down:                             176684.\n\
                    Pages purgeable:                                4481.\n";
        // (105261 + 222161 + 4295 + 4481) * 16 KiB
        assert_eq!(parse_vm_stat(text), Some(5253));
        assert_eq!(parse_vm_stat("garbage"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn samples_this_mac() {
        let s = sample_host();
        assert!(s.mem_total_mib.unwrap() > 0);
        assert!(s.mem_available_mib.unwrap() <= s.mem_total_mib.unwrap());
        assert!(s.level.is_some());
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
