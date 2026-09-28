// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Sandbox policy: what a confined process may touch.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Landlock TCP rule for one direction (connect or bind).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpRule {
    /// Not restricted.
    Any,
    /// No TCP port allowed.
    Deny,
    /// Only these ports.
    Ports(Vec<u16>),
}

/// What seccomp does when a denied syscall is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompMode {
    /// Return `EPERM` to the caller.
    Errno,
    /// Kill the whole process.
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Read-only (and executable) paths.
    pub read: Vec<PathBuf>,
    /// Read-write paths (implies read).
    pub write: Vec<PathBuf>,
    pub tcp_connect: TcpRule,
    pub tcp_bind: TcpRule,
    /// Landlock IPC scoping: abstract unix sockets and signals outside the
    /// sandbox (needs Landlock ABI >= 6).
    pub scope_ipc: bool,
    /// `None` disables the seccomp denylist.
    pub seccomp: Option<SeccompMode>,
    /// Permit creating new namespaces (denied by default).
    pub allow_namespaces: bool,
    /// Address-space limit in bytes (`RLIMIT_AS`).
    pub max_memory: Option<u64>,
    /// `RLIMIT_NPROC`. Counts every process of the real UID, not just the
    /// sandbox, so pick a value above the user's current process count.
    pub max_processes: Option<u64>,
    /// CPU seconds (`RLIMIT_CPU`).
    pub cpu_seconds: Option<u64>,
    /// Wall-clock timeout; the whole process group is killed.
    pub timeout_secs: Option<u64>,
    pub clean_env: bool,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    /// Report what could not be enforced instead of failing.
    pub best_effort: bool,
    /// Pretend the kernel's Landlock ABI is at most this (testing, or to pin
    /// behaviour across hosts).
    pub max_abi: Option<u32>,
    /// Captured output cap per stream.
    pub max_output_bytes: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            read: Vec::new(),
            write: Vec::new(),
            tcp_connect: TcpRule::Any,
            tcp_bind: TcpRule::Any,
            scope_ipc: true,
            seccomp: Some(SeccompMode::Errno),
            allow_namespaces: false,
            max_memory: None,
            max_processes: None,
            cpu_seconds: None,
            timeout_secs: None,
            clean_env: false,
            env: Vec::new(),
            cwd: None,
            best_effort: false,
            max_abi: None,
            max_output_bytes: 16 * 1024 * 1024,
        }
    }
}

/// What was actually enforced for a run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    /// Landlock ABI in effect (0 = unavailable).
    pub landlock_abi: u32,
    pub filesystem: bool,
    pub tcp_connect: bool,
    pub tcp_bind: bool,
    pub scope_abstract_unix: bool,
    pub scope_signal: bool,
    pub seccomp: bool,
    /// Everything the policy asked for (or that would normally apply) that
    /// this run did NOT enforce.
    pub not_enforced: Vec<String>,
}

/// Parse `256M`, `1G`, `512K`, `4096` (binary multiples).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty size".into());
    }
    let lower = t.to_ascii_lowercase();
    let lower = lower.trim_end_matches('b').trim_end_matches('i');
    let (num, mult) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1u64 << 10),
        Some('m') => (&lower[..lower.len() - 1], 1u64 << 20),
        Some('g') => (&lower[..lower.len() - 1], 1u64 << 30),
        Some('t') => (&lower[..lower.len() - 1], 1u64 << 40),
        _ => (lower, 1u64),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid size {s:?}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_with_binary_suffixes() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("512K").unwrap(), 512 * 1024);
        assert_eq!(parse_size("256M").unwrap(), 256 << 20);
        assert_eq!(parse_size("1g").unwrap(), 1 << 30);
        assert_eq!(parse_size("2GiB").unwrap(), 2 << 30);
        assert_eq!(parse_size("64MB").unwrap(), 64 << 20);
    }

    #[test]
    fn bad_sizes_are_rejected() {
        assert!(parse_size("").is_err());
        assert!(parse_size("abc").is_err());
        assert!(parse_size("12X").is_err());
        assert!(parse_size("99999999999T").is_err());
    }

    #[test]
    fn default_policy_is_the_safe_one() {
        let p = Policy::default();
        assert!(p.scope_ipc);
        assert!(!p.best_effort);
        assert!(!p.allow_namespaces);
        assert_eq!(p.seccomp, Some(SeccompMode::Errno));
    }

    #[test]
    fn policy_round_trips_through_json() {
        let mut p = Policy::default();
        p.tcp_connect = TcpRule::Ports(vec![443]);
        p.max_memory = Some(1 << 28);
        let j = serde_json::to_string(&p).unwrap();
        let back: Policy = serde_json::from_str(&j).unwrap();
        assert_eq!(back.tcp_connect, TcpRule::Ports(vec![443]));
        assert_eq!(back.max_memory, Some(1 << 28));
        // Unknown-field-free partial JSON falls back to defaults.
        let partial: Policy = serde_json::from_str(r#"{"read":["/usr"]}"#).unwrap();
        assert!(partial.scope_ipc);
    }
}
