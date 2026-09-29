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

/// Run the command as this unprivileged uid/gid (needs a root caller). Every
/// sandbox gets its own uid so `RLIMIT_NPROC` and file ownership are per sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}

impl std::str::FromStr for RunAs {
    type Err = String;

    /// `UID:GID`, or a bare `UID` (gid = uid).
    fn from_str(s: &str) -> Result<Self, String> {
        let (u, g) = match s.split_once(':') {
            Some((u, g)) => (u, g),
            None => (s, s),
        };
        let uid: u32 = u
            .trim()
            .parse()
            .map_err(|_| format!("invalid uid in {s:?}"))?;
        let gid: u32 = g
            .trim()
            .parse()
            .map_err(|_| format!("invalid gid in {s:?}"))?;
        if uid == 0 || gid == 0 {
            return Err("run-as must be an unprivileged (non-zero) uid and gid".into());
        }
        Ok(RunAs { uid, gid })
    }
}

/// Namespace isolation: a private mount/pid/ipc/uts view (and no network when
/// the policy grants none) built with unprivileged user namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    /// No namespaces (Landlock and seccomp only).
    #[default]
    Off,
    /// Use namespaces when the kernel allows them; otherwise run without and
    /// report it in `enforcement.not_enforced`.
    Auto,
    /// Namespaces are required: refuse to run without them.
    Strict,
}

impl std::str::FromStr for Isolation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(Isolation::Off),
            "auto" => Ok(Isolation::Auto),
            "strict" => Ok(Isolation::Strict),
            other => Err(format!(
                "isolation = {other:?}: expected \"off\", \"auto\" or \"strict\""
            )),
        }
    }
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
    /// Drop to this uid/gid before confining (caller must be root).
    pub run_as: Option<RunAs>,
    /// Namespace isolation mode.
    pub isolation: Isolation,
    /// Allow `socket(AF_UNIX)`. Otherwise it is denied by seccomp wherever
    /// the mount namespace does not already hide host sockets.
    pub allow_unix: bool,
    /// Allow UDP/raw/packet/netlink sockets while the network is shared with
    /// the host (name resolution needs UDP). Ignored when TCP is unrestricted.
    pub allow_udp: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            read: Vec::new(),
            write: Vec::new(),
            // Deny by default: a bare `Policy::default()` must not silently
            // hand out unrestricted TCP, and (via `net_restricted` in
            // run.rs) it must not skip the UDP/raw/packet/netlink/AF_UNIX
            // seccomp filters either — those only engage once the policy
            // restricts the network at all. Every caller that wants
            // outbound access sets these fields explicitly.
            tcp_connect: TcpRule::Deny,
            tcp_bind: TcpRule::Deny,
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
            run_as: None,
            isolation: Isolation::Off,
            allow_unix: false,
            allow_udp: false,
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
    /// Ran as the unprivileged `run_as` uid/gid.
    #[serde(default)]
    pub uid_dropped: bool,
    /// Private user/mount/pid/ipc/uts namespaces and a private root.
    #[serde(default)]
    pub namespaces: bool,
    /// Empty network namespace (no TCP, UDP or unix reachability outside).
    #[serde(default)]
    pub network_isolated: bool,
    /// seccomp argument filters on `socket()` (UDP/raw/packet/netlink/unix).
    #[serde(default)]
    pub seccomp_sockets: bool,
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
        // Deny-by-default: a caller who builds a Policy and forgets to set
        // network fields must not end up with unrestricted TCP, or (since
        // run.rs's socket filters only engage once the policy restricts the
        // network at all) with unfiltered UDP/raw/AF_UNIX either.
        assert_eq!(p.tcp_connect, TcpRule::Deny);
        assert_eq!(p.tcp_bind, TcpRule::Deny);
        assert!(!p.allow_unix);
        assert!(!p.allow_udp);
    }

    #[test]
    fn run_as_and_isolation_parse() {
        assert_eq!(
            "1000:2000".parse::<RunAs>().unwrap(),
            RunAs {
                uid: 1000,
                gid: 2000
            }
        );
        assert_eq!(
            "4242".parse::<RunAs>().unwrap(),
            RunAs {
                uid: 4242,
                gid: 4242
            }
        );
        assert!("0".parse::<RunAs>().is_err());
        assert!("1000:0".parse::<RunAs>().is_err());
        assert!("x:1".parse::<RunAs>().is_err());
        assert_eq!("auto".parse::<Isolation>().unwrap(), Isolation::Auto);
        assert_eq!("strict".parse::<Isolation>().unwrap(), Isolation::Strict);
        assert!("full".parse::<Isolation>().is_err());
    }

    #[test]
    fn new_fields_default_to_the_conservative_values() {
        let p = Policy::default();
        assert_eq!(p.isolation, Isolation::Off);
        assert!(p.run_as.is_none());
        assert!(!p.allow_unix && !p.allow_udp);
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
