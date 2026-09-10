// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Container lifecycle protocol spoken between `containerd-shim-fluxvm-v2`
//! on the host and `fluxvm-container-agent` inside a FluxVM guest.
//!
//! The protocol is newline-delimited JSON over AF_VSOCK. Requests carry the
//! same per-VM shared secret used by the existing FluxVM guest agent, but are
//! served on a separate port so the stable guest-agent API remains unchanged.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const DEFAULT_CONTAINER_AGENT_PORT: u32 = 17778;
pub const DEFAULT_CONTAINER_STREAM_PORT: u32 = 17779;
pub const DEFAULT_CALL_TIMEOUT_SECS: u64 = 30;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerIo {
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub terminal: bool,
    /// Set 5: stdio is transported over the dedicated VSOCK stream port
    /// instead of guest-visible virtiofs files. Path fields remain presence
    /// markers for stdin/stdout/stderr so older agents can reject cleanly.
    #[serde(default)]
    pub streaming: bool,
}


#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IoStreamKind {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoStreamAttach {
    #[serde(default)]
    pub token: Option<String>,
    pub id: String,
    #[serde(default)]
    pub exec_id: Option<String>,
    pub stream: IoStreamKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoStreamAck {
    pub ok: bool,
    #[serde(default)]
    pub message: Option<String>,
}

/// Sentinel Set 8S: per-container network policy, enforced in-guest via
/// cgroup_skb programs attached to the container's own cgroup (independent
/// of and additive to Set 6S's host-side, Pod-scoped `fluxvm_pod_policy`).
/// `None` on `Create` still gets the container policed (every container's
/// cgroup gets the programs attached unconditionally) but with an
/// enabled-and-empty policy, which the guest's fail-closed-by-default design
/// (see bpf/fluxvm_guest_cgroup.bpf.c) turns into "deny all non-loopback
/// traffic until a policy is actually set."
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerNetworkPolicy {
    /// An unlisted peer is allowed when true. Default false: unlike Set 6S's
    /// Pod-level policy (allow-by-default for backward compatibility with
    /// VMs that never opt in), a container only ever gets this policy
    /// attached at all once Set 8S is in use, so there's no legacy
    /// allow-everything behavior to preserve.
    #[serde(default)]
    pub default_allow: bool,
    /// Log-and-allow instead of drop.
    #[serde(default)]
    pub audit_mode: bool,
    #[serde(default)]
    pub allow_addresses: Vec<IpAddr>,
    #[serde(default)]
    pub deny_addresses: Vec<IpAddr>,
}

/// Portable subset of OCI LinuxResources used by the guest cgroup-v2 layer.
/// Values keep OCI units/semantics (quota/period in microseconds, memory in
/// bytes). Fields not present remain unchanged on live update.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    #[serde(default)]
    pub cpu_quota: Option<i64>,
    #[serde(default)]
    pub cpu_period: Option<u64>,
    #[serde(default)]
    pub cpu_shares: Option<u64>,
    #[serde(default)]
    pub cpuset_cpus: Option<String>,
    #[serde(default)]
    pub cpuset_mems: Option<String>,
    #[serde(default)]
    pub memory_limit_bytes: Option<i64>,
    /// OCI memory.reservation, mapped to cgroup-v2 memory.low.
    #[serde(default)]
    pub memory_reservation_bytes: Option<i64>,
    /// OCI memory.swap (memory+swap combined): 0 means unset and -1 means
    /// unlimited, matching OCI/cgroup-v1 compatibility semantics.
    #[serde(default)]
    pub memory_swap_bytes: Option<i64>,
    #[serde(default)]
    pub pids_limit: Option<i64>,
    /// Safe cgroup-v2 unified controls copied from OCI LinuxResources.unified.
    /// The guest agent enforces a strict allowlist before touching cgroupfs.
    #[serde(default)]
    pub unified: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ContainerStats {
    pub cpu_usage_usec: u64,
    pub cpu_user_usec: u64,
    pub cpu_system_usec: u64,
    pub cpu_nr_periods: u64,
    pub cpu_nr_throttled: u64,
    pub cpu_throttled_usec: u64,
    pub memory_usage_bytes: u64,
    pub memory_limit_bytes: u64,
    pub memory_peak_bytes: u64,
    pub memory_swap_usage_bytes: u64,
    pub memory_swap_limit_bytes: u64,
    pub memory_anon_bytes: u64,
    pub memory_file_bytes: u64,
    pub memory_anon_thp_bytes: u64,
    pub memory_file_mapped_bytes: u64,
    pub memory_dirty_bytes: u64,
    pub memory_writeback_bytes: u64,
    pub memory_pgfault: u64,
    pub memory_pgmajfault: u64,
    pub memory_inactive_anon_bytes: u64,
    pub memory_active_anon_bytes: u64,
    pub memory_total_inactive_file_bytes: u64,
    pub memory_active_file_bytes: u64,
    pub memory_unevictable_bytes: u64,
    pub memory_events_max: u64,
    pub memory_events_oom: u64,
    pub memory_events_oom_kill: u64,
    pub pids_current: u64,
    /// `0` means unlimited, matching containerd's cgroup metrics convention.
    pub pids_limit: u64,
}

/// Monotonic cgroup-v2 event counters used by the host shim to publish
/// containerd lifecycle events without granting the host access to guest
/// cgroupfs. Counters come from the container's `memory.events` file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CgroupEvents {
    pub low: u64,
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

/// Guest-side security enforcement counters. These are process-wide monotonic
/// counters for the container agent and are intended for diagnostics/audit,
/// not billing. They deliberately expose counts only, never syscall arguments
/// or SELinux/AppArmor labels.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SecurityStats {
    pub seccomp_notify_received: u64,
    pub seccomp_notify_denied: u64,
    pub seccomp_notify_continued: u64,
    pub seccomp_notify_errors: u64,
    pub selinux_mounts_labeled: u64,
    pub lsm_apply_failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum ContainerRequest {
    Ping,
    /// Configure the aggregate Pod/sandbox cgroup. This is intentionally
    /// separate from per-container resources: Kubernetes puts Pod-wide limits
    /// on CRI sandbox annotations, not always in the pause container's OCI
    /// linux.resources block.
    ConfigureSandboxResources {
        resources: ResourceLimits,
    },
    Create {
        id: String,
        /// Complete OCI runtime config after host paths have been translated
        /// into paths visible from inside the guest.
        config_json: String,
        io: ContainerIo,
        /// Set 6: this container is the CRI pause/sandbox container for its
        /// Pod group. Its IPC/UTS (and PID, if `share_process_namespace`)
        /// namespaces are recorded so sibling containers in the same group
        /// can join them, matching runc/Kata's "join the pause container"
        /// convention. Defaults to `false` so older shims/bare `ctr run`
        /// keep today's behavior (every container fully isolated).
        #[serde(default)]
        is_sandbox: bool,
        /// Set 6: mirrors the Kubernetes PodSpec `shareProcessNamespace`
        /// field. Only meaningful when a sandbox container exists for the
        /// group; ignored otherwise.
        #[serde(default)]
        share_process_namespace: bool,
        /// Set 8S: see `ContainerNetworkPolicy`.
        #[serde(default)]
        network_policy: Option<ContainerNetworkPolicy>,
    },
    Start {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
    },
    State {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
    },
    Exec {
        id: String,
        exec_id: String,
        /// OCI Process JSON (not a full config.json).
        process_json: String,
        io: ContainerIo,
    },
    Kill {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        signal: i32,
        #[serde(default)]
        all: bool,
    },
    Pause { id: String },
    Resume { id: String },
    Wait {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
    },
    Pids { id: String },
    Stats { id: String },
    CgroupEvents { id: String },
    /// Return monotonic guest-agent security counters.
    SecurityStats,
    UpdateResources {
        id: String,
        resources: ResourceLimits,
    },
    ResizePty {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        width: u32,
        height: u32,
    },
    CloseIo {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
    },
    Delete {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        #[serde(default)]
        force: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEnvelope {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub request: ContainerRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ContainerResponse {
    Pong,
    SandboxResourcesConfigured,
    Created {
        pid: u32,
        /// Set 9S: stable per-container identity minted in-guest, exposed so
        /// host-side audit can correlate an in-guest LSM denial event back
        /// to `(container_id, container_identity)`. `0` when Set 9S's guest
        /// LSM isn't attached (missing `CONFIG_BPF_LSM`/BTF/bpffs) — never a
        /// minted value, since the top tag bit is always set on a real one.
        #[serde(default)]
        container_identity: u32,
    },
    Started { pid: u32 },
    ExecStarted { pid: u32 },
    State {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        status: ContainerStatus,
        pid: u32,
        #[serde(default)]
        exit_code: Option<i32>,
        #[serde(default)]
        exited_at_unix_nano: Option<i64>,
    },
    Exited {
        exit_code: i32,
        exited_at_unix_nano: i64,
    },
    Pids { pids: Vec<u32> },
    Stats { stats: ContainerStats },
    CgroupEvents { events: CgroupEvents },
    SecurityStats { stats: SecurityStats },
    ResourcesUpdated,
    PtyResized,
    IoClosed,
    Killed,
    Paused,
    Resumed,
    Deleted {
        pid: u32,
        exit_code: i32,
        exited_at_unix_nano: i64,
    },
    Error { message: String },
}

pub fn encode_line<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let mut out = serde_json::to_string(value)?;
    out.push('\n');
    Ok(out)
}

pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_round_trip() {
        let req = ContainerEnvelope {
            token: Some("secret".into()),
            request: ContainerRequest::Create {
                id: "c1".into(),
                config_json: "{\"ociVersion\":\"1.1.0\"}".into(),
                io: ContainerIo {
                    stdin: None,
                    stdout: Some("/run/fluxvm/pod/io/c1.out".into()),
                    stderr: Some("/run/fluxvm/pod/io/c1.err".into()),
                    terminal: false,
                    streaming: false,
                },
                is_sandbox: true,
                share_process_namespace: false,
                network_policy: None,
            },
        };
        let line = encode_line(&req).unwrap();
        let back: ContainerEnvelope = decode_line(&line).unwrap();
        assert_eq!(back.token.as_deref(), Some("secret"));
        assert!(matches!(
            back.request,
            ContainerRequest::Create { is_sandbox: true, share_process_namespace: false, .. }
        ));
    }

    #[test]
    fn resource_update_round_trip() {
        let req = ContainerEnvelope {
            token: None,
            request: ContainerRequest::UpdateResources {
                id: "c1".into(),
                resources: ResourceLimits {
                    cpu_quota: Some(50_000),
                    cpu_period: Some(100_000),
                    memory_limit_bytes: Some(256 * 1024 * 1024),
                    memory_reservation_bytes: Some(128 * 1024 * 1024),
                    memory_swap_bytes: Some(512 * 1024 * 1024),
                    pids_limit: Some(128),
                    unified: BTreeMap::from([("memory.high".into(), "201326592".into())]),
                    ..Default::default()
                },
            },
        };
        let line = encode_line(&req).unwrap();
        let back: ContainerEnvelope = decode_line(&line).unwrap();
        assert!(matches!(back.request, ContainerRequest::UpdateResources { .. }));
    }

    #[test]
    fn deleted_response_round_trip() {
        let response = ContainerResponse::Deleted {
            pid: 42,
            exit_code: 137,
            exited_at_unix_nano: 123456789,
        };
        let line = encode_line(&response).unwrap();
        let back: ContainerResponse = decode_line(&line).unwrap();
        assert!(matches!(
            back,
            ContainerResponse::Deleted { pid: 42, exit_code: 137, .. }
        ));
    }

    #[test]
    fn stats_response_round_trip() {
        let response = ContainerResponse::Stats {
            stats: ContainerStats {
                cpu_usage_usec: 100,
                memory_usage_bytes: 4096,
                pids_current: 3,
                pids_limit: 64,
                ..Default::default()
            },
        };
        let line = encode_line(&response).unwrap();
        let back: ContainerResponse = decode_line(&line).unwrap();
        assert!(matches!(back, ContainerResponse::Stats { .. }));
    }
    #[test]
    fn exited_response_round_trip() {
        let response = ContainerResponse::Exited {
            exit_code: 0,
            exited_at_unix_nano: 1_759_000_000_000_000_000,
        };
        let line = encode_line(&response).unwrap();
        let back: ContainerResponse = decode_line(&line).unwrap();
        assert!(matches!(back, ContainerResponse::Exited { exit_code: 0, .. }));
    }

    #[test]
    fn cgroup_events_round_trip() {
        let response = ContainerResponse::CgroupEvents {
            events: CgroupEvents { oom: 2, oom_kill: 1, ..Default::default() },
        };
        let line = encode_line(&response).unwrap();
        let back: ContainerResponse = decode_line(&line).unwrap();
        assert!(matches!(back, ContainerResponse::CgroupEvents { events } if events.oom_kill == 1));
    }

    #[test]
    fn stream_attach_round_trip() {
        let attach = IoStreamAttach {
            token: Some("secret".into()),
            id: "c1".into(),
            exec_id: Some("shell".into()),
            stream: IoStreamKind::Stdout,
        };
        let line = encode_line(&attach).unwrap();
        let back: IoStreamAttach = decode_line(&line).unwrap();
        assert_eq!(back.id, "c1");
        assert_eq!(back.exec_id.as_deref(), Some("shell"));
        assert_eq!(back.stream, IoStreamKind::Stdout);
    }

    #[test]
    fn security_stats_round_trip() {
        let response = ContainerResponse::SecurityStats {
            stats: SecurityStats { seccomp_notify_denied: 2, ..Default::default() },
        };
        let line = encode_line(&response).unwrap();
        let back: ContainerResponse = decode_line(&line).unwrap();
        assert!(matches!(back, ContainerResponse::SecurityStats { stats } if stats.seccomp_notify_denied == 2));
    }

}
