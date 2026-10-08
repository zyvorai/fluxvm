// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Confined `exec`: runs a request's command under Landlock + seccomp via
//! `fluxvm-procbox` when the request carries a policy, and reports what was
//! actually enforced. Also holds the token fail-closed switch.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use fluxvm_guest_protocol::{
    AgentResponse, ExecEnforcement, ExecIsolation, ExecPolicy, ExecSeccompMode, ExecTcpRule,
};
use fluxvm_procbox::{Enforcement, Isolation, Policy, RunAs, RunOptions, SeccompMode, TcpRule};
use std::path::PathBuf;
use std::time::Duration;

/// Environment variable that lets the agent serve requests without a token
/// file. Off by default: a missing token refuses every request.
pub const INSECURE_ENV: &str = "FLUXVM_AGENT_ALLOW_INSECURE";

/// Whether the value of [`INSECURE_ENV`] opts in to running unauthenticated.
pub fn insecure_opt_in(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some("1" | "true" | "yes" | "on"))
}

fn tcp_rule(r: &ExecTcpRule) -> TcpRule {
    match r {
        ExecTcpRule::Any => TcpRule::Any,
        ExecTcpRule::Deny => TcpRule::Deny,
        ExecTcpRule::Ports(p) => TcpRule::Ports(p.clone()),
    }
}

/// Convert the wire policy to procbox's. `request_timeout` caps the policy's
/// own wall-clock timeout, so a policy can only shorten a request's timeout.
pub fn to_procbox(p: &ExecPolicy, request_timeout: Duration) -> Policy {
    let timeout = match p.timeout_secs {
        Some(t) => t.min(request_timeout.as_secs()),
        None => request_timeout.as_secs(),
    };
    let defaults = Policy::default();
    Policy {
        read: p.read.iter().map(PathBuf::from).collect(),
        write: p.write.iter().map(PathBuf::from).collect(),
        tcp_connect: tcp_rule(&p.tcp_connect),
        tcp_bind: tcp_rule(&p.tcp_bind),
        scope_ipc: p.scope_ipc,
        seccomp: p.seccomp.map(|m| match m {
            ExecSeccompMode::Errno => SeccompMode::Errno,
            ExecSeccompMode::Kill => SeccompMode::Kill,
        }),
        allow_namespaces: p.allow_namespaces,
        max_memory: p.max_memory,
        max_processes: p.max_processes,
        cpu_seconds: p.cpu_seconds,
        timeout_secs: Some(timeout),
        clean_env: p.clean_env,
        env: p.env.clone(),
        cwd: p.cwd.as_ref().map(PathBuf::from),
        best_effort: p.best_effort,
        max_output_bytes: p.max_output_bytes.unwrap_or(defaults.max_output_bytes),
        run_as: p.run_as.map(|r| RunAs {
            uid: r.uid,
            gid: r.gid,
        }),
        isolation: match p.isolation {
            ExecIsolation::Off => Isolation::Off,
            ExecIsolation::Auto => Isolation::Auto,
            ExecIsolation::Strict => Isolation::Strict,
        },
        allow_unix: p.allow_unix,
        allow_udp: p.allow_udp,
        ..defaults
    }
}

pub fn enforcement_to_wire(e: &Enforcement) -> ExecEnforcement {
    ExecEnforcement {
        landlock_abi: e.landlock_abi,
        filesystem: e.filesystem,
        tcp_connect: e.tcp_connect,
        tcp_bind: e.tcp_bind,
        scope_abstract_unix: e.scope_abstract_unix,
        scope_signal: e.scope_signal,
        seccomp: e.seccomp,
        uid_dropped: e.uid_dropped,
        namespaces: e.namespaces,
        network_isolated: e.network_isolated,
        seccomp_sockets: e.seccomp_sockets,
        not_enforced: e.not_enforced.clone(),
    }
}

/// Run `command` via `/bin/sh -c` confined by `policy`. Fails closed: if the
/// confinement cannot be set up the command is not run at all.
pub fn exec_confined(command: &str, timeout: Duration, policy: &ExecPolicy) -> AgentResponse {
    let pb = to_procbox(policy, timeout);
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    match fluxvm_procbox::run(&pb, &argv, &RunOptions { capture: true }) {
        Ok(r) if r.timed_out => AgentResponse::Error {
            message: format!(
                "command exceeded {}s timeout and was killed",
                pb.timeout_secs.unwrap_or(timeout.as_secs())
            ),
        },
        Ok(r) => AgentResponse::Exec {
            exit_code: r.exit_code.or(r.signal.map(|s| 128 + s)).unwrap_or(-1),
            stdout: r.stdout,
            stderr: r.stderr,
            enforcement: Some(enforcement_to_wire(&r.enforcement)),
        },
        Err(e) => AgentResponse::Error {
            message: format!("policy could not be enforced, command not run: {e:#}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_guest_protocol::ExecRunAs;

    #[test]
    fn default_wire_policy_converts_to_the_procbox_default() {
        let pb = to_procbox(&ExecPolicy::default(), Duration::from_secs(30));
        let d = Policy::default();
        assert_eq!(pb.tcp_connect, d.tcp_connect);
        assert_eq!(pb.tcp_bind, d.tcp_bind);
        assert_eq!(pb.scope_ipc, d.scope_ipc);
        assert_eq!(pb.seccomp, d.seccomp);
        assert_eq!(pb.isolation, d.isolation);
        assert_eq!(pb.max_output_bytes, d.max_output_bytes);
        assert!(!pb.allow_namespaces && !pb.allow_unix && !pb.allow_udp);
    }

    #[test]
    fn fields_convert() {
        let wire = ExecPolicy {
            read: vec!["/usr".into(), "/bin".into()],
            write: vec!["/tmp/work".into()],
            tcp_connect: ExecTcpRule::Ports(vec![443]),
            seccomp: Some(ExecSeccompMode::Kill),
            max_memory: Some(1 << 28),
            cwd: Some("/tmp/work".into()),
            env: vec![("A".into(), "b".into())],
            run_as: Some(ExecRunAs {
                uid: 1000,
                gid: 1000,
            }),
            isolation: ExecIsolation::Strict,
            ..ExecPolicy::default()
        };
        let pb = to_procbox(&wire, Duration::from_secs(30));
        assert_eq!(pb.read, vec![PathBuf::from("/usr"), PathBuf::from("/bin")]);
        assert_eq!(pb.write, vec![PathBuf::from("/tmp/work")]);
        assert_eq!(pb.tcp_connect, TcpRule::Ports(vec![443]));
        assert_eq!(pb.seccomp, Some(SeccompMode::Kill));
        assert_eq!(pb.max_memory, Some(1 << 28));
        assert_eq!(pb.cwd, Some(PathBuf::from("/tmp/work")));
        assert_eq!(pb.env, vec![("A".to_string(), "b".to_string())]);
        assert_eq!(
            pb.run_as,
            Some(RunAs {
                uid: 1000,
                gid: 1000
            })
        );
        assert_eq!(pb.isolation, Isolation::Strict);
    }

    #[test]
    fn disabling_seccomp_is_preserved() {
        let wire = ExecPolicy {
            seccomp: None,
            ..ExecPolicy::default()
        };
        assert_eq!(to_procbox(&wire, Duration::from_secs(5)).seccomp, None);
    }

    #[test]
    fn policy_timeout_can_only_shorten_the_request_timeout() {
        let req = Duration::from_secs(30);
        let mut wire = ExecPolicy::default();
        assert_eq!(to_procbox(&wire, req).timeout_secs, Some(30));
        wire.timeout_secs = Some(5);
        assert_eq!(to_procbox(&wire, req).timeout_secs, Some(5));
        wire.timeout_secs = Some(600);
        assert_eq!(to_procbox(&wire, req).timeout_secs, Some(30));
    }

    #[test]
    fn enforcement_converts_field_for_field() {
        let e = Enforcement {
            landlock_abi: 4,
            filesystem: true,
            tcp_connect: true,
            seccomp: true,
            not_enforced: vec!["scope_ipc".into()],
            ..Enforcement::default()
        };
        let w = enforcement_to_wire(&e);
        assert_eq!(w.landlock_abi, 4);
        assert!(w.filesystem && w.tcp_connect && w.seccomp);
        assert!(!w.tcp_bind && !w.namespaces);
        assert_eq!(w.not_enforced, vec!["scope_ipc".to_string()]);
    }

    #[test]
    fn insecure_opt_in_is_explicit() {
        assert!(!insecure_opt_in(None));
        assert!(!insecure_opt_in(Some("")));
        assert!(!insecure_opt_in(Some("0")));
        assert!(!insecure_opt_in(Some("no")));
        assert!(insecure_opt_in(Some("1")));
        assert!(insecure_opt_in(Some("true")));
    }
}
