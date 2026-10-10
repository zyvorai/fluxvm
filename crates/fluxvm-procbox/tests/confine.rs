// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Real confinement tests: a child is sandboxed and asked to do one thing.
//! They skip (not fail) when the host kernel lacks the needed Landlock ABI.
#![cfg(target_os = "linux")]

use fluxvm_procbox::{landlock, run, Policy, RunOptions, RunResult, SeccompMode, TcpRule};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

fn bin() -> String {
    env!("CARGO_BIN_EXE_fluxvm-procbox").to_string()
}

macro_rules! need_abi {
    ($n:expr) => {
        if landlock::kernel_abi() < $n {
            eprintln!(
                "SKIP: needs Landlock ABI >= {}, host has {}",
                $n,
                landlock::kernel_abi()
            );
            return;
        }
    };
}

/// Read access to what a dynamically linked helper needs, no scoping.
fn base() -> Policy {
    let mut p = Policy {
        scope_ipc: false,
        ..Default::default()
    };
    for d in ["/usr", "/lib", "/lib64", "/bin", "/etc"] {
        if Path::new(d).exists() {
            p.read.push(d.into());
        }
    }
    p.read
        .push(Path::new(&bin()).parent().unwrap().to_path_buf());
    p
}

fn sandbox(p: &Policy, op: &str, arg: Option<&str>) -> RunResult {
    let mut argv = vec![bin(), "selftest".into(), op.into()];
    if let Some(a) = arg {
        argv.push(a.into());
    }
    run(p, &argv, &RunOptions { capture: true }).expect("sandboxed run")
}

fn out(r: &RunResult) -> String {
    r.stdout.trim().to_string()
}

fn unconfined(op: &str, arg: Option<&str>) -> String {
    let mut c = Command::new(bin());
    c.args(["selftest", op]);
    if let Some(a) = arg {
        c.arg(a);
    }
    String::from_utf8_lossy(&c.output().unwrap().stdout)
        .trim()
        .to_string()
}

const EACCES: &str = "errno=13";
const EPERM: &str = "errno=1";

#[test]
fn write_inside_allowed_dir_works_and_outside_is_eacces() {
    need_abi!(3);
    let allowed = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut p = base();
    p.write.push(allowed.path().to_path_buf());

    let inside = allowed.path().join("f");
    let r = sandbox(&p, "write", Some(inside.to_str().unwrap()));
    assert_eq!(out(&r), "ok", "{r:?}");
    assert!(inside.exists());

    let outside = other.path().join("f");
    let r = sandbox(&p, "write", Some(outside.to_str().unwrap()));
    assert_eq!(out(&r), EACCES, "{r:?}");
    assert!(!outside.exists());
    assert!(r.enforcement.filesystem);
}

#[test]
fn read_only_path_cannot_be_written() {
    need_abi!(3);
    let ro = tempfile::tempdir().unwrap();
    std::fs::write(ro.path().join("data"), b"hello").unwrap();
    let mut p = base();
    p.read.push(ro.path().to_path_buf());

    let f = ro.path().join("data");
    assert_eq!(out(&sandbox(&p, "read", Some(f.to_str().unwrap()))), "ok");
    assert_eq!(
        out(&sandbox(&p, "write", Some(f.to_str().unwrap()))),
        EACCES
    );
}

#[test]
fn unlisted_directory_is_unreadable() {
    need_abi!(3);
    let listed = tempfile::tempdir().unwrap();
    let hidden = tempfile::tempdir().unwrap();
    std::fs::write(hidden.path().join("secret"), b"x").unwrap();
    let mut p = base();
    p.read.push(listed.path().to_path_buf());

    assert_eq!(
        out(&sandbox(&p, "read", Some(listed.path().to_str().unwrap()))),
        "ok"
    );
    assert_eq!(
        out(&sandbox(&p, "read", Some(hidden.path().to_str().unwrap()))),
        EACCES
    );
    let secret = hidden.path().join("secret");
    assert_eq!(
        out(&sandbox(&p, "read", Some(secret.to_str().unwrap()))),
        EACCES
    );
}

#[test]
fn a_command_outside_the_allowed_paths_does_not_start() {
    need_abi!(3);
    let p = Policy {
        scope_ipc: false,
        ..Default::default()
    };
    let err = run(
        &p,
        &["/bin/true".to_string()],
        &RunOptions { capture: true },
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("failed to start"), "{err}");
}

#[test]
fn tcp_connect_is_limited_to_allowed_ports() {
    need_abi!(4);
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    let ap = allowed.local_addr().unwrap().port().to_string();
    let dp = denied.local_addr().unwrap().port().to_string();
    let mut p = base();
    p.tcp_connect = TcpRule::Ports(vec![allowed.local_addr().unwrap().port()]);

    let r = sandbox(&p, "connect", Some(&ap));
    assert_eq!(out(&r), "ok", "{r:?}");
    assert!(r.enforcement.tcp_connect);
    assert_eq!(out(&sandbox(&p, "connect", Some(&dp))), EACCES);
    // Sanity: without the rule the same connect works.
    assert_eq!(unconfined("connect", Some(&dp)), "ok");
}

#[test]
fn tcp_deny_blocks_connect_and_bind() {
    need_abi!(4);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let free = {
        let t = TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap().port().to_string()
    };
    let mut p = base();
    p.tcp_connect = TcpRule::Deny;
    p.tcp_bind = TcpRule::Deny;
    assert_eq!(out(&sandbox(&p, "connect", Some(&port))), EACCES);
    assert_eq!(out(&sandbox(&p, "bind", Some(&free))), EACCES);
}

#[test]
fn dangerous_syscalls_return_eperm_inside_and_work_outside() {
    need_abi!(3);
    let p = base();
    for op in ["ptrace", "keyctl", "pvm"] {
        let r = sandbox(&p, op, None);
        assert_eq!(out(&r), EPERM, "{op}: {r:?}");
        assert!(r.enforcement.seccomp);
        assert_ne!(unconfined(op, None), EPERM, "{op} must work unconfined");
    }
    // Opting out of seccomp lets them through.
    let mut open = base();
    open.seccomp = None;
    assert_ne!(out(&sandbox(&open, "ptrace", None)), EPERM);
    assert!(sandbox(&open, "ptrace", None)
        .enforcement
        .not_enforced
        .iter()
        .any(|g| g.contains("seccomp")));
}

#[test]
fn kill_mode_terminates_the_process_with_sigsys() {
    need_abi!(3);
    let mut p = base();
    p.seccomp = Some(SeccompMode::Kill);
    let r = sandbox(&p, "ptrace", None);
    assert_eq!(r.signal, Some(libc::SIGSYS), "{r:?}");
}

#[test]
fn memory_limit_is_enforced() {
    need_abi!(3);
    let mut p = base();
    p.max_memory = Some(128 << 20);
    assert_eq!(out(&sandbox(&p, "alloc", Some("512"))), "errno=12");
    assert_eq!(out(&sandbox(&p, "alloc", Some("8"))), "ok");
}

#[test]
fn timeout_kills_the_child_and_reports_it() {
    need_abi!(3);
    let mut p = base();
    p.timeout_secs = Some(1);
    let r = sandbox(&p, "sleep", Some("30"));
    assert!(r.timed_out, "{r:?}");
    assert_eq!(r.signal, Some(libc::SIGKILL));
    assert!(r.wall_ms < 10_000, "took {} ms", r.wall_ms);
    assert!(!r.success());
}

#[test]
fn timeout_kills_the_whole_process_group() {
    need_abi!(3);
    let mut p = base();
    p.timeout_secs = Some(1);
    // dash opens /dev/null for a background job's stdin.
    p.read.push("/dev/null".into());
    let argv: Vec<String> = ["/bin/sh", "-c", "sleep 30 & wait"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let started = std::time::Instant::now();
    let r = run(&p, &argv, &RunOptions { capture: true }).unwrap();
    assert!(r.timed_out, "{r:?}");
    // Capture would block until the background sleep exits if it survived.
    assert!(started.elapsed().as_secs() < 10);
}

#[test]
fn exit_status_and_output_are_reported() {
    need_abi!(3);
    let p = base();
    let argv: Vec<String> = ["/bin/sh", "-c", "echo hi; echo err >&2; exit 3"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let r = run(&p, &argv, &RunOptions { capture: true }).unwrap();
    assert_eq!(r.exit_code, Some(3));
    assert_eq!(r.stdout, "hi\n");
    assert_eq!(r.stderr, "err\n");
    assert!(!r.timed_out && !r.success());
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["exit_code"], 3);
    assert_eq!(j["enforcement"]["filesystem"], true);
}

#[test]
fn output_is_capped() {
    need_abi!(3);
    let mut p = base();
    p.max_output_bytes = 10;
    let argv: Vec<String> = ["/bin/sh", "-c", "yes | head -c 1000"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let r = run(&p, &argv, &RunOptions { capture: true }).unwrap();
    assert_eq!(r.stdout.len(), 10);
    assert!(r.output_truncated);
}

#[test]
fn strict_mode_fails_closed_when_the_kernel_cannot_enforce_the_policy() {
    need_abi!(3);
    let mut p = base();
    p.max_abi = Some(3); // pretend the kernel predates TCP rules
    p.tcp_connect = TcpRule::Deny;
    let err = run(
        &p,
        &[bin(), "selftest".into(), "ok".into()],
        &RunOptions { capture: true },
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("strict mode"), "{err}");
    assert!(err.contains("TCP connect"), "{err}");
}

#[test]
fn best_effort_runs_and_reports_the_gap() {
    need_abi!(4);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let mut p = base();
    p.max_abi = Some(3);
    p.tcp_connect = TcpRule::Deny;
    p.best_effort = true;
    let r = sandbox(&p, "connect", Some(&port));
    // The rule could not be enforced, so the connect is not blocked...
    assert_eq!(out(&r), "ok", "{r:?}");
    // ...and the result says so.
    assert!(!r.enforcement.tcp_connect);
    assert!(
        r.enforcement
            .not_enforced
            .iter()
            .any(|g| g.contains("TCP connect")),
        "{:?}",
        r.enforcement
    );
}

#[test]
fn missing_rule_path_is_an_error_in_strict_and_a_note_in_best_effort() {
    need_abi!(3);
    let mut p = base();
    p.read.push("/definitely/not/here".into());
    let err = run(
        &p,
        &[bin(), "selftest".into(), "sleep".into(), "0".into()],
        &RunOptions { capture: true },
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("/definitely/not/here"),
        "{err:#}"
    );
    p.best_effort = true;
    let r = sandbox(&p, "sleep", Some("0"));
    assert!(r
        .enforcement
        .not_enforced
        .iter()
        .any(|g| g.contains("/definitely/not/here")));
}

#[test]
fn clean_env_drops_inherited_variables_but_keeps_explicit_ones() {
    need_abi!(3);
    let mut p = base();
    p.clean_env = true;
    p.env = vec![("PROCBOX_EXPLICIT".into(), "yes".into())];
    assert_eq!(out(&sandbox(&p, "env", Some("HOME"))), "value=/tmp");
    // `env` above ran with only PATH, HOME and the explicit variable.
    assert_eq!(
        out(&sandbox(&p, "env", Some("PROCBOX_EXPLICIT"))),
        "value=yes"
    );
    let inherit = base();
    let home = std::env::var("HOME").ok();
    if let Some(h) = home {
        assert_eq!(
            out(&sandbox(&inherit, "env", Some("HOME"))),
            format!("value={h}")
        );
    }
}

#[test]
fn ipc_scoping_blocks_signals_and_abstract_sockets_outside_the_sandbox() {
    need_abi!(6);
    let mut p = base();
    p.scope_ipc = true;

    let r = sandbox(&p, "signal-parent", None);
    assert_eq!(out(&r), EPERM, "{r:?}");
    assert!(r.enforcement.scope_signal && r.enforcement.scope_abstract_unix);
    assert_eq!(unconfined("signal-parent", None), "ok");

    // An abstract unix socket listening outside the sandbox.
    let name = format!("procbox-test-{}", std::process::id());
    let fd = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (i, b) in name.as_bytes().iter().enumerate() {
            addr.sun_path[i + 1] = *b as libc::c_char;
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
        assert_eq!(
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len),
            0
        );
        assert_eq!(libc::listen(fd, 4), 0);
        fd
    };
    assert_eq!(unconfined("unix-abstract", Some(&name)), "ok");
    assert_eq!(out(&sandbox(&p, "unix-abstract", Some(&name))), EPERM);
    unsafe { libc::close(fd) };

    // Without scoping the same signal is delivered.
    let unscoped = base();
    assert_eq!(out(&sandbox(&unscoped, "signal-parent", None)), "ok");
}
