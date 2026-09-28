// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Isolation, uid drop and socket-filter tests. Each test sandboxes one
//! `selftest` op and observes what the kernel really allows.
//!
//! Namespace tests run when the host allows them for the caller (unprivileged
//! user namespaces, or any root caller) and skip otherwise. uid-drop tests
//! need root: run the test binary with `sudo`.
#![cfg(target_os = "linux")]

use fluxvm_procbox::{
    isolate, landlock, run, Isolation, Policy, RunAs, RunOptions, RunResult, SeccompMode, TcpRule,
};
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const EACCES: &str = "errno=13";
const EPERM: &str = "errno=1";
const ENOENT: &str = "errno=2";

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

macro_rules! need_abi {
    ($n:expr) => {
        if landlock::kernel_abi() < $n {
            eprintln!("SKIP: needs Landlock ABI >= {}", $n);
            return;
        }
    };
}

macro_rules! need_ns {
    () => {
        if let Err(why) = isolate::userns_status(None) {
            eprintln!("SKIP: namespaces unavailable here: {why}");
            return;
        }
    };
}

macro_rules! need_root {
    () => {
        if !is_root() {
            eprintln!("SKIP: needs root (run the test binary with sudo)");
            return;
        }
    };
}

/// A world-searchable directory holding a copy of the helper binary, so a
/// sandbox that runs as another uid can still execute it. It is copied once per
/// test process: copying per test races other tests' `fork` (`ETXTBSY`).
struct Fixture {
    dir: PathBuf,
    bin: String,
}

static FIXTURE: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();

extern "C" fn remove_fixture() {
    if let Some(f) = FIXTURE.get() {
        let _ = std::fs::remove_dir_all(&f.dir);
    }
}

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        let dir = tempfile::tempdir_in("/tmp").unwrap().keep();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = dir.join("procbox");
        std::fs::copy(env!("CARGO_BIN_EXE_fluxvm-procbox"), &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { libc::atexit(remove_fixture) };
        Fixture {
            bin: bin.to_string_lossy().into_owned(),
            dir,
        }
    })
}

/// A world-accessible scratch directory (created by the test, who may be
/// root, and used by a sandbox that runs as another uid).
fn open_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    d
}

fn base(f: &Fixture) -> Policy {
    let mut p = Policy::default();
    p.scope_ipc = false;
    for d in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
        if Path::new(d).exists() {
            p.read.push(d.into());
        }
    }
    p.read.push(f.dir.clone());
    p
}

fn sandbox(f: &Fixture, p: &Policy, op: &str, arg: Option<&str>) -> RunResult {
    let mut argv = vec![f.bin.clone(), "selftest".into(), op.into()];
    if let Some(a) = arg {
        argv.push(a.into());
    }
    run(p, &argv, &RunOptions { capture: true }).expect("sandboxed run")
}

fn out(r: &RunResult) -> String {
    r.stdout.trim().to_string()
}

const UID: u32 = 61234;

#[test]
fn private_root_shows_only_granted_paths_and_a_fresh_pid_namespace() {
    need_abi!(3);
    need_ns!();
    let f = fixture();
    let w = open_dir();
    let mut p = base(&f);
    p.write.push(w.path().to_path_buf());
    p.read.push("/proc".into());
    p.isolation = Isolation::Strict;

    let r = sandbox(&f, &p, "read", Some("/etc/hostname"));
    // Not merely denied: absent from the private root.
    assert_eq!(out(&r), ENOENT, "{r:?}");
    assert!(r.enforcement.namespaces, "{:?}", r.enforcement);
    assert_eq!(
        out(&sandbox(&f, &p, "read", Some("/home"))),
        ENOENT,
        "host /home must not exist in the private root"
    );
    assert_eq!(out(&sandbox(&f, &p, "read", Some("/usr/bin"))), "ok");

    let file = w.path().join("made-inside");
    assert_eq!(
        out(&sandbox(&f, &p, "write", Some(file.to_str().unwrap()))),
        "ok"
    );
    assert!(
        file.exists(),
        "a write to the bound workspace reaches the host"
    );

    let ids = out(&sandbox(&f, &p, "ids", None));
    assert!(
        ids.ends_with("pid=1"),
        "command is pid 1 of its namespace: {ids}"
    );
    let mounts: usize = out(&sandbox(&f, &p, "mounts", None))
        .trim_start_matches("mounts=")
        .parse()
        .unwrap();
    assert!(mounts < 30, "private root has few mounts, got {mounts}");
}

#[test]
fn read_only_binds_stay_read_only_inside_the_private_root() {
    need_abi!(3);
    need_ns!();
    let f = fixture();
    let ro = open_dir();
    std::fs::write(ro.path().join("data"), b"x").unwrap();
    std::fs::set_permissions(
        ro.path().join("data"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let mut p = base(&f);
    p.read.push(ro.path().to_path_buf());
    p.isolation = Isolation::Strict;
    let path = ro.path().join("data");
    let path = path.to_str().unwrap();
    assert_eq!(out(&sandbox(&f, &p, "read", Some(path))), "ok");
    let w = out(&sandbox(&f, &p, "write", Some(path)));
    assert!(
        w == EACCES || w == "errno=30",
        "expected EACCES/EROFS, got {w}"
    );
    assert_eq!(std::fs::read(path).unwrap(), b"x");
}

#[test]
fn exit_status_and_signals_pass_through_the_intermediate_process() {
    need_abi!(3);
    need_ns!();
    let f = fixture();
    let mut p = base(&f);
    p.isolation = Isolation::Strict;

    let r = sandbox(&f, &p, "read", Some("/definitely/missing"));
    assert_eq!(r.exit_code, Some(1), "{r:?}");
    let r = sandbox(&f, &p, "read", Some("/usr"));
    assert_eq!(r.exit_code, Some(0), "{r:?}");

    p.seccomp = Some(SeccompMode::Kill);
    let r = sandbox(&f, &p, "ptrace", None);
    assert_eq!(r.signal, Some(libc::SIGSYS), "{r:?}");
}

#[test]
fn timeout_kills_a_namespaced_command_and_its_descendants() {
    need_abi!(3);
    need_ns!();
    let f = fixture();
    let mut p = base(&f);
    p.isolation = Isolation::Strict;
    p.timeout_secs = Some(1);
    let started = std::time::Instant::now();
    let r = sandbox(&f, &p, "sleep", Some("30"));
    assert!(r.timed_out, "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn no_network_policy_gets_an_empty_network_namespace() {
    need_abi!(4);
    need_ns!();
    let f = fixture();
    let mut p = base(&f);
    p.isolation = Isolation::Strict;
    p.tcp_connect = TcpRule::Deny;
    p.tcp_bind = TcpRule::Deny;

    let r = sandbox(&f, &p, "ifaces", None);
    assert_eq!(out(&r), "ifaces=lo", "{r:?}");
    assert!(r.enforcement.network_isolated);

    // A datagram to a host listener does not arrive: different namespace.
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    host.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let port = host.local_addr().unwrap().port().to_string();
    let r = sandbox(&f, &p, "udp-send", Some(&port));
    let mut buf = [0u8; 8];
    assert!(
        host.recv(&mut buf).is_err(),
        "datagram escaped the netns: {r:?}"
    );
}

#[test]
fn capabilities_are_dropped_in_the_private_root() {
    need_abi!(3);
    need_ns!();
    let f = fixture();
    let mut p = base(&f);
    p.isolation = Isolation::Strict;
    p.read.push("/proc".into());
    let r = sandbox(&f, &p, "capeff", None);
    assert_eq!(out(&r), "capeff=0000000000000000", "{r:?}");
}

#[test]
fn a_granted_proc_is_a_fresh_mount_of_the_new_pid_namespace() {
    need_abi!(3);
    need_ns!();
    let f = fixture();
    let mut p = base(&f);
    p.isolation = Isolation::Strict;
    p.read.push("/proc".into());
    assert_eq!(
        out(&sandbox(&f, &p, "read", Some("/proc/self/status"))),
        "ok"
    );
    // Only this namespace's processes are listed, so pid 1 is the command.
    assert_eq!(out(&sandbox(&f, &p, "read", Some("/proc/1/status"))), "ok");
}

#[test]
fn seccomp_denies_udp_raw_netlink_and_unix_sockets_on_a_shared_network() {
    need_abi!(4);
    let f = fixture();
    let mut p = base(&f);
    p.tcp_connect = TcpRule::Ports(vec![9]);
    p.tcp_bind = TcpRule::Deny;

    for kind in ["udp", "netlink", "unix", "unix-dgram"] {
        let r = sandbox(&f, &p, "socket", Some(kind));
        assert_eq!(out(&r), EPERM, "{kind}: {r:?}");
    }
    assert_eq!(out(&sandbox(&f, &p, "socket", Some("tcp"))), "ok");
    assert_eq!(
        out(&sandbox(&f, &p, "socket", Some("unixpair"))),
        "ok",
        "socketpair is a different syscall and stays allowed"
    );
    let r = sandbox(&f, &p, "socket", Some("tcp"));
    assert!(r.enforcement.seccomp_sockets, "{:?}", r.enforcement);

    p.allow_udp = true;
    assert_eq!(out(&sandbox(&f, &p, "socket", Some("udp"))), "ok");
    assert_eq!(out(&sandbox(&f, &p, "socket", Some("netlink"))), "ok");
    assert_eq!(out(&sandbox(&f, &p, "socket", Some("unix"))), EPERM);
    p.allow_unix = true;
    assert_eq!(out(&sandbox(&f, &p, "socket", Some("unix"))), "ok");
}

#[test]
fn socket_filters_are_off_when_tcp_is_unrestricted() {
    let f = fixture();
    let p = base(&f);
    let r = sandbox(&f, &p, "socket", Some("udp"));
    assert_eq!(out(&r), "ok", "{r:?}");
    assert!(!r.enforcement.seccomp_sockets);
}

#[test]
fn pathname_unix_sockets_on_the_host_are_unreachable() {
    need_abi!(4);
    let f = fixture();
    let dir = open_dir();
    let sock = dir.path().join("s.sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let mut p = base(&f);
    p.read.push(dir.path().to_path_buf());
    p.tcp_connect = TcpRule::Deny;
    p.tcp_bind = TcpRule::Deny;
    let r = sandbox(&f, &p, "unix-path", Some(sock.to_str().unwrap()));
    assert_eq!(
        out(&r),
        EPERM,
        "creating the socket is what seccomp stops: {r:?}"
    );
}

#[test]
fn udp_reaches_a_host_listener_only_when_explicitly_allowed_and_shared() {
    need_abi!(4);
    let f = fixture();
    let host = UdpSocket::bind("127.0.0.1:0").unwrap();
    host.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let port = host.local_addr().unwrap().port().to_string();
    let mut p = base(&f);
    p.tcp_connect = TcpRule::Ports(vec![9]);
    p.tcp_bind = TcpRule::Deny;

    let r = sandbox(&f, &p, "udp-send", Some(&port));
    assert_eq!(out(&r), EPERM, "{r:?}");
    p.allow_udp = true;
    let r = sandbox(&f, &p, "udp-send", Some(&port));
    assert_eq!(out(&r), "ok", "{r:?}");
    let mut buf = [0u8; 8];
    assert_eq!(
        host.recv(&mut buf).unwrap(),
        4,
        "control: the listener is observable"
    );
}

#[test]
fn run_as_without_root_is_refused_up_front() {
    if is_root() {
        eprintln!("SKIP: caller is root");
        return;
    }
    let f = fixture();
    let mut p = base(&f);
    p.run_as = Some(RunAs { uid: UID, gid: UID });
    let argv = vec![f.bin.clone(), "selftest".into(), "ids".into()];
    let e = run(&p, &argv, &RunOptions { capture: true }).unwrap_err();
    assert!(format!("{e:#}").contains("root"), "{e:#}");
}

#[test]
fn strict_isolation_fails_closed_when_namespaces_are_unavailable() {
    if isolate::userns_status(None).is_ok() {
        eprintln!("SKIP: namespaces work here");
        return;
    }
    let f = fixture();
    let mut p = base(&f);
    p.isolation = Isolation::Strict;
    let argv = vec![f.bin.clone(), "selftest".into(), "ids".into()];
    let e = run(&p, &argv, &RunOptions { capture: true }).unwrap_err();
    assert!(
        format!("{e:#}").contains("namespaces are unavailable"),
        "{e:#}"
    );
    p.isolation = Isolation::Auto;
    let r = run(&p, &argv, &RunOptions { capture: true }).unwrap();
    assert!(!r.enforcement.namespaces);
    assert!(
        r.enforcement
            .not_enforced
            .iter()
            .any(|g| g.contains("namespace isolation")),
        "{:?}",
        r.enforcement
    );
}

// ---- root only ------------------------------------------------------------

#[test]
fn root_run_as_drops_to_the_sandbox_uid_and_loses_every_capability() {
    need_abi!(3);
    need_root!();
    let f = fixture();
    let mut p = base(&f);
    p.run_as = Some(RunAs { uid: UID, gid: UID });
    p.read.push("/proc".into());

    for iso in [Isolation::Off, Isolation::Strict] {
        p.isolation = iso;
        let r = sandbox(&f, &p, "ids", None);
        assert!(
            out(&r).starts_with(&format!("uid={UID} gid={UID}")),
            "{iso:?}: {r:?}"
        );
        assert!(r.enforcement.uid_dropped);
        assert_eq!(
            out(&sandbox(&f, &p, "capeff", None)),
            "capeff=0000000000000000",
            "{iso:?}"
        );
    }
}

#[test]
fn root_isolation_needs_no_user_namespace_and_hides_the_host() {
    need_abi!(3);
    need_root!();
    let f = fixture();
    let w = open_dir();
    let mut p = base(&f);
    p.run_as = Some(RunAs { uid: UID, gid: UID });
    p.isolation = Isolation::Strict;
    p.write.push(w.path().to_path_buf());

    let r = sandbox(&f, &p, "read", Some("/etc/shadow"));
    assert_eq!(out(&r), ENOENT, "{r:?}");
    assert!(r.enforcement.namespaces);
    let file = w.path().join("owned-by-sandbox");
    assert_eq!(
        out(&sandbox(&f, &p, "write", Some(file.to_str().unwrap()))),
        "ok"
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&file).unwrap().uid(), UID);
    let ids = out(&sandbox(&f, &p, "ids", None));
    assert!(ids.ends_with("pid=1"), "{ids}");
}

#[test]
fn root_owned_files_are_unreadable_to_the_sandbox_uid() {
    need_abi!(3);
    need_root!();
    let f = fixture();
    let d = open_dir();
    let secret = d.path().join("root-only");
    std::fs::write(&secret, b"s").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut p = base(&f);
    p.read.push(d.path().to_path_buf());
    p.run_as = Some(RunAs { uid: UID, gid: UID });
    for iso in [Isolation::Off, Isolation::Strict] {
        p.isolation = iso;
        assert_eq!(
            out(&sandbox(&f, &p, "read", Some(secret.to_str().unwrap()))),
            EACCES,
            "{iso:?}"
        );
    }
}

#[test]
fn nproc_limit_is_counted_per_sandbox_uid() {
    need_abi!(3);
    need_root!();
    let f = fixture();
    let mut p = base(&f);
    p.max_processes = Some(20);
    p.run_as = Some(RunAs { uid: UID, gid: UID });
    let r = sandbox(&f, &p, "spawn-count", Some("100"));
    let n: usize = out(&r).trim_start_matches("spawned=").parse().unwrap();
    assert!(n < 20, "RLIMIT_NPROC must cap forks, got {n}: {r:?}");
    // A different uid starts from zero, not from this sandbox's count.
    p.run_as = Some(RunAs {
        uid: UID + 1,
        gid: UID + 1,
    });
    let r = sandbox(&f, &p, "spawn-count", Some("10"));
    assert_eq!(out(&r), "spawned=10", "{r:?}");
}
