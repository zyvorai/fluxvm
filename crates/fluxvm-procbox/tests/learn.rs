// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! End to end: learn a program, then run it confined by the generated
//! profile. Tests skip (not fail) when ptrace or the needed Landlock ABI is
//! unavailable, or when a helper (python3) is missing.
#![cfg(target_os = "linux")]

use fluxvm_procbox::{landlock, run_with, Policy, Profile, RunOptions, SyscallOverrides};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

macro_rules! need_ptrace {
    () => {
        if !ptrace_works() {
            eprintln!("SKIP: ptrace is not permitted here");
            return;
        }
    };
}

macro_rules! need_tool {
    ($t:expr) => {
        if Command::new($t).arg("--version").output().is_err() {
            eprintln!("SKIP: {} is not installed", $t);
            return;
        }
    };
}

fn ptrace_works() -> bool {
    match Command::new(bin())
        .args(["learn", "--", "/bin/true"])
        .output()
    {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

fn s(o: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Learn `cmd`, writing the profile to `out`; returns the process output.
fn learn(out: &Path, cmd: &[&str]) -> Output {
    Command::new(bin())
        .args(["learn", "--force", "--out"])
        .arg(out)
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn learn")
}

/// Run `cmd` confined by the profile; returns (exit_code, stdout+stderr).
fn confined(profile: &Path, cmd: &[&str]) -> (Option<i32>, String) {
    let o = Command::new(bin())
        .args(["run", "--json", "-p"])
        .arg(profile)
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn run");
    assert!(o.status.success(), "run failed: {}", s(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("json result");
    (
        v["exit_code"].as_i64().map(|c| c as i32),
        format!("{}{}", v["stdout"], v["stderr"]),
    )
}

fn load(profile: &Path) -> Profile {
    Profile::from_toml_str(&std::fs::read_to_string(profile).unwrap()).unwrap()
}

fn paths(v: &[PathBuf]) -> Vec<String> {
    v.iter().map(|p| p.display().to_string()).collect()
}

/// The profile grants write to `dir` (the canonical path of a temp dir).
fn grants_write(p: &Profile, dir: &Path) -> bool {
    let d = dir.canonicalize().unwrap();
    p.fs_write.iter().any(|w| d.starts_with(w))
}

#[test]
fn learned_profile_lets_the_same_run_succeed_and_blocks_variations() {
    need_abi!(6);
    need_ptrace!();
    let work = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let prof = work.path().join("p.toml");
    let dir = work.path().join("out");
    std::fs::create_dir(&dir).unwrap();
    let script = "cat /etc/hostname > /dev/null; echo x > \"$1/result.txt\"";
    let d = dir.to_str().unwrap();

    let o = learn(&prof, &["/bin/sh", "-c", script, "sh", d]);
    assert!(o.status.success(), "{}", s(&o));
    let p = load(&prof);
    assert!(grants_write(&p, &dir), "{p:?}");
    assert!(
        paths(&p.fs_read)
            .iter()
            .any(|r| r == "/usr" || r == "/etc/hostname"),
        "{:?}",
        p.fs_read
    );
    assert_eq!(
        p.net_connect,
        Some(fluxvm_procbox::profile::NetRule::Keyword("deny".into()))
    );
    let text = std::fs::read_to_string(&prof).unwrap();
    assert!(text.contains("Needs human review"), "{text}");

    // The file was created during learning; remove it so the confined run
    // must create it again (proving the directory grant, not a file rule).
    std::fs::remove_file(dir.join("result.txt")).unwrap();
    let (code, out) = confined(&prof, &["/bin/sh", "-c", script, "sh", d]);
    assert_eq!(code, Some(0), "{out}");
    assert!(dir.join("result.txt").exists());

    // Variation 1: write somewhere that was never learned.
    let other_dir = other.path().to_str().unwrap().to_string();
    let (code, out) = confined(
        &prof,
        &["/bin/sh", "-c", "echo y > \"$1/evil\"", "sh", &other_dir],
    );
    assert_ne!(code, Some(0), "unlearned write must fail: {out}");
    assert!(!other.path().join("evil").exists());

    // Variation 2: read a file that was never learned.
    let (code, out) = confined(&prof, &["/bin/sh", "-c", "cat /etc/passwd"]);
    assert_ne!(code, Some(0), "unlearned read must fail: {out}");
}

#[test]
fn python_loopback_connect_is_learned_as_a_port_rule() {
    need_abi!(6);
    need_ptrace!();
    need_tool!("python3");
    let work = tempfile::tempdir().unwrap();
    let prof = work.path().join("p.toml");
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let (p1, p2) = (
        l1.local_addr().unwrap().port().to_string(),
        l2.local_addr().unwrap().port().to_string(),
    );
    let code =
        "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1]))).close()";

    let o = learn(&prof, &["python3", "-c", code, &p1]);
    assert!(o.status.success(), "{}", s(&o));
    let p = load(&prof);
    assert_eq!(
        p.net_connect,
        Some(fluxvm_procbox::profile::NetRule::Ports(vec![p1
            .parse()
            .unwrap()])),
        "{}",
        std::fs::read_to_string(&prof).unwrap()
    );
    let text = std::fs::read_to_string(&prof).unwrap();
    assert!(text.contains("not addresses"), "{text}");

    let (c, out) = confined(&prof, &["python3", "-c", code, &p1]);
    assert_eq!(c, Some(0), "learned port must work: {out}");
    let (c, out) = confined(&prof, &["python3", "-c", code, &p2]);
    assert_ne!(c, Some(0), "another port must be blocked: {out}");
}

#[test]
fn child_processes_and_threads_are_traced() {
    need_abi!(6);
    need_ptrace!();
    need_tool!("python3");
    let work = tempfile::tempdir().unwrap();
    let prof = work.path().join("p.toml");
    let d_sub = work.path().join("from_subshell");
    let d_thr = work.path().join("from_thread");
    std::fs::create_dir(&d_sub).unwrap();
    std::fs::create_dir(&d_thr).unwrap();
    let script = "( echo a > \"$1/f\" ) & wait; \
                  python3 -c \"import threading,sys; \
                  t=threading.Thread(target=lambda: open(sys.argv[1]+'/g','w').write('x')); \
                  t.start(); t.join()\" \"$2\"";
    let o = learn(
        &prof,
        &[
            "/bin/sh",
            "-c",
            script,
            "sh",
            d_sub.to_str().unwrap(),
            d_thr.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", s(&o));
    let p = load(&prof);
    assert!(grants_write(&p, &d_sub), "subshell child not traced: {p:?}");
    assert!(grants_write(&p, &d_thr), "thread not traced: {p:?}");
}

#[test]
fn learn_refuses_to_overwrite_and_reports_a_failing_program() {
    need_ptrace!();
    let work = tempfile::tempdir().unwrap();
    let prof = work.path().join("p.toml");
    let o = Command::new(bin())
        .args(["learn", "--out"])
        .arg(&prof)
        .args(["--", "/bin/sh", "-c", "exit 3"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(3), "{}", s(&o));
    let text = std::fs::read_to_string(&prof).unwrap();
    assert!(text.contains("WARNING"), "{text}");

    let again = Command::new(bin())
        .args(["learn", "--out"])
        .arg(&prof)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(2), "{}", s(&again));
    assert!(String::from_utf8_lossy(&again.stderr).contains("--force"));
}

#[test]
fn timeout_kills_a_runaway_learn() {
    need_ptrace!();
    let work = tempfile::tempdir().unwrap();
    let prof = work.path().join("p.toml");
    let start = std::time::Instant::now();
    let o = Command::new(bin())
        .args(["learn", "-t", "1", "--out"])
        .arg(&prof)
        .args(["--", "/bin/sleep", "30"])
        .output()
        .unwrap();
    assert!(start.elapsed().as_secs() < 10, "{}", s(&o));
    assert_eq!(o.status.code(), Some(3), "{}", s(&o));
    assert!(std::fs::read_to_string(&prof)
        .unwrap()
        .contains("time limit"));
}

#[test]
fn profile_validate_accepts_good_and_rejects_bad_files() {
    let d = tempfile::tempdir().unwrap();
    let good = d.path().join("good.toml");
    std::fs::write(&good, "fs_read = [\"/usr\"]\nnet_connect = [443]\n").unwrap();
    let o = Command::new(bin())
        .args(["profile", "validate"])
        .arg(&good)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("ok:"));

    for (name, body, needle) in [
        ("typo.toml", "fs_reed = [\"/usr\"]\n", "fs_reed"),
        ("rel.toml", "fs_read = [\"relative/dir\"]\n", "absolute"),
        ("port.toml", "net_connect = [0]\n", "port 0"),
    ] {
        let f = d.path().join(name);
        std::fs::write(&f, body).unwrap();
        let o = Command::new(bin())
            .args(["profile", "validate"])
            .arg(&f)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{name}: {}", s(&o));
        assert!(
            String::from_utf8_lossy(&o.stderr).contains(needle),
            "{name}: {}",
            s(&o)
        );
    }
}

#[test]
fn named_profiles_resolve_through_xdg_config_home() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("fluxvm-procbox").join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("mine.toml"), "fs_read = [\"/usr\"]\n").unwrap();
    let o = Command::new(bin())
        .env("XDG_CONFIG_HOME", d.path())
        .args(["profile", "validate", "mine"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o));
    let missing = Command::new(bin())
        .env("XDG_CONFIG_HOME", d.path())
        .args(["profile", "validate", "nope"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn cli_flags_override_profile_values() {
    need_abi!(6);
    let d = tempfile::tempdir().unwrap();
    let prof = d.path().join("p.toml");
    std::fs::write(
        &prof,
        "fs_read = [\"/usr\", \"/lib\", \"/lib64\", \"/bin\", \"/etc\"]\ntimeout_secs = 1\n",
    )
    .unwrap();
    let run = |extra: &[&str]| -> serde_json::Value {
        let o = Command::new(bin())
            .args(["run", "--json", "-p"])
            .arg(&prof)
            .args(extra)
            .args(["--", "/bin/sleep", "2"])
            .output()
            .unwrap();
        serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("{}", s(&o)))
    };
    assert_eq!(run(&[])["timed_out"], true, "profile timeout applies");
    let v = run(&["-t", "10"]);
    assert_eq!(v["timed_out"], false, "flag replaces profile scalar: {v}");
    assert_eq!(v["exit_code"], 0);
}

#[test]
fn profile_syscall_overrides_change_the_denylist() {
    need_abi!(3);
    let mut p = Policy::default();
    p.scope_ipc = false;
    for dir in ["/usr", "/lib", "/lib64", "/bin", "/etc"] {
        if Path::new(dir).exists() {
            p.read.push(dir.into());
        }
    }
    p.read
        .push(Path::new(&bin()).parent().unwrap().to_path_buf());
    let selftest = |op: &str, ov: &SyscallOverrides, arg: Option<&str>| {
        let mut argv = vec![bin(), "selftest".into(), op.into()];
        argv.extend(arg.map(str::to_string));
        run_with(&p, ov, &argv, &RunOptions { capture: true })
            .expect("run")
            .stdout
            .trim()
            .to_string()
    };
    let none = SyscallOverrides::default();
    assert_eq!(selftest("ptrace", &none, None), "errno=1");
    let allow = SyscallOverrides {
        allow: vec!["ptrace".into()],
        ..Default::default()
    };
    assert_ne!(selftest("ptrace", &allow, None), "errno=1");

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    assert_eq!(selftest("connect", &none, Some(&port)), "ok");
    let deny = SyscallOverrides {
        deny: vec!["connect".into()],
        ..Default::default()
    };
    assert_eq!(selftest("connect", &deny, Some(&port)), "errno=1");
}
