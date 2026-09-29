// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! End to end: learn a program, then run it confined by the generated
//! profile. Tests skip (not fail) when ptrace or the needed Landlock ABI is
//! unavailable, or when a helper (python3) is missing.
#![cfg(target_os = "linux")]

use fluxvm_procbox::{landlock, run_with, Policy, Profile, RunOptions, SyscallOverrides, TcpRule};
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
    // This test is about the seccomp `syscall_deny`/`syscall_allow`
    // overrides, not TCP port policy, so leave TCP unrestricted (the
    // deny-by-default policy would otherwise block `connect` at the
    // Landlock layer before the syscall-override behaviour is exercised).
    p.tcp_connect = TcpRule::Any;
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

// ------------------------------------------------------- merging across runs

const SCRIPT_A: &str = "cat /etc/hostname > /dev/null; echo a > \"$1/a-out\"";
/// Reads /etc/os-release, connects to a loopback port, writes a file. Only
/// double quotes, so it can also be passed through `--cmd '...'`.
const SCRIPT_B: &str = "import socket,sys; open(\"/etc/os-release\").read(); \
    socket.create_connection((\"127.0.0.1\", int(sys.argv[2]))).close(); \
    open(sys.argv[1]+\"/b-out\",\"w\").write(\"b\")";

fn learn_merge(out: &Path, prior: &Path, extra: &[&str], cmd: &[&str]) -> Output {
    Command::new(bin())
        .args(["learn", "--merge"])
        .arg(prior)
        .arg("--out")
        .arg(out)
        .args(extra)
        .arg("--")
        .args(cmd)
        .output()
        .expect("spawn learn --merge")
}

fn sidecar_path(profile: &Path) -> PathBuf {
    fluxvm_procbox::learn::Sidecar::path_for(profile)
}

fn sidecar_labels(profile: &Path) -> Vec<String> {
    let sc = fluxvm_procbox::learn::Sidecar::load(&sidecar_path(profile)).expect("sidecar");
    sc.runs.iter().map(|r| r.label.clone()).collect()
}

/// Both scripts must succeed confined by `prof`; an unlearned write and an
/// unlearned port must still fail.
fn assert_runs_both_confined(prof: &Path, d1: &Path, d2: &Path, port: &str, other_port: &str) {
    let p = load(prof);
    assert!(grants_write(&p, d1), "{p:?}");
    assert!(grants_write(&p, d2), "{p:?}");
    assert_eq!(
        p.net_connect,
        Some(fluxvm_procbox::profile::NetRule::Ports(vec![port
            .parse()
            .unwrap()])),
        "{}",
        std::fs::read_to_string(prof).unwrap()
    );
    let _ = std::fs::remove_file(d1.join("a-out"));
    let _ = std::fs::remove_file(d2.join("b-out"));
    let (c, out) = confined(
        prof,
        &["/bin/sh", "-c", SCRIPT_A, "sh", d1.to_str().unwrap()],
    );
    assert_eq!(c, Some(0), "script A under the merged profile: {out}");
    assert!(d1.join("a-out").exists());
    let (c, out) = confined(
        prof,
        &["python3", "-c", SCRIPT_B, d2.to_str().unwrap(), port],
    );
    assert_eq!(c, Some(0), "script B under the merged profile: {out}");
    assert!(d2.join("b-out").exists());

    // A variation nobody learned: write elsewhere, and another port.
    let other = tempfile::tempdir().unwrap();
    let (c, out) = confined(
        prof,
        &[
            "/bin/sh",
            "-c",
            "echo y > \"$1/evil\"",
            "sh",
            other.path().to_str().unwrap(),
        ],
    );
    assert_ne!(c, Some(0), "unlearned write must fail: {out}");
    assert!(!other.path().join("evil").exists());
    let (c, out) = confined(
        prof,
        &["python3", "-c", SCRIPT_B, d2.to_str().unwrap(), other_port],
    );
    assert_ne!(c, Some(0), "unlearned port must fail: {out}");
}

#[test]
fn merge_updates_a_profile_in_place_and_covers_both_runs() {
    need_abi!(6);
    need_ptrace!();
    need_tool!("python3");
    let work = tempfile::tempdir().unwrap();
    let prof = work.path().join("p.toml");
    let (d1, d2) = (work.path().join("out1"), work.path().join("out2"));
    std::fs::create_dir(&d1).unwrap();
    std::fs::create_dir(&d2).unwrap();
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let (port, other_port) = (
        l1.local_addr().unwrap().port().to_string(),
        l2.local_addr().unwrap().port().to_string(),
    );

    let o = Command::new(bin())
        .args(["learn", "--label", "a", "--out"])
        .arg(&prof)
        .args(["--", "/bin/sh", "-c", SCRIPT_A, "sh", d1.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o));
    assert_eq!(sidecar_labels(&prof), ["a"]);

    // No --force needed: --out is the profile being merged into.
    let o = learn_merge(
        &prof,
        &prof,
        &["--label", "b"],
        &["python3", "-c", SCRIPT_B, d2.to_str().unwrap(), &port],
    );
    assert!(o.status.success(), "{}", s(&o));
    assert_eq!(sidecar_labels(&prof), ["a", "b"]);
    let text = std::fs::read_to_string(&prof).unwrap();
    assert!(text.contains("Merged 2 run(s)"), "{text}");
    assert_runs_both_confined(&prof, &d1, &d2, &port, &other_port);

    // Learning the same command again yields the same profile. Its output
    // file must be gone first, otherwise the re-run legitimately observes a
    // write to an existing file instead of a create. (Byte-exact idempotency
    // of the merge itself is covered by the unit tests; a real re-run also
    // differs in pids and syscall counts, so compare the parsed profile.)
    let _ = std::fs::remove_file(d1.join("a-out"));
    let _ = std::fs::remove_file(d2.join("b-out"));
    let before = load(&prof);
    let o = learn_merge(
        &prof,
        &prof,
        &["--label", "b"],
        &["python3", "-c", SCRIPT_B, d2.to_str().unwrap(), &port],
    );
    assert!(o.status.success(), "{}", s(&o));
    assert_eq!(load(&prof), before);
    assert_eq!(sidecar_labels(&prof), ["a", "b"]);

    // --forget drops run "a": its directory is no longer granted.
    let o = learn_merge(
        &prof,
        &prof,
        &["--forget", "a", "--label", "c"],
        &["/bin/true"],
    );
    assert!(o.status.success(), "{}", s(&o));
    assert_eq!(sidecar_labels(&prof), ["b", "c"]);
    assert!(!grants_write(&load(&prof), &d1));
    assert!(grants_write(&load(&prof), &d2));
}

#[test]
fn several_cmd_runs_in_one_invocation_match_merging_them_one_by_one() {
    need_abi!(6);
    need_ptrace!();
    need_tool!("python3");
    let work = tempfile::tempdir().unwrap();
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let (port, other_port) = (
        l1.local_addr().unwrap().port().to_string(),
        l2.local_addr().unwrap().port().to_string(),
    );
    let mk = |name: &str| {
        let d = work.path().join(name);
        std::fs::create_dir(&d).unwrap();
        d
    };
    let (d1, d2) = (mk("m1"), mk("m2"));
    let cmd_a = format!("/bin/sh -c '{SCRIPT_A}' sh {}", d1.display());
    let cmd_b = format!("python3 -c '{SCRIPT_B}' {} {port}", d2.display());
    let multi = work.path().join("multi.toml");
    let o = Command::new(bin())
        .args(["learn", "--out"])
        .arg(&multi)
        .args(["--cmd", &cmd_a, "--cmd", &cmd_b])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o));
    assert_eq!(sidecar_labels(&multi).len(), 2);
    assert_runs_both_confined(&multi, &d1, &d2, &port, &other_port);

    // The same two commands merged one after the other, in fresh directories.
    let (e1, e2) = (mk("s1"), mk("s2"));
    let seq = work.path().join("seq.toml");
    let o = Command::new(bin())
        .args(["learn", "--out"])
        .arg(&seq)
        .args(["--", "/bin/sh", "-c", SCRIPT_A, "sh", e1.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o));
    let o = learn_merge(
        &seq,
        &seq,
        &[],
        &["python3", "-c", SCRIPT_B, e2.to_str().unwrap(), &port],
    );
    assert!(o.status.success(), "{}", s(&o));
    let (m, q) = (load(&multi), load(&seq));
    assert_eq!(m.fs_read, q.fs_read, "same reads either way");
    assert_eq!(m.net_connect, q.net_connect);
    assert_eq!(m.fs_write.len(), q.fs_write.len());
}

#[test]
fn merge_without_an_observation_file_needs_an_explicit_opt_in() {
    need_ptrace!();
    let work = tempfile::tempdir().unwrap();
    let prior = work.path().join("hand.toml");
    let d = work.path().join("w");
    std::fs::create_dir(&d).unwrap();
    std::fs::write(
        &prior,
        format!(
            "fs_read = [\"/usr\"]\nfs_write = [{:?}]\nmax_processes = 32\n",
            d
        ),
    )
    .unwrap();
    let out = work.path().join("merged.toml");
    let o = learn_merge(&out, &prior, &[], &["/bin/true"]);
    assert!(!o.status.success(), "{}", s(&o));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("--merge-profile-only"),
        "{}",
        s(&o)
    );
    assert!(!out.exists());

    let o = learn_merge(&out, &prior, &["--merge-profile-only"], &["/bin/true"]);
    assert!(o.status.success(), "{}", s(&o));
    let p = load(&out);
    assert_eq!(p.max_processes, Some(32), "non-learned keys are kept");
    assert!(grants_write(&p, &d), "{p:?}");
    assert_eq!(sidecar_labels(&out).len(), 2, "prior + the new run");

    // A different existing --out still needs --force.
    let o = learn_merge(&out, &prior, &["--merge-profile-only"], &["/bin/true"]);
    assert!(!o.status.success(), "{}", s(&o));
    assert!(String::from_utf8_lossy(&o.stderr).contains("--force"));
}
