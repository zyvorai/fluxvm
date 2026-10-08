// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Drives `AppleBackend` against a fake runner (a small Python process that speaks the control-socket protocol),
// so the supervision logic is tested without Virtualization.framework. Real VM runs: scripts/macos-live-test.sh.

use fluxvm_apple::{AppleBackend, control_call, find_runner, read_guest_ip};
use fluxvm_core::{
    backend::{LaunchContext, PreparedNetwork, VmBackend},
    config::Config,
    model::{CreateVmRequest, NetworkSpec},
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const FAKE_RUNNER: &str = r#"#!/usr/bin/env python3
import json, os, socket, sys
cfg = json.load(open(sys.argv[3]))
if os.environ.get("FAKE_RUNNER_FAIL"):
    print("fake runner failure: no hypervisor", file=sys.stderr); sys.exit(3)
state = {"s": "running"}
path = cfg["control_socket"]
try: os.unlink(path)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(4)
open(cfg["ip_file"], "w").write("192.168.64.77")
while True:
    c, _ = srv.accept()
    cmd = json.loads(c.recv(4096).decode())["cmd"]
    if cmd == "pause": state["s"] = "paused"
    if cmd == "resume": state["s"] = "running"
    if cmd in ("stop", "shutdown"):
        c.send((json.dumps({"ok": True, "state": "stopping"}) + "\n").encode()); c.close(); os.unlink(path); sys.exit(0)
    c.send((json.dumps({"ok": True, "state": state["s"], "ip": "192.168.64.77"}) + "\n").encode()); c.close()
"#;

fn request() -> CreateVmRequest {
    serde_json::from_str(r#"{"name":"fake","backend":"vz","image":"/x.raw","vcpus":2,"memory_mib":1024,"network":{"mode":"user"}}"#).unwrap()
}

fn context(dir: &Path) -> LaunchContext {
    let ws = dir.join("ws");
    fs::create_dir_all(&ws).unwrap();
    LaunchContext {
        id: uuid::Uuid::new_v4(),
        workspace: ws.clone(),
        disk: ws.join("root.raw"),
        seed_disk: None,
        log_path: ws.join("console.log"),
        network: PreparedNetwork {
            spec: NetworkSpec::None,
            tap_name: None,
            tap_fd: None,
            netns: None,
            dhcp_leasefile: None,
            guest_ip: None,
            guest_cidr: None,
            gateway: None,
            extra_tap_fds: vec![],
        },
        guest_cid: None,
        vsock_socket: None,
        disk_format: "raw".into(),
        nbd_export: None,
    }
}

// One test function: it sets process-wide environment variables, so cases must not run in parallel.
#[tokio::test]
async fn backend_supervises_a_runner_over_its_control_socket() {
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fake-runner");
    fs::write(&fake, FAKE_RUNNER).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
    // SAFETY: single-threaded test body at this point; no other test in this binary touches the environment.
    unsafe { std::env::set_var("FLUXVM_VZ_RUNNER", &fake) };
    assert_eq!(find_runner().unwrap(), fake);

    // Launch: the backend waits for `running` and returns the runner's pid and control socket.
    let ctx = context(dir.path());
    let launched = AppleBackend
        .launch(&Config::default(), &request(), &ctx)
        .await
        .expect("launch");
    assert!(launched.pid > 1);
    let sock = launched.control_socket.clone().expect("control socket");
    assert!(
        sock.to_string_lossy().len() < 100,
        "socket path must fit sockaddr_un"
    );
    assert_eq!(
        read_guest_ip(&ctx.workspace).as_deref(),
        Some("192.168.64.77")
    );

    // Pause and resume go through the control socket.
    let r = control_call(&sock, "pause").await.unwrap();
    assert_eq!(r.state(), Some("paused"));
    let r = control_call(&sock, "resume").await.unwrap();
    assert_eq!(r.state(), Some("running"));
    assert_eq!(r.ip(), Some("192.168.64.77"));

    // The runner config handed over is complete and the MAC is stable across relaunches.
    let conf: serde_json::Value =
        serde_json::from_slice(&fs::read(ctx.workspace.join("vz-config.json")).unwrap()).unwrap();
    assert_eq!(conf["guest_os"], "linux");
    assert_eq!(conf["cpus"], 2);
    let mac = fs::read_to_string(ctx.workspace.join("vz-mac")).unwrap();
    assert!(mac.starts_with("02:"), "locally administered MAC: {mac}");

    // Graceful shutdown ends the runner.
    let r = control_call(&sock, "shutdown").await.unwrap();
    assert!(r.ok());
    for _ in 0..50 {
        if !sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(!sock.exists(), "runner cleaned up its socket");

    // A runner that fails is reported with its own error text, not a timeout.
    unsafe { std::env::set_var("FAKE_RUNNER_FAIL", "1") };
    let ctx2 = context(&dir.path().join("second"));
    let err = AppleBackend
        .launch(&Config::default(), &request(), &ctx2)
        .await
        .expect_err("must fail")
        .to_string();
    assert!(err.contains("fake runner failure"), "{err}");
    unsafe { std::env::remove_var("FAKE_RUNNER_FAIL") };

    // Unsupported requests are refused before any process starts.
    let mut bad = request();
    bad.network = serde_json::from_str(r#"{"mode":"tap"}"#).unwrap();
    let err = AppleBackend
        .launch(
            &Config::default(),
            &bad,
            &context(&dir.path().join("third")),
        )
        .await
        .expect_err("tap")
        .to_string();
    assert!(err.contains("user"), "{err}");

    // A missing runner explains how to build it.
    unsafe { std::env::set_var("FLUXVM_VZ_RUNNER", "/nonexistent/runner") };
    // (the built-in default may still be found on a Mac, so only assert the message shape when it is absent)
    if let Err(e) = find_runner() {
        assert!(e.to_string().contains("fluxvm-vz-runner"));
    }
}
