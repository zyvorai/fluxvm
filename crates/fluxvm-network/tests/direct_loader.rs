// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Root + Linux integration test for the bridge-less direct attach, driven through the same
//! entry points the scheduler uses (`prepare` -> `apply_sandbox_policy` -> status -> `cleanup`),
//! against a Cilium-shaped topology built from network namespaces. No KVM: a small Python
//! "guest" adopts the tap fd the daemon hands out, exactly as QEMU would inherit it.
//!
//!   node ns:  lxc0 (10.97.0.1) <-veth-> eth0 :pod ns      (Cilium delivers here)
//!   pod ns:   eth0 --direct_in--> tap (created by prepare(), fd held here) --> guest
//!
//! Skipped unless: Linux, root, `ip`/`nsenter`/`python3`, bpffs, and built BPF objects in
//! `FLUXVM_TEST_BPF_DIR` (run scripts/build-ebpf.sh <dir> first).
//!
//!   FLUXVM_TEST_BPF_DIR=/tmp/bpf sudo -E cargo test -p fluxvm-network --test direct_loader -- --nocapture

use fluxvm_core::{
    config::{Config, DataplaneMode},
    model::{DirectMode, DirectSpec, NetworkSpec},
};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

fn sh(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn skip(why: &str) {
    eprintln!("SKIP direct_loader: {why}");
}

struct Cleanup {
    id: Option<Uuid>,
    namespaces: Vec<String>,
    guest: Option<Child>,
    fd: Option<i32>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(g) = self.guest.as_mut() {
            let _ = g.kill();
            let _ = g.wait();
        }
        if let Some(id) = self.id {
            // A panicking test must not strand bpffs pins or TC/TCX attachments.
            let _ = fluxvm_network::dataplane::remove_sandbox_policy_best_effort(id);
        }
        if let Some(fd) = self.fd.take() {
            // SAFETY: the fd was returned by prepare() and is closed exactly once, here.
            unsafe { libc::close(fd) };
        }
        for ns in &self.namespaces {
            let _ = sh("ip", &["netns", "del", ns]);
        }
    }
}

fn in_ns(ns: &str, cmd: &[&str]) -> bool {
    let mut args = vec![format!("--net=/run/netns/{ns}"), "--".to_string()];
    args.extend(cmd.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    sh("nsenter", &refs)
}

fn ns_out(ns: &str, cmd: &[&str]) -> String {
    let mut args = vec![format!("--net=/run/netns/{ns}"), "--".to_string()];
    args.extend(cmd.iter().map(|s| s.to_string()));
    Command::new("nsenter")
        .args(&args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Everything needed to see why traffic does not flow, printed only on failure.
fn diag(node: &str, pod: &str, tap: &str, id: Uuid, stats: &Path) {
    eprintln!("---- DIAG (ping failed) ----");
    eprintln!(
        "guest stats: {}",
        std::fs::read_to_string(stats)
            .unwrap_or_default()
            .replace('\n', " ")
    );
    eprintln!(
        "pod eth0 ingress filters:\n{}",
        ns_out(pod, &["tc", "filter", "show", "dev", "eth0", "ingress"])
    );
    eprintln!(
        "pod {tap} ingress filters:\n{}",
        ns_out(pod, &["tc", "filter", "show", "dev", tap, "ingress"])
    );
    eprintln!(
        "pod bpftool net:\n{}",
        ns_out(pod, &["bpftool", "net", "show"])
    );
    eprintln!("pod links:\n{}", ns_out(pod, &["ip", "-s", "link"]));
    eprintln!("node neigh: {}", ns_out(node, &["ip", "neigh"]));
    let dir = format!("/sys/fs/bpf/fluxvm/vms/{}", id.simple());
    for m in [
        "maps/fluxvm_direct",
        "direct_maps/fluxvm_direct_in",
        "maps/fluxvm_id",
    ] {
        eprintln!(
            "{m}:\n{}",
            String::from_utf8_lossy(
                &Command::new("bpftool")
                    .args(["map", "dump", "pinned", &format!("{dir}/{m}")])
                    .output()
                    .map(|o| o.stdout)
                    .unwrap_or_default()
            )
        );
    }
    eprintln!(
        "meta: {:?}",
        std::fs::read_dir(format!("/run/fluxvm/ebpf/vms/{}", id.simple())).map(|d| d
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>())
    );
    eprintln!("---- END DIAG ----");
}

fn stat(path: &Path, key: &str) -> u64 {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_tap_is_wired_by_the_loader_and_carries_traffic() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return skip("root required");
    }
    let Some(bpf_dir) = std::env::var_os("FLUXVM_TEST_BPF_DIR").map(PathBuf::from) else {
        return skip("FLUXVM_TEST_BPF_DIR not set (build with scripts/build-ebpf.sh <dir>)");
    };
    for tool in ["ip", "nsenter", "python3", "bpftool", "tc"] {
        if !have(tool) {
            return skip(&format!("{tool} not found"));
        }
    }
    if !bpf_dir.join("fluxvm_tc.bpf.o").exists() || !bpf_dir.join("fluxvm_direct.bpf.o").exists() {
        return skip("fluxvm_tc.bpf.o / fluxvm_direct.bpf.o missing in FLUXVM_TEST_BPF_DIR");
    }

    let pid = std::process::id();
    let node = format!("fvrt{pid}-node");
    let pod = format!("fvrt{pid}-pod");
    let pod_path = format!("/run/netns/{pod}");
    let work = tempfile::tempdir().unwrap();
    let stats = work.path().join("guest.stats");
    let mut cleanup = Cleanup {
        id: None,
        namespaces: vec![node.clone(), pod.clone()],
        guest: None,
        fd: None,
    };

    // ── topology: a Cilium-shaped pod (veth peer in the pod netns, no bridge anywhere) ──
    assert!(sh("ip", &["netns", "add", &node]));
    assert!(sh("ip", &["netns", "add", &pod]));
    assert!(sh(
        "ip",
        &[
            "-n", &node, "link", "add", "lxc0", "type", "veth", "peer", "name", "eth0", "netns",
            &pod
        ]
    ));
    assert!(sh(
        "ip",
        &["-n", &node, "addr", "add", "10.97.0.1/24", "dev", "lxc0"]
    ));
    for (ns, dev) in [(&node, "lo"), (&node, "lxc0"), (&pod, "lo"), (&pod, "eth0")] {
        assert!(sh("ip", &["-n", ns, "link", "set", dev, "up"]));
    }

    // ── daemon side: the same calls the scheduler makes ──
    let mut cfg = Config::default();
    cfg.state_dir = work.path().join("state");
    std::fs::create_dir_all(&cfg.state_dir).unwrap();
    cfg.sandbox.dataplane.mode = DataplaneMode::Ebpf;
    cfg.sandbox.dataplane.bpf_object = bpf_dir.join("fluxvm_tc.bpf.o");
    cfg.sandbox.dataplane.required = true;
    cfg.sandbox.dataplane.default_allow = true;

    let id = Uuid::new_v4();
    cleanup.id = Some(id);
    let spec = NetworkSpec::Tap {
        tap_name: Some("fvrt0".into()),
        bridge: None,
        mac: Some("02:00:00:00:00:02".into()),
        netns: false,
        extra: vec![],
        direct: Some(DirectSpec {
            outer: "eth0".into(),
            netns_path: Some(pod_path.clone()),
            mode: DirectMode::PeerVeth,
            guest_ips: vec![],
        }),
    };
    let prepared = fluxvm_network::prepare(&cfg, id, &spec)
        .await
        .expect("prepare");
    let tap = prepared.tap_name.clone().expect("tap name");
    let fd = prepared
        .tap_fd
        .expect("a foreign-netns tap must be handed over as an fd");
    cleanup.fd = Some(fd);
    assert!(
        prepared.netns.is_none(),
        "the VMM must NOT be launched inside the pod netns"
    );
    assert!(
        fluxvm_network::direct::recorded(id).is_some(),
        "prepare() must record the direct attach for the loader"
    );
    assert!(
        !std::path::Path::new(&format!("/sys/class/net/{tap}")).exists(),
        "the tap must live in the pod netns, not the daemon's"
    );

    fluxvm_network::dataplane::apply_sandbox_policy(&cfg, id, Some(&tap), None, &[], None).expect(
        "apply_sandbox_policy must attach the egress program AND the direct inbound redirect",
    );

    let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, id).unwrap();
    assert!(
        st.direct_required && st.direct_attached,
        "direct hook must be live: {st:?}"
    );
    assert!(st.attached, "overall attachment must be healthy: {st:?}");
    assert_eq!(
        st.schema_version,
        Some(fluxvm_network::ebpf::DATAPLANE_SCHEMA_VERSION)
    );

    // ── the "guest": adopts the inherited fd, never enters the pod netns ──
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/direct-datapath-guest.py");
    let child = Command::new("python3")
        .arg(&script)
        .arg(format!("fd:{fd}"))
        .arg("10.97.0.2")
        .arg("02:00:00:00:00:02")
        .arg(&stats)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn guest");
    cleanup.guest = Some(child);
    for _ in 0..50 {
        if stats.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(stats.exists(), "guest did not start");

    let ping = || {
        in_ns(
            &node,
            &["ping", "-c", "3", "-W", "1", "-i", "0.2", "-q", "10.97.0.2"],
        )
    };
    if !ping() {
        diag(&node, &pod, &tap, id, &stats);
    }
    assert!(
        ping(),
        "node must reach the guest through eth0 -> direct_in -> tap -> egress -> lxc0"
    );
    assert!(
        stat(&stats, "icmp_replies") >= 3,
        "guest must have answered the echo requests"
    );

    let bridges = ns_out(&node, &["ip", "-d", "link"])
        .matches("bridge ")
        .count()
        + ns_out(&pod, &["ip", "-d", "link"])
            .matches("bridge ")
            .count();
    assert_eq!(bridges, 0, "no bridge device may exist in either namespace");

    // ── repair / restart: re-applying must keep the redirect wiring (it is re-derived from
    //    the recorded direct attach, since remove() wipes the per-VM metadata) ──
    fluxvm_network::dataplane::apply_sandbox_policy(&cfg, id, Some(&tap), None, &[], None)
        .expect("re-apply (reconcile/restart) must succeed");
    let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, id).unwrap();
    assert!(
        st.attached && st.direct_attached,
        "still attached after re-apply: {st:?}"
    );
    assert!(ping(), "connectivity must survive a re-apply");

    // ── teardown through the scheduler's cleanup entry point ──
    fluxvm_network::cleanup(&cfg.state_dir, id, &prepared.spec, &tap, None)
        .await
        .expect("cleanup");
    let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, id).unwrap();
    assert!(
        !st.attached && !st.direct_required,
        "nothing may remain attached: {st:?}"
    );
    assert!(
        fluxvm_network::direct::recorded(id).is_none(),
        "the direct record must be removed with the rest of the per-VM metadata"
    );
    let filters = ns_out(&pod, &["tc", "filter", "show", "dev", "eth0", "ingress"]);
    assert!(
        !filters.contains("bpf"),
        "the inbound program must be detached from the outer device:\n{filters}"
    );
    assert!(
        !cfg.sandbox
            .dataplane
            .pin_root
            .join("vms")
            .join(id.simple().to_string())
            .exists(),
        "bpffs pins must be removed"
    );
}
