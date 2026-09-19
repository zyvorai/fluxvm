// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Root + Linux integration test for the standalone "l2-uplink" direct mode: two VMs share ONE
//! uplink with no bridge anywhere, driven through the same calls the scheduler makes.
//!
//!   lan ns:  up0 (10.95.0.1) <-veth-> NIC          NIC has no IP and no bridge master
//!   here:    NIC ── direct_in (shared maps) ──▶ tapA (guest A, 10.95.0.10)
//!                                             ╲▶ tapB (guest B, 10.95.0.11)
//!
//! Asserts: LAN -> each guest (ARP steered by the declared guest IP, then unicast by MAC), each
//! guest -> LAN, guest <-> guest switched locally, no bridge device, and that removing one VM
//! removes only its own steering entries while the other keeps working.
//!
//! Run through scripts/test-direct-uplink.sh, which puts the test in a private network + mount
//! namespace so a live host's own namespace is never touched. Skipped unless Linux, root, the
//! tools and `FLUXVM_TEST_BPF_DIR` (built objects) are present.

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

fn out(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn stat(path: &Path, key: &str) -> u64 {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

struct Vm {
    id: Uuid,
    tap: String,
    mac: &'static str,
    ip: &'static str,
    guest: Option<Child>,
    stats: PathBuf,
}

struct Cleanup {
    vms: Vec<Uuid>,
    guests: Vec<Child>,
    lan: String,
    nic: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for g in &mut self.guests {
            let _ = g.kill();
            let _ = g.wait();
        }
        for id in &self.vms {
            let _ = fluxvm_network::dataplane::remove_sandbox_policy_best_effort(*id);
        }
        let _ = sh("ip", &["link", "del", &self.nic]);
        let _ = sh("ip", &["netns", "del", &self.lan]);
        // The shared per-uplink maps are deliberately left pinned by the loader; remove ours.
        let _ = std::fs::remove_dir_all(format!("/sys/fs/bpf/fluxvm/uplinks/{}", self.nic));
    }
}

fn spec(tap: &str, mac: &str, nic: &str, ip: &str) -> NetworkSpec {
    NetworkSpec::Tap {
        tap_name: Some(tap.into()),
        bridge: None,
        mac: Some(mac.into()),
        netns: false,
        extra: vec![],
        direct: Some(DirectSpec {
            outer: nic.into(),
            netns_path: None,
            mode: DirectMode::L2Uplink,
            guest_ips: vec![ip.into()],
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_vms_share_one_uplink_without_a_bridge() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return eprintln!("SKIP direct_uplink: root required");
    }
    let Some(bpf_dir) = std::env::var_os("FLUXVM_TEST_BPF_DIR").map(PathBuf::from) else {
        return eprintln!("SKIP direct_uplink: FLUXVM_TEST_BPF_DIR not set");
    };
    for tool in ["ip", "python3", "bpftool", "tc"] {
        if !have(tool) {
            return eprintln!("SKIP direct_uplink: {tool} not found");
        }
    }
    if !bpf_dir.join("fluxvm_tc.bpf.o").exists() || !bpf_dir.join("fluxvm_direct.bpf.o").exists() {
        return eprintln!("SKIP direct_uplink: BPF objects missing");
    }
    // The loader reads ifindexes from /sys/class/net, which only reflects THIS namespace when
    // sysfs was mounted inside it. Refuse to run against the machine's real namespace.
    if std::env::var_os("FLUXVM_TEST_ISOLATED").is_none() {
        return eprintln!(
            "SKIP direct_uplink: run via scripts/test-direct-uplink.sh (private net+mount namespace)"
        );
    }

    let pid = std::process::id();
    let nic = format!("fvu{pid}n");
    let lan = format!("fvu{pid}-lan");
    let work = tempfile::tempdir().unwrap();
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/direct-datapath-guest.py");
    let mut cleanup = Cleanup {
        vms: vec![],
        guests: vec![],
        lan: lan.clone(),
        nic: nic.clone(),
    };

    // ── topology: an unbridged uplink with a LAN peer behind it ──
    assert!(sh("ip", &["netns", "add", &lan]));
    assert!(sh(
        "ip",
        &[
            "link", "add", &nic, "type", "veth", "peer", "name", "up0", "netns", &lan
        ]
    ));
    assert!(sh("ip", &["link", "set", &nic, "up"]));
    assert!(sh(
        "ip",
        &["-n", &lan, "addr", "add", "10.95.0.1/24", "dev", "up0"]
    ));
    assert!(sh("ip", &["-n", &lan, "link", "set", "up0", "up"]));
    assert!(sh("ip", &["-n", &lan, "link", "set", "lo", "up"]));

    let mut cfg = Config::default();
    cfg.state_dir = work.path().join("state");
    std::fs::create_dir_all(&cfg.state_dir).unwrap();
    cfg.sandbox.dataplane.mode = DataplaneMode::Ebpf;
    cfg.sandbox.dataplane.bpf_object = bpf_dir.join("fluxvm_tc.bpf.o");
    cfg.sandbox.dataplane.required = true;
    cfg.sandbox.dataplane.default_allow = true;

    let mut vms: Vec<Vm> = Vec::new();
    for (tap, mac, ip) in [
        ("fvtA0", "02:00:00:00:0a:0a", "10.95.0.10"),
        ("fvtB0", "02:00:00:00:0b:0b", "10.95.0.11"),
    ] {
        let id = Uuid::new_v4();
        cleanup.vms.push(id);
        let prepared = fluxvm_network::prepare(&cfg, id, &spec(tap, mac, &nic, ip))
            .await
            .expect("prepare");
        assert!(
            prepared.tap_fd.is_none(),
            "a host-namespace tap is opened by name, not by fd"
        );
        fluxvm_network::dataplane::apply_sandbox_policy(
            &cfg,
            id,
            prepared.tap_name.as_deref(),
            None,
            &[],
            None,
        )
        .expect("apply_sandbox_policy for an l2-uplink VM");
        let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, id).unwrap();
        assert!(
            st.attached && st.direct_required && st.direct_attached,
            "{tap}: {st:?}"
        );
        vms.push(Vm {
            id,
            tap: tap.into(),
            mac,
            ip,
            guest: None,
            stats: work.path().join(format!("{tap}.stats")),
        });
    }
    let expect_tcx = std::env::var("FLUXVM_TCX")
        .map(|v| v != "off")
        .unwrap_or(true);
    let mode = std::fs::read_to_string(format!(
        "/run/fluxvm/ebpf/vms/{}/direct_attach_mode",
        vms[0].id.simple()
    ))
    .unwrap_or_default();
    eprintln!("inbound attach mode: {}", mode.trim());
    if !expect_tcx {
        assert_eq!(
            mode.trim(),
            "tc",
            "FLUXVM_TCX=off must use the legacy clsact path"
        );
    }
    if mode.trim() == "tc" {
        let shown = out(
            "tc",
            &["filter", "show", "dev", &nic, "ingress", "pref", "49154"],
        );
        assert!(
            shown.contains("handle 0x3") && shown.contains("handle 0x4"),
            "each VM needs its own handle under the shared preference:\n{shown}"
        );
    }

    // ── guests: A pings the LAN peer, B pings A (guest <-> guest) ──
    for (i, target) in [(0usize, "10.95.0.1"), (1usize, "10.95.0.10")] {
        let v = &vms[i];
        let child = Command::new("python3")
            .arg(&script)
            .arg(&v.tap)
            .arg(v.ip)
            .arg(v.mac)
            .arg(&v.stats)
            .arg(format!("ping={target}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn guest");
        vms[i].guest = Some(child);
    }
    for v in &mut vms {
        cleanup.guests.push(v.guest.take().unwrap());
    }
    for v in &vms {
        for _ in 0..50 {
            if v.stats.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(v.stats.exists(), "guest {} did not start", v.tap);
    }

    // LAN -> guest: the ARP request is a broadcast, so it can only reach a guest through the
    // declared-IP steering; the replies and the echo are then plain unicast by MAC.
    for v in &vms {
        assert!(
            sh(
                "ip",
                &[
                    "netns", "exec", &lan, "ping", "-c", "3", "-W", "1", "-i", "0.2", "-q", v.ip
                ]
            ),
            "LAN peer must reach {} ({})",
            v.tap,
            v.ip
        );
    }
    // guest -> LAN and guest <-> guest, initiated by the guests themselves
    let mut waited = 0;
    while waited < 40
        && (stat(&vms[0].stats, "echo_replies_rx") == 0
            || stat(&vms[1].stats, "echo_replies_rx") == 0)
    {
        std::thread::sleep(Duration::from_millis(250));
        waited += 1;
    }
    assert!(
        stat(&vms[0].stats, "echo_replies_rx") > 0,
        "guest A must reach the LAN peer"
    );
    assert!(
        stat(&vms[1].stats, "echo_replies_rx") > 0,
        "guest B must reach guest A locally (shared MAC/IP maps, no bridge)"
    );
    assert_eq!(
        out("ip", &["-d", "link"]).matches("bridge ").count(),
        0,
        "no bridge device may exist"
    );

    // ── remove A: only A's entries go, B keeps working, A is unreachable ──
    let id_a = vms[0].id;
    fluxvm_network::cleanup(
        &cfg.state_dir,
        id_a,
        &spec("fvtA0", vms[0].mac, &nic, vms[0].ip),
        "fvtA0",
        None,
    )
    .await
    .expect("cleanup A");
    assert!(
        sh(
            "ip",
            &[
                "netns",
                "exec",
                &lan,
                "ping",
                "-c",
                "2",
                "-W",
                "1",
                "-i",
                "0.2",
                "-q",
                "10.95.0.11"
            ]
        ),
        "B must keep working after A is removed (its program and entries are untouched)"
    );
    // A's ARP cache entry in the LAN peer may still be warm, so drop it before testing reachability.
    let _ = sh("ip", &["-n", &lan, "neigh", "flush", "dev", "up0"]);
    assert!(
        !sh(
            "ip",
            &[
                "netns",
                "exec",
                &lan,
                "ping",
                "-c",
                "2",
                "-W",
                "1",
                "-i",
                "0.2",
                "-q",
                "10.95.0.10"
            ]
        ),
        "A's steering entries must be gone"
    );
    let st = fluxvm_network::ebpf::attachment_status(&cfg.sandbox.dataplane, vms[1].id).unwrap();
    assert!(
        st.attached && st.direct_attached,
        "B still attached: {st:?}"
    );
    fluxvm_network::cleanup(
        &cfg.state_dir,
        vms[1].id,
        &spec("fvtB0", vms[1].mac, &nic, vms[1].ip),
        "fvtB0",
        None,
    )
    .await
    .expect("cleanup B");
}
