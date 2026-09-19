// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Bridge-less ("direct") tap attach.
//!
//! A `NetworkSpec::Tap { direct: Some(..) }` VM has no bridge between its tap
//! and the outer device; a TC/eBPF redirect (see `bpf/fluxvm_direct.bpf.c` and
//! the redirect tail in `bpf/fluxvm_tc.bpf.c`) moves frames instead. That only
//! works when the tap and the outer device share a network namespace, because
//! `bpf_redirect` takes an ifindex that is meaningful within one namespace.
//!
//! For a CNI pod that namespace is the pod's, while the VMM runs in the host
//! namespace and so cannot open the tap by name. The daemon therefore creates
//! the tap *inside* the pod namespace itself and hands the VMM an already-open
//! `/dev/net/tun` fd (`PreparedNetwork::tap_fd`), the same fd-inheritance
//! pattern macvtap uses.

use anyhow::{Context, Result, bail};
use fluxvm_core::{model::DirectSpec, process::run_checked};
use serde::{Deserialize, Serialize};
use std::{ffi::CString, fs::File, os::fd::AsRawFd, path::Path};
use uuid::Uuid;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
/// Without this the guest's virtio-net cannot negotiate checksum/TSO offloads
/// on an fd-attached tap (QEMU opening a tap by `ifname=` sets it itself).
const IFF_VNET_HDR: libc::c_short = 0x4000;

/// `struct ifreq` as `TUNSETIFF` reads it: a 16-byte name and the flags half of
/// the trailing union, padded out to the kernel's 40-byte size.
#[repr(C)]
struct IfReqFlags {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}
const _: () = assert!(std::mem::size_of::<IfReqFlags>() == 40);

fn ifreq_for(name: &str) -> Result<IfReqFlags> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        bail!("tap interface name must be 1..=15 characters");
    }
    if name.bytes().any(|b| b == 0 || b == b'/') {
        bail!("tap interface name contains an invalid character");
    }
    let mut ifr = IfReqFlags {
        name: [0; libc::IFNAMSIZ],
        flags: IFF_TAP | IFF_NO_PI | IFF_VNET_HDR,
        _pad: [0; 22],
    };
    ifr.name[..name.len()].copy_from_slice(name.as_bytes());
    Ok(ifr)
}

/// `nsenter` arguments that run `cmd` inside the network namespace at `path`.
/// Only the *net* namespace is entered, so bpffs pins and the daemon's
/// filesystem view stay visible to the child.
pub fn nsenter_args(netns_path: &str, cmd: &[&str]) -> Vec<String> {
    let mut a = vec![format!("--net={netns_path}"), "--".into()];
    a.extend(cmd.iter().map(|s| s.to_string()));
    a
}

/// Runs `ip <args>` inside `netns_path`.
pub async fn ip_in_netns(netns_path: &str, args: &[&str]) -> Result<()> {
    let mut cmd = vec!["ip"];
    cmd.extend_from_slice(args);
    run_checked("nsenter", &nsenter_args(netns_path, &cmd)).await
}

/// Creates tap `name` inside the network namespace at `netns_path` and returns
/// an exec-inheritable (no `O_CLOEXEC`) fd bound to it.
///
/// The tap is *not* persistent: it disappears when the last fd to it closes,
/// so a VMM exit, a failed launch (the backends close the fd) or a daemon
/// crash all clean it up without a separate teardown step.
fn open_tap_in_netns_blocking(netns_path: &str, name: &str) -> Result<i32> {
    let mut ifr = ifreq_for(name)?;
    let ns = File::open(netns_path).with_context(|| format!("opening netns {netns_path}"))?;
    // SAFETY: `ns` is a valid open netns fd for the duration of the call.
    // setns(CLONE_NEWNET) changes only the calling *thread's* namespace, which
    // is why this runs on a dedicated short-lived thread (see caller) and
    // never on a tokio worker or the daemon's main thread.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        bail!(
            "setns into {netns_path}: {}",
            std::io::Error::last_os_error()
        );
    }
    let tun = CString::new("/dev/net/tun").expect("static path has no NUL");
    // SAFETY: valid NUL-terminated path. The open happens *inside* the target
    // namespace because a tun device belongs to the namespace of the socket
    // that created it. No O_CLOEXEC on purpose: the fd must survive exec into
    // the VMM.
    let fd = unsafe { libc::open(tun.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        bail!("opening /dev/net/tun: {}", std::io::Error::last_os_error());
    }
    // SAFETY: `ifr` is a live, correctly sized `struct ifreq`; `fd` is a tun fd.
    if unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut IfReqFlags) } != 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: `fd` was opened above and not yet handed to anyone.
        unsafe { libc::close(fd) };
        bail!("TUNSETIFF {name} in {netns_path}: {err}");
    }
    Ok(fd)
}

/// Async wrapper: runs the `setns` work on its own OS thread.
async fn open_tap_in_netns(netns_path: &str, name: &str) -> Result<i32> {
    let (p, n) = (netns_path.to_string(), name.to_string());
    tokio::task::spawn_blocking(move || {
        // A fresh std thread, not the blocking-pool thread: pool threads are
        // reused, and a thread left in the wrong namespace would silently
        // misplace unrelated work. The thread exits after this one call.
        std::thread::Builder::new()
            .name("fluxvm-tap-netns".into())
            .spawn(move || open_tap_in_netns_blocking(&p, &n))
            .context("spawning netns thread")?
            .join()
            .map_err(|_| anyhow::anyhow!("netns tap thread panicked"))?
    })
    .await
    .context("joining netns tap task")?
}

/// Result of preparing a direct tap.
pub struct DirectTap {
    /// Set when the tap lives in a foreign netns: the VMM must use `fd=`.
    pub fd: Option<i32>,
}

/// Creates the tap for `direct` (no bridge enslavement) and brings it up.
///
/// * `netns_path: None` — the tap is created in the host namespace by name,
///   exactly like a bridged tap minus `set_master`, so every VMM backend can
///   open it by `ifname`.
/// * `netns_path: Some(_)` — the tap is created inside that namespace and an
///   fd is returned for the VMM.
pub async fn prepare_tap(tap: &str, direct: &DirectSpec) -> Result<DirectTap> {
    match &direct.netns_path {
        None => {
            crate::create_tap(tap).await?;
            Ok(DirectTap { fd: None })
        }
        Some(path) => {
            let fd = open_tap_in_netns(path, tap).await?;
            if let Err(e) = ip_in_netns(path, &["link", "set", "dev", tap, "up"]).await {
                // SAFETY: fd is ours and not yet handed to a VMM.
                unsafe { libc::close(fd) };
                return Err(e).context("bringing the direct tap up");
            }
            Ok(DirectTap { fd: Some(fd) })
        }
    }
}

/// Best-effort removal of a direct tap that may still exist (host-namespace
/// taps are persistent; namespaced ones normally vanish with their fd).
pub async fn cleanup(tap: &str, direct: &DirectSpec) {
    if let Some(path) = &direct.netns_path {
        let _ = ip_in_netns(path, &["link", "del", tap]).await;
    }
}

/// What the eBPF loader must know to (re)wire a direct VM, persisted next to the
/// rest of the per-VM attach metadata so that *every* later operation -- repair,
/// reconfigure, status, remove -- can re-enter the right namespace and re-apply
/// the redirect config without being told again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectAttach {
    pub spec: DirectSpec,
    /// Guest MAC: the inbound steering key for `DirectMode::L2Uplink`.
    #[serde(default)]
    pub guest_mac: Option<String>,
}

const RECORD_FILE: &str = "direct.json";

pub(crate) fn record_in(dir: &Path, a: &DirectAttach) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let json = serde_json::to_vec_pretty(a)?;
    std::fs::write(dir.join(RECORD_FILE), json).context("recording direct attach")
}

pub(crate) fn recorded_in(dir: &Path) -> Option<DirectAttach> {
    let raw = std::fs::read(dir.join(RECORD_FILE)).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Records that VM `id` is a direct VM. Call before applying the dataplane.
pub fn record(id: Uuid, a: &DirectAttach) -> Result<()> {
    record_in(&crate::ebpf::vm_meta_dir(id), a)
}

/// The direct attach recorded for `id`, if it is a direct VM.
pub fn recorded(id: Uuid) -> Option<DirectAttach> {
    recorded_in(&crate::ebpf::vm_meta_dir(id))
}

/// Parses `aa:bb:cc:dd:ee:ff` into its six bytes.
pub fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        bail!("invalid MAC {mac:?}: expected 6 colon-separated octets");
    }
    let mut out = [0u8; 6];
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).with_context(|| format!("invalid MAC {mac:?}"))?;
    }
    Ok(out)
}

// Wire encodings of the maps in bpf/fluxvm_direct.bpf.h and bpf/fluxvm_direct.bpf.c.
// Native-endian u32 fields, no implicit padding: keep in lockstep with the C structs.
pub(crate) const OUT_PEER: u32 = 1; // FLUXVM_DIRECT_PEER
pub(crate) const OUT_REDIRECT: u32 = 2; // FLUXVM_DIRECT_REDIRECT
pub(crate) const IN_PEER: u32 = 1; // FLUXVM_DIRECT_IN_PEER
pub(crate) const IN_L2: u32 = 2; // FLUXVM_DIRECT_IN_L2

/// `struct direct_out { peer_ifindex, mode, flags, pad }` (16 B).
pub(crate) fn out_value(peer_ifindex: u32, mode: u32, flags: u32) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..4].copy_from_slice(&peer_ifindex.to_ne_bytes());
    v[4..8].copy_from_slice(&mode.to_ne_bytes());
    v[8..12].copy_from_slice(&flags.to_ne_bytes());
    v
}

/// `struct direct_in { tap_ifindex, mode }` (8 B).
pub(crate) fn in_value(tap_ifindex: u32, mode: u32) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[0..4].copy_from_slice(&tap_ifindex.to_ne_bytes());
    v[4..8].copy_from_slice(&mode.to_ne_bytes());
    v
}

/// Shared per-uplink steering maps (bpf/fluxvm_direct.bpf.h). One pair per uplink, reused by name by
/// every VM's programs; sizes MUST equal the header's or libbpf refuses the reuse.
pub(crate) const DMAC_MAP: &str = "fluxvm_dmac";
pub(crate) const DIP_MAP: &str = "fluxvm_dip";
pub(crate) const DMAC_ENTRIES: u32 = 1024; // FLUXVM_DIRECT_MAC_ENTRIES
pub(crate) const DIP_ENTRIES: u32 = 1024; // FLUXVM_DIRECT_IP_ENTRIES

/// Where the shared maps for `outer` are pinned: `<pin_root>/uplinks/<outer>`.
pub(crate) fn uplink_dir(pin_root: &Path, outer: &str) -> std::path::PathBuf {
    pin_root.join("uplinks").join(outer)
}

/// The IPv4 address as it appears on the wire (network byte order): the `fluxvm_dip` key.
pub(crate) fn ip_key(ip: &str) -> Result<[u8; 4]> {
    Ok(ip
        .parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("guest IP {ip:?} is not an IPv4 address"))?
        .octets())
}

/// Why `outer` cannot be a bridge-less uplink, or `None` when it can. A device that is a port of a
/// bridge or bond would have its frames consumed by the master before a TC hook could steer them.
pub fn uplink_problem(sysfs_class_net: &Path, outer: &str) -> Option<String> {
    let dev = sysfs_class_net.join(outer);
    if !dev.exists() {
        return Some(format!("uplink {outer} does not exist"));
    }
    if dev.join("master").exists() {
        let master = std::fs::read_link(dev.join("master"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "?".into());
        return Some(format!(
            "uplink {outer} is a port of {master}; use the bridge/bond itself or an unenslaved NIC \
             (a bridge-less tap needs the frames to reach the uplink's TC hook)"
        ));
    }
    None
}

/// `struct mac_key { u8 addr[6]; u8 pad[2]; }` (8 B).
pub(crate) fn mac_key(mac: [u8; 6]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[..6].copy_from_slice(&mac);
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::model::DirectMode;

    fn attach() -> DirectAttach {
        DirectAttach {
            spec: DirectSpec {
                outer: "eth0".into(),
                netns_path: Some("/run/netns/fvcni-abc".into()),
                mode: DirectMode::PeerVeth,
                guest_ips: vec![],
            },
            guest_mac: Some("02:00:00:00:00:02".into()),
        }
    }

    #[test]
    fn record_round_trips_and_missing_means_not_direct() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(recorded_in(d.path()), None, "no record => not a direct VM");
        record_in(d.path(), &attach()).unwrap();
        assert_eq!(recorded_in(d.path()), Some(attach()));
        // Overwriting (a repair re-record) is idempotent.
        record_in(d.path(), &attach()).unwrap();
        assert_eq!(recorded_in(d.path()), Some(attach()));
    }

    #[test]
    fn corrupt_record_is_treated_as_not_direct_not_a_panic() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(RECORD_FILE), b"{not json").unwrap();
        assert_eq!(recorded_in(d.path()), None);
    }

    #[test]
    fn map_values_match_the_c_struct_layouts() {
        let v = out_value(0x0102_0304, OUT_PEER, 0);
        assert_eq!(v.len(), 16);
        assert_eq!(&v[0..4], &0x0102_0304u32.to_ne_bytes());
        assert_eq!(&v[4..8], &1u32.to_ne_bytes());
        assert_eq!(&v[8..16], &[0u8; 8]);
        let w = in_value(7, IN_L2);
        assert_eq!(w.len(), 8);
        assert_eq!(&w[0..4], &7u32.to_ne_bytes());
        assert_eq!(&w[4..8], &2u32.to_ne_bytes());
        let k = mac_key([0x02, 0, 0, 0, 0, 0x2a]);
        assert_eq!(k, [0x02, 0, 0, 0, 0, 0x2a, 0, 0]);
    }

    #[test]
    fn ip_keys_are_wire_order_and_garbage_is_rejected() {
        assert_eq!(ip_key("10.1.2.3").unwrap(), [10, 1, 2, 3]);
        assert!(ip_key("fd00::1").is_err());
        assert!(ip_key("300.1.1.1").is_err());
        assert!(ip_key("").is_err());
    }

    #[test]
    fn uplink_dir_is_scoped_per_device() {
        assert_eq!(
            uplink_dir(Path::new("/sys/fs/bpf/fluxvm"), "enp1s0"),
            Path::new("/sys/fs/bpf/fluxvm/uplinks/enp1s0")
        );
    }

    #[test]
    fn a_bridge_or_bond_port_and_a_missing_nic_are_not_uplinks() {
        let root = tempfile::tempdir().unwrap();
        let net = root.path();
        assert!(
            uplink_problem(net, "enp1s0")
                .unwrap()
                .contains("does not exist")
        );
        std::fs::create_dir_all(net.join("enp1s0")).unwrap();
        assert_eq!(uplink_problem(net, "enp1s0"), None, "a plain NIC is fine");
        // enslaved: sysfs exposes `master` as a symlink to the master device
        std::fs::create_dir_all(net.join("vmbr0")).unwrap();
        std::os::unix::fs::symlink(net.join("vmbr0"), net.join("enp1s0/master")).unwrap();
        let why = uplink_problem(net, "enp1s0").unwrap();
        assert!(why.contains("port of vmbr0"), "{why}");
        assert_eq!(
            uplink_problem(net, "vmbr0"),
            None,
            "the master itself is a valid outer"
        );
    }

    #[test]
    fn parse_mac_accepts_valid_and_rejects_garbage() {
        assert_eq!(
            parse_mac("02:00:00:00:00:2A").unwrap(),
            [0x02, 0, 0, 0, 0, 0x2a]
        );
        for bad in [
            "",
            "02:00:00:00:00",
            "02:00:00:00:00:00:00",
            "zz:00:00:00:00:00",
            "0200.0000.002a",
        ] {
            assert!(parse_mac(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ifreq_carries_name_and_tap_flags() {
        let ifr = ifreq_for("eph1234abcd").unwrap();
        assert_eq!(&ifr.name[..11], b"eph1234abcd");
        assert_eq!(ifr.name[11], 0, "name must stay NUL-terminated");
        assert_eq!(ifr.flags, 0x0002 | 0x1000 | 0x4000);
    }

    #[test]
    fn ifreq_rejects_bad_names() {
        assert!(ifreq_for("").is_err());
        assert!(
            ifreq_for("0123456789abcdef").is_err(),
            "16 chars leaves no NUL"
        );
        assert!(ifreq_for("a/b").is_err());
        assert!(ifreq_for("0123456789abcde").is_ok(), "15 chars is the max");
    }

    #[test]
    fn nsenter_enters_only_the_net_namespace() {
        let a = nsenter_args("/run/netns/fvcni-abc", &["ip", "link", "show"]);
        assert_eq!(a[0], "--net=/run/netns/fvcni-abc");
        assert!(
            !a.iter().any(|x| x.starts_with("--mount") || x == "-a"),
            "bpffs pins must stay visible, so the mount namespace is not entered"
        );
        assert_eq!(&a[1..], ["--", "ip", "link", "show"]);
    }

    /// Needs root and `ip netns`; skipped elsewhere. Proves the core claim of
    /// the fd handoff: the tap appears in the pod netns and NOT in ours.
    #[tokio::test]
    async fn tap_fd_lands_in_the_target_namespace() {
        if unsafe { libc::geteuid() } != 0
            || std::process::Command::new("ip")
                .args(["netns", "add", "fvdt-unit"])
                .status()
                .map(|s| !s.success())
                .unwrap_or(true)
        {
            eprintln!("SKIP: needs root + ip netns");
            return;
        }
        let path = "/run/netns/fvdt-unit";
        let fd = open_tap_in_netns(path, "fvdtu0").await.expect("open tap");
        let in_ns = std::process::Command::new("nsenter")
            .args([
                "--net=/run/netns/fvdt-unit",
                "--",
                "ip",
                "link",
                "show",
                "fvdtu0",
            ])
            .status()
            .unwrap()
            .success();
        let in_host = std::path::Path::new("/sys/class/net/fvdtu0").exists();
        unsafe { libc::close(fd) };
        let gone = !std::process::Command::new("nsenter")
            .args([
                "--net=/run/netns/fvdt-unit",
                "--",
                "ip",
                "link",
                "show",
                "fvdtu0",
            ])
            .status()
            .unwrap()
            .success();
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", "fvdt-unit"])
            .status();
        assert!(in_ns, "tap must exist inside the target netns");
        assert!(!in_host, "tap must not leak into the daemon's netns");
        assert!(gone, "non-persistent tap must vanish when the fd closes");
    }
}
