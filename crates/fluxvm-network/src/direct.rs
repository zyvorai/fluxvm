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
use std::{ffi::CString, fs::File, os::fd::AsRawFd};

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
        bail!(
            "opening /dev/net/tun: {}",
            std::io::Error::last_os_error()
        );
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(ifreq_for("0123456789abcdef").is_err(), "16 chars leaves no NUL");
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
            .args(["--net=/run/netns/fvdt-unit", "--", "ip", "link", "show", "fvdtu0"])
            .status()
            .unwrap()
            .success();
        let in_host = std::path::Path::new("/sys/class/net/fvdtu0").exists();
        unsafe { libc::close(fd) };
        let gone = !std::process::Command::new("nsenter")
            .args(["--net=/run/netns/fvdt-unit", "--", "ip", "link", "show", "fvdtu0"])
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
