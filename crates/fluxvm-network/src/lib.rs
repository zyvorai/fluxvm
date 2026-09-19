// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

pub mod cilium;
pub mod cnp;
pub mod dataplane;
pub mod direct;
pub mod ebpf;
pub mod egress;
pub mod egress_proxy;
pub mod endpoint;
pub mod groups;
pub mod identity;
pub mod ipam;
pub mod ipcache;
pub mod ipv6_ext_walk;
pub mod migration_state;
pub mod netns;
pub mod packetflow;
pub mod pod_identity;
pub mod qemu_cgroup;
pub mod service;
pub mod service_ha;
pub mod service_policy;
pub mod service_pressure;
pub mod tcx;
pub mod xdp;

use anyhow::{Context, Result, bail};
use fluxvm_core::{
    backend::PreparedNetwork,
    config::Config,
    model::{ExtraNic, NetworkSpec},
    process::run_checked,
};
use std::ffi::CString;
use uuid::Uuid;

pub async fn prepare(cfg: &Config, id: Uuid, spec: &NetworkSpec) -> Result<PreparedNetwork> {
    spec.validate_direct().map_err(|e| anyhow::anyhow!(e))?;
    match spec {
        NetworkSpec::None | NetworkSpec::User { .. } => Ok(PreparedNetwork {
            spec: spec.clone(),
            tap_name: None,
            tap_fd: None,
            netns: None,
            dhcp_leasefile: None,
            guest_ip: None,
            guest_cidr: None,
            gateway: None,
        }),
        NetworkSpec::Tap {
            tap_name,
            bridge,
            mac,
            extra,
            netns: use_netns,
            ..
        } if *use_netns => {
            if !extra.is_empty() {
                bail!("Multus extra NICs require network.netns=false (host-bridge taps)");
            }
            let handle = netns::prepare(&cfg.state_dir, id, mac.as_deref())
                .await
                .context("preparing network namespace")?;
            Ok(PreparedNetwork {
                spec: NetworkSpec::Tap {
                    tap_name: Some(handle.tap_name.clone()),
                    bridge: bridge.clone(),
                    mac: mac.clone(),
                    netns: true,
                    extra: vec![],
                    direct: None,
                },
                tap_name: Some(handle.tap_name),
                tap_fd: None,
                netns: Some(handle.netns),
                dhcp_leasefile: Some(handle.dhcp_leasefile),
                guest_ip: Some(handle.guest_ip),
                guest_cidr: Some(handle.guest_cidr),
                gateway: Some(handle.gateway),
            })
        }
        NetworkSpec::Tap {
            tap_name,
            mac,
            direct: Some(direct),
            ..
        } => {
            let tap = tap_name
                .clone()
                .unwrap_or_else(|| format!("eph{}", &id.simple().to_string()[..8]));
            if tap.len() > 15 {
                bail!("tap interface name must be <= 15 characters");
            }
            // No set_master and no default_bridge fallback: the whole point is
            // that nothing bridges this tap. A redirect program pairs it with
            // `direct.outer` instead (attached by the dataplane step).
            let made = direct::prepare_tap(&tap, direct)
                .await
                .context("preparing direct (bridge-less) tap")?;
            Ok(PreparedNetwork {
                spec: NetworkSpec::Tap {
                    tap_name: Some(tap.clone()),
                    bridge: None,
                    mac: mac.clone(),
                    netns: false,
                    extra: vec![],
                    direct: Some(direct.clone()),
                },
                tap_name: Some(tap),
                tap_fd: made.fd,
                // The VMM runs in the host namespace and takes the tap by fd;
                // it is deliberately NOT launched inside the outer netns.
                netns: None,
                dhcp_leasefile: None,
                guest_ip: None,
                guest_cidr: None,
                gateway: None,
            })
        }
        NetworkSpec::Tap {
            tap_name,
            bridge,
            mac,
            extra,
            ..
        } => {
            let tap = tap_name
                .clone()
                .unwrap_or_else(|| format!("eph{}", &id.simple().to_string()[..8]));
            if tap.len() > 15 {
                bail!("tap interface name must be <= 15 characters");
            }
            let bridge = bridge.clone().or_else(|| cfg.default_bridge.clone());

            if let Err(e) = create_tap(&tap).await {
                return Err(e);
            }
            if let Some(br) = &bridge {
                if let Err(e) = set_master(&tap, br).await {
                    let _ = cleanup_tap(&tap).await;
                    return Err(e);
                }
            }
            let mut prepared_extra: Vec<ExtraNic> = Vec::with_capacity(extra.len());
            for (i, nic) in extra.iter().enumerate() {
                if nic.bridge.is_empty() {
                    let _ = cleanup_tap(&tap).await;
                    for prev in &prepared_extra {
                        if let Some(name) = &prev.tap_name {
                            let _ = cleanup_tap(name).await;
                        }
                    }
                    bail!("extra NIC {i} is missing a bridge");
                }
                let etap = nic
                    .tap_name
                    .clone()
                    .unwrap_or_else(|| format!("x{i}{}", &id.simple().to_string()[..7]));
                if etap.len() > 15 {
                    let _ = cleanup_tap(&tap).await;
                    bail!("extra tap interface name must be <= 15 characters");
                }
                if let Err(e) = add_bridge_tap(&etap, &nic.bridge).await {
                    let _ = cleanup_tap(&tap).await;
                    for prev in &prepared_extra {
                        if let Some(name) = &prev.tap_name {
                            let _ = cleanup_tap(name).await;
                        }
                    }
                    return Err(e).context("preparing Multus extra NIC");
                }
                prepared_extra.push(ExtraNic {
                    bridge: nic.bridge.clone(),
                    mac: nic.mac.clone(),
                    tap_name: Some(etap),
                });
            }
            Ok(PreparedNetwork {
                spec: NetworkSpec::Tap {
                    tap_name: Some(tap.clone()),
                    bridge,
                    mac: mac.clone(),
                    netns: false,
                    extra: prepared_extra,
                    direct: None,
                },
                tap_name: Some(tap),
                tap_fd: None,
                netns: None,
                dhcp_leasefile: None,
                guest_ip: None,
                guest_cidr: None,
                gateway: None,
            })
        }
        NetworkSpec::Macvtap {
            parent,
            macvtap_mode,
            mac,
        } => {
            let name = format!("eph{}", &id.simple().to_string()[..8]);
            if name.len() > 15 {
                bail!("macvtap interface name must be <= 15 characters");
            }
            let mvmode = macvtap_mode.clone().unwrap_or_else(|| "bridge".into());

            let created: Result<i32> = async {
                run_checked(
                    "ip",
                    &[
                        "link".into(),
                        "add".into(),
                        "link".into(),
                        parent.clone(),
                        "name".into(),
                        name.clone(),
                        "type".into(),
                        "macvtap".into(),
                        "mode".into(),
                        mvmode.clone(),
                    ],
                )
                .await?;
                if let Some(m) = mac {
                    run_checked(
                        "ip",
                        &[
                            "link".into(),
                            "set".into(),
                            "dev".into(),
                            name.clone(),
                            "address".into(),
                            m.clone(),
                        ],
                    )
                    .await?;
                }
                run_checked(
                    "ip",
                    &[
                        "link".into(),
                        "set".into(),
                        "dev".into(),
                        name.clone(),
                        "up".into(),
                    ],
                )
                .await?;
                open_tap_fd(&name).await
            }
            .await;

            match created {
                Ok(fd) => Ok(PreparedNetwork {
                    spec: spec.clone(),
                    tap_name: Some(name),
                    tap_fd: Some(fd),
                    netns: None,
                    dhcp_leasefile: None,
                    guest_ip: None,
                    guest_cidr: None,
                    gateway: None,
                }),
                Err(e) => {
                    let _ = cleanup_macvtap(&name).await;
                    Err(e)
                }
            }
        }
    }
}

/// Host-visible interface where VM-originated traffic enters the host.
/// Namespaced TAP uses the host side of the VM veth; direct TAP/macvtap uses
/// the prepared host device. This is deterministic across stop/start.
pub fn dataplane_interface_name(
    id: Uuid,
    has_netns: bool,
    tap_name: Option<&str>,
) -> Option<String> {
    if has_netns {
        Some(netns::host_veth_name(id))
    } else {
        tap_name.map(str::to_string)
    }
}

pub fn dataplane_interface(id: Uuid, network: &PreparedNetwork) -> Option<String> {
    dataplane_interface_name(id, network.netns.is_some(), network.tap_name.as_deref())
}

/// Opens the macvtap character device (`/dev/tap<ifindex>`) for `name`
/// without O_CLOEXEC, so the fd survives exec into the spawned VMM and can
/// be passed on the command line (`-netdev tap,fd=N` / `--net fd=N`).
async fn open_tap_fd(name: &str) -> Result<i32> {
    let ifindex = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .with_context(|| format!("reading ifindex for {name}"))?;
    let dev_path = format!("/dev/tap{}", ifindex.trim());
    let c_path = CString::new(dev_path.clone()).context("device path contains a NUL byte")?;

    // SAFETY: c_path is a valid, NUL-terminated C string for the lifetime of
    // this call; libc::open with O_RDWR only (no O_CLOEXEC) is what makes
    // this fd inheritable by the child VMM process across fork+exec.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        bail!("opening {dev_path}: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Dispatches cleanup of the ephemeral network device recorded for a VM,
/// based on which kind it is (TAP vs. macvtap use different deletion
/// commands).
pub async fn cleanup(
    state_dir: &std::path::Path,
    id: Uuid,
    spec: &NetworkSpec,
    tap_name: &str,
    netns_name: Option<&str>,
) -> Result<()> {
    // Config-aware scheduler paths already remove native pins. This fallback
    // catches default-path state after partial failures/crashes.
    let _ = dataplane::remove_sandbox_policy_best_effort(id);
    if let Some(iface) = dataplane_interface_name(id, netns_name.is_some(), Some(tap_name)) {
        service::remove_for_vm_best_effort(id, &iface);
    }

    // Deleting the namespace tears down everything inside it (the tap
    // included) — no separate tap cleanup needed, and calling
    // cleanup_tap/cleanup_macvtap for a namespaced tap would fail anyway
    // (it doesn't exist in the host's own namespace to delete).
    if let Some(ns) = netns_name {
        return netns::cleanup(state_dir, id, ns).await;
    }
    match spec {
        NetworkSpec::Macvtap { .. } => cleanup_macvtap(tap_name).await,
        NetworkSpec::Tap {
            direct: Some(direct),
            ..
        } => {
            direct::cleanup(tap_name, direct).await;
            // Host-namespace direct taps are persistent like bridged ones.
            if direct.netns_path.is_none() {
                cleanup_tap(tap_name).await?;
            }
            Ok(())
        }
        NetworkSpec::Tap { extra, .. } => {
            cleanup_tap(tap_name).await?;
            for nic in extra {
                if let Some(name) = &nic.tap_name {
                    cleanup_tap(name).await?;
                }
            }
            Ok(())
        }
        _ => cleanup_tap(tap_name).await,
    }
}

/// Create a TAP and enslave it to `bridge`. Used for Multus extras and
/// post-claim NIC hotplug.
pub async fn add_bridge_tap(tap: &str, bridge: &str) -> Result<()> {
    if tap.len() > 15 {
        bail!("tap interface name must be <= 15 characters");
    }
    if bridge.is_empty() || bridge.len() > 15 {
        bail!("bridge name must be 1..=15 characters");
    }
    create_tap(tap).await?;
    if let Err(e) = set_master(tap, bridge).await {
        let _ = cleanup_tap(tap).await;
        return Err(e);
    }
    Ok(())
}

pub(crate) async fn create_tap(tap: &str) -> Result<()> {
    run_checked(
        "ip",
        &[
            "tuntap".into(),
            "add".into(),
            "dev".into(),
            tap.into(),
            "mode".into(),
            "tap".into(),
        ],
    )
    .await?;
    run_checked(
        "ip",
        &[
            "link".into(),
            "set".into(),
            "dev".into(),
            tap.into(),
            "up".into(),
        ],
    )
    .await?;
    Ok(())
}

async fn set_master(tap: &str, bridge: &str) -> Result<()> {
    run_checked(
        "ip",
        &[
            "link".into(),
            "set".into(),
            tap.into(),
            "master".into(),
            bridge.into(),
        ],
    )
    .await
}

pub async fn cleanup_tap(tap: &str) -> Result<()> {
    let _ = run_checked(
        "ip",
        &[
            "link".into(),
            "set".into(),
            "dev".into(),
            tap.into(),
            "down".into(),
        ],
    )
    .await;
    let _ = run_checked(
        "ip",
        &[
            "tuntap".into(),
            "del".into(),
            "dev".into(),
            tap.into(),
            "mode".into(),
            "tap".into(),
        ],
    )
    .await;
    Ok(())
}

pub async fn cleanup_macvtap(name: &str) -> Result<()> {
    let _ = run_checked("ip", &["link".into(), "del".into(), name.into()]).await;
    Ok(())
}
