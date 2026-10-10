// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

mod bpf_map;
pub mod cilium;
pub mod cnp;
pub mod dataplane;
pub mod direct;
pub mod ebpf;
pub mod edge_capture;
pub mod edge_contract;
pub mod edge_qos;
pub mod egress;
pub mod egress_proxy;
pub mod endpoint;
pub mod groups;
pub mod http_acl;
pub mod identity;
pub mod ipam;
pub mod ipcache;
pub mod ipv6_ext_walk;
pub mod migration_state;
pub mod netns;
pub mod netns_scope;
pub mod packetflow;
pub mod pod_identity;
pub mod qemu_cgroup;
pub mod service;
pub mod service_ha;
pub mod service_policy;
pub mod service_pressure;
mod store;
pub mod tcx;
pub mod tls_intercept;
pub mod transparent_redirect;
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
            extra_tap_fds: Vec::new(),
        }),
        NetworkSpec::Tap {
            tap_name,
            bridge,
            mac,
            extra,
            netns: use_netns,
            ..
        } if *use_netns => {
            // Extra NICs are host-bridge taps; the VMM runs inside the netns and
            // takes them as inherited fds (QEMU only; the scheduler refuses the rest).
            let (prepared_extra, extra_fds) = prepare_netns_extras(id, extra).await?;
            let handle = match netns::prepare(&cfg.state_dir, id, mac.as_deref()).await {
                Ok(h) => h,
                Err(e) => {
                    release_extras(&prepared_extra, &extra_fds).await;
                    return Err(e).context("preparing network namespace");
                }
            };
            Ok(PreparedNetwork {
                spec: NetworkSpec::Tap {
                    tap_name: Some(handle.tap_name.clone()),
                    bridge: bridge.clone(),
                    mac: mac.clone(),
                    netns: true,
                    extra: prepared_extra,
                    direct: None,
                },
                tap_name: Some(handle.tap_name),
                tap_fd: None,
                netns: Some(handle.netns),
                dhcp_leasefile: Some(handle.dhcp_leasefile),
                guest_ip: Some(handle.guest_ip),
                guest_cidr: Some(handle.guest_cidr),
                gateway: Some(handle.gateway),
                extra_tap_fds: extra_fds,
            })
        }
        NetworkSpec::Tap {
            tap_name,
            mac,
            direct: Some(direct),
            extra,
            ..
        } => {
            let tap = tap_name
                .clone()
                .unwrap_or_else(|| format!("eph{}", &id.simple().to_string()[..8]));
            if tap.len() > 15 {
                bail!("tap interface name must be <= 15 characters");
            }
            // The redirect is the ONLY thing forwarding this VM's traffic (there is no bridge
            // to fall back on), and it is installed by the eBPF dataplane. Refuse up front
            // rather than create a tap that can never carry a packet.
            if cfg.sandbox.dataplane.mode == fluxvm_core::config::DataplaneMode::Legacy {
                bail!(
                    "network.direct requires sandbox.dataplane.mode = ebpf or cilium \
                     (the eBPF redirect is the only forwarding path for a bridge-less tap)"
                );
            }
            // An uplink that is a bridge/bond port would have its frames taken by the master
            // before a TC hook sees them, so the redirect would silently never fire.
            if direct.mode == fluxvm_core::model::DirectMode::L2Uplink
                && direct.netns_path.is_none()
                && let Some(why) =
                    direct::uplink_problem(std::path::Path::new("/sys/class/net"), &direct.outer)
            {
                bail!("network.direct: {why}");
            }
            // No set_master and no default_bridge fallback: the whole point is
            // that nothing bridges this tap. A redirect program pairs it with
            // `direct.outer` instead (attached by the dataplane step).
            let made = direct::prepare_tap(&tap, direct)
                .await
                .context("preparing direct (bridge-less) tap")?;
            // Recorded here, not at each call site: create, start, snapshot restore and the
            // periodic reconcile all reach the loader through prepare(), and the loader needs
            // this to re-enter the outer device's netns and re-apply the redirect config.
            let attach = direct::DirectAttach {
                spec: direct.clone(),
                guest_mac: mac.clone(),
                tap_name: None,
            };
            if let Err(e) = direct::record(id, &attach) {
                if let Some(fd) = made.fd {
                    // SAFETY: the fd is ours and has not been handed to a VMM yet.
                    unsafe { libc::close(fd) };
                }
                let _ = cleanup_tap(&tap).await;
                return Err(e).context("recording direct attach");
            }
            // Hybrid / Multus: prepare extra NICs (bridge or per-NIC direct).
            let mut prepared_extra: Vec<ExtraNic> = Vec::with_capacity(extra.len());
            for (i, nic) in extra.iter().enumerate() {
                let etap = nic
                    .tap_name
                    .clone()
                    .unwrap_or_else(|| format!("x{i}{}", &id.simple().to_string()[..7]));
                if etap.len() > 15 {
                    let _ = cleanup_tap(&tap).await;
                    for prev in &prepared_extra {
                        if let Some(name) = &prev.tap_name {
                            let _ = cleanup_tap(name).await;
                        }
                    }
                    bail!("extra tap interface name must be <= 15 characters");
                }
                if let Some(ed) = &nic.direct {
                    let made_extra = match direct::prepare_tap(&etap, ed).await {
                        Ok(m) => m,
                        Err(e) => {
                            let _ = cleanup_tap(&tap).await;
                            for prev in &prepared_extra {
                                if let Some(name) = &prev.tap_name {
                                    let _ = cleanup_tap(name).await;
                                }
                            }
                            return Err(e).context(format!("preparing direct extra NIC {i}"));
                        }
                    };
                    if let Some(fd) = made_extra.fd {
                        // Extra taps are name-based for the VMM (like Multus bridge);
                        // close the spare fd so we do not leak it.
                        unsafe { libc::close(fd) };
                    }
                    let extra_attach = direct::DirectAttach {
                        spec: ed.clone(),
                        guest_mac: nic.mac.clone(),
                        tap_name: Some(etap.clone()),
                    };
                    if let Err(e) = direct::record_extra(id, i, &extra_attach) {
                        let _ = cleanup_tap(&tap).await;
                        let _ = cleanup_tap(&etap).await;
                        for prev in &prepared_extra {
                            if let Some(name) = &prev.tap_name {
                                let _ = cleanup_tap(name).await;
                            }
                        }
                        return Err(e).context("recording direct extra attach");
                    }
                    prepared_extra.push(ExtraNic {
                        bridge: String::new(),
                        mac: nic.mac.clone(),
                        tap_name: Some(etap),
                        direct: Some(ed.clone()),
                    });
                } else {
                    if nic.bridge.is_empty() {
                        let _ = cleanup_tap(&tap).await;
                        for prev in &prepared_extra {
                            if let Some(name) = &prev.tap_name {
                                let _ = cleanup_tap(name).await;
                            }
                        }
                        bail!("extra NIC {i} is missing a bridge");
                    }
                    if let Err(e) = add_bridge_tap(&etap, &nic.bridge).await {
                        let _ = cleanup_tap(&tap).await;
                        for prev in &prepared_extra {
                            if let Some(name) = &prev.tap_name {
                                let _ = cleanup_tap(name).await;
                            }
                        }
                        return Err(e).context("preparing Multus extra NIC on direct primary");
                    }
                    prepared_extra.push(ExtraNic {
                        bridge: nic.bridge.clone(),
                        mac: nic.mac.clone(),
                        tap_name: Some(etap),
                        direct: None,
                    });
                }
            }
            Ok(PreparedNetwork {
                spec: NetworkSpec::Tap {
                    tap_name: Some(tap.clone()),
                    bridge: None,
                    mac: mac.clone(),
                    netns: false,
                    extra: prepared_extra,
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
                extra_tap_fds: Vec::new(),
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

            create_tap(&tap).await?;
            if let Some(br) = &bridge
                && let Err(e) = set_master(&tap, br).await
            {
                let _ = cleanup_tap(&tap).await;
                return Err(e);
            }
            let mut prepared_extra: Vec<ExtraNic> = Vec::with_capacity(extra.len());
            for (i, nic) in extra.iter().enumerate() {
                if is_free_slot(nic) {
                    prepared_extra.push(nic.clone());
                    continue;
                }
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
                    direct: None,
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
                extra_tap_fds: Vec::new(),
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
                    extra_tap_fds: Vec::new(),
                }),
                Err(e) => {
                    let _ = cleanup_macvtap(&name).await;
                    Err(e)
                }
            }
        }
    }
}

/// Host-bridge taps for a netns VM's extra NICs, each with an fd the VMM
/// inherits. Direct (bridge-less) extras aren't supported next to a netns NIC.
async fn prepare_netns_extras(
    id: Uuid,
    extra: &[ExtraNic],
) -> Result<(Vec<ExtraNic>, Vec<Option<i32>>)> {
    let mut prepared: Vec<ExtraNic> = Vec::with_capacity(extra.len());
    let mut fds: Vec<Option<i32>> = Vec::with_capacity(extra.len());
    for (i, nic) in extra.iter().enumerate() {
        if is_free_slot(nic) {
            prepared.push(nic.clone());
            fds.push(None);
            continue;
        }
        match prepare_netns_extra(id, i, nic).await {
            Ok((etap, fd)) => {
                prepared.push(ExtraNic {
                    bridge: nic.bridge.clone(),
                    mac: nic.mac.clone(),
                    tap_name: Some(etap),
                    direct: None,
                });
                fds.push(Some(fd));
            }
            Err(e) => {
                release_extras(&prepared, &fds).await;
                return Err(e);
            }
        }
    }
    Ok((prepared, fds))
}

/// A slot left by an unplug: keeps later NICs on their PCIe ports.
fn is_free_slot(n: &ExtraNic) -> bool {
    n.tap_name.is_none() && n.direct.is_none() && n.bridge.is_empty()
}

fn netns_extra_tap_name(id: Uuid, i: usize, nic: &ExtraNic) -> String {
    nic.tap_name
        .clone()
        .unwrap_or_else(|| format!("x{i}{}", &id.simple().to_string()[..7]))
}

async fn prepare_netns_extra(id: Uuid, i: usize, nic: &ExtraNic) -> Result<(String, i32)> {
    if nic.direct.is_some() {
        bail!("extra NIC {i}: direct NICs need network.netns=false");
    }
    if nic.bridge.is_empty() {
        bail!("extra NIC {i} is missing a bridge");
    }
    let etap = netns_extra_tap_name(id, i, nic);
    if etap.len() > 15 {
        bail!("extra tap interface name must be <= 15 characters");
    }
    add_bridge_tap(&etap, &nic.bridge)
        .await
        .with_context(|| format!("preparing extra NIC {i}"))?;
    match direct::open_host_tap(&etap) {
        Ok(fd) => Ok((etap, fd)),
        Err(e) => {
            let _ = cleanup_tap(&etap).await;
            Err(e)
        }
    }
}

async fn release_extras(extra: &[ExtraNic], fds: &[Option<i32>]) {
    for fd in fds.iter().flatten() {
        fluxvm_core::process::close_fd(*fd);
    }
    for nic in extra {
        if let Some(name) = &nic.tap_name {
            let _ = cleanup_tap(name).await;
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
        // Extra NICs of a netns VM are host-bridge taps outside the namespace.
        if let NetworkSpec::Tap { extra, .. } = spec {
            for (i, nic) in extra.iter().enumerate().filter(|(_, n)| !is_free_slot(n)) {
                let name = netns_extra_tap_name(id, i, nic);
                if let Err(e) = cleanup_tap(&name).await {
                    tracing::warn!(tap = name, "removing extra NIC tap failed: {e:#}");
                }
            }
        }
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
