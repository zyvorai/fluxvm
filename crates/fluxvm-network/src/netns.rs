// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Per-VM network namespaces: real isolation (separate routing table,
//! nftables, interface list — not just a shared L2 segment like the
//! tap-on-a-shared-bridge mode), built from a veth pair (host <-> namespace)
//! NATed to the host's own connectivity, plus a small internal bridge
//! inside the namespace joining the veth's namespace end to the VM's own
//! tap device. A per-namespace `dnsmasq` DHCP server on that bridge hands
//! the guest a real, usable address -- see `guest_ip_from_lease`.
//!
//! Topology (host on the left, the VM's namespace on the right):
//!
//! ```text
//!   host default netns                    │  VM's netns
//!                                          │
//!   <vethh> 169.254.X.1/28  <───veth pair───>  <vethn> ── <br> ── <tap> ── VM
//!        │                                │       169.254.X.2/28 on <br>
//!   nftables MASQUERADE                   │       dnsmasq DHCP serves
//!   (POSTROUTING -s 169.254.X.0/28)       │       169.254.X.3-.14 on <br>
//!                                         │       default route via 169.254.X.1
//! ```
//!
//! Subnet blocks are allocated from `state_dir/ipam.json` (4096 /28 slots in
//! 169.254.0.0/16) rather than derived from the VM UUID hash.

use crate::{dataplane, ipam::IpamStore};
use anyhow::{Context, Result};
use fluxvm_core::process::run_checked;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct NetnsHandle {
    pub netns: String,
    pub tap_name: String,
    pub dhcp_leasefile: PathBuf,
    /// The guest's reserved address (bare IP, e.g. "169.254.12.35") --
    /// always base+3 of the /28, pinned to the guest's MAC via dnsmasq's
    /// `--dhcp-host`, so it's known and stable from the moment the
    /// namespace is created rather than only after the guest actually
    /// completes a DHCP handshake.
    pub guest_ip: String,
    /// `guest_ip` with the /28 prefix, e.g. "169.254.12.35/28" -- what a
    /// static (non-DHCP) guest network-config needs.
    pub guest_cidr: String,
    /// The namespace's gateway address (base+1) -- what a static guest
    /// network-config's route needs.
    pub gateway: String,
}

fn short_id(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// Host-visible side of this VM's namespace veth pair. Public so the
/// dataplane can attach TC/eBPF without persisting another piece of state.
pub fn host_veth_name(id: Uuid) -> String {
    format!("vh{}", short_id(id))
}

fn nft_table_name(short: &str) -> String {
    format!("fluxvm_netns_{short}")
}

fn subnet_from_octets(third: u8, base: u8) -> String {
    format!("169.254.{third}.{base}/28")
}

/// Where this namespace's dnsmasq state (lease file, log, pidfile) lives --
/// public so callers can derive the lease file path from just a namespace
/// name (e.g. `VmRecord.netns`) without needing to separately persist it.
pub fn dhcp_dir(netns: &str) -> PathBuf {
    // Under /run/fluxvm, not a new top-level /run dir: that's the one
    // path this crate can already write to under fluxvm.service's
    // ProtectSystem=strict + ReadWritePaths hardening (see the service
    // unit) -- a sibling /run/fluxvm-netns-dhcp would need its own
    // ReadWritePaths entry for no real benefit.
    PathBuf::from("/run/fluxvm/netns-dhcp").join(netns)
}

/// Path to this namespace's DHCP lease file — see [`guest_ip_from_lease`].
pub fn leasefile_path(netns: &str) -> PathBuf {
    dhcp_dir(netns).join("leases")
}

/// Creates the namespace, veth pair, internal bridge, and tap device
/// described in the module doc, and wires up NAT so the VM can reach
/// outbound. Best-effort torn down (via `cleanup`) if any step fails partway
/// through.
pub async fn prepare(state_dir: &Path, id: Uuid, mac: Option<&str>) -> Result<NetnsHandle> {
    // A known MAC is what lets the guest's address be pinned (dnsmasq
    // --dhcp-host) and therefore known deterministically -- without one
    // there's nothing to reserve the address against.
    let mac = mac.context("netns networking requires an explicit MAC address")?;
    let short = short_id(id);
    let netns = format!("eph-{short}");
    let veth_host = host_veth_name(id);
    let veth_ns = format!("vn{short}");
    let bridge = format!("br{short}");
    let tap = format!("tap{short}");
    let state_dir_buf = state_dir.to_path_buf();
    let state_dir_ipam = state_dir_buf.clone();
    let (third, base) =
        tokio::task::spawn_blocking(move || IpamStore::load(&state_dir_ipam).allocate(id))
            .await
            .context("ipam allocate worker panicked")??;
    let host_ip = format!("169.254.{third}.{}/28", base + 1);
    let ns_ip = format!("169.254.{third}.{}/28", base + 2);
    let ns_subnet = subnet_from_octets(third, base);
    let gateway = format!("169.254.{third}.{}", base + 1);
    let guest_ip = format!("169.254.{third}.{}", base + 3);
    let guest_cidr = format!("{guest_ip}/28");
    let dhcp_range_start = guest_ip.clone();
    let dhcp_range_end = format!("169.254.{third}.{}", base + 14);
    let dhcp_dir = dhcp_dir(&netns);
    let dhcp_leasefile = dhcp_dir.join("leases");
    let nft_table = nft_table_name(&short);

    let result: Result<()> = async {
        run_checked("ip", &["netns".into(), "add".into(), netns.clone()])
            .await
            .context("creating network namespace")?;
        run_checked(
            "ip",
            &[
                "link".into(),
                "add".into(),
                veth_host.clone(),
                "type".into(),
                "veth".into(),
                "peer".into(),
                "name".into(),
                veth_ns.clone(),
            ],
        )
        .await
        .context("creating veth pair")?;
        run_checked(
            "ip",
            &[
                "link".into(),
                "set".into(),
                veth_ns.clone(),
                "netns".into(),
                netns.clone(),
            ],
        )
        .await
        .context("moving veth namespace-end into the namespace")?;
        run_checked(
            "ip",
            &[
                "addr".into(),
                "add".into(),
                host_ip,
                "dev".into(),
                veth_host.clone(),
            ],
        )
        .await
        .context("assigning host-end veth address")?;
        run_checked(
            "ip",
            &["link".into(), "set".into(), veth_host.clone(), "up".into()],
        )
        .await
        .context("bringing up host-end veth")?;

        // Everything from here on runs inside the namespace via `ip netns
        // exec <ns> ip ...` — note the second `ip`: `ip netns exec` runs an
        // arbitrary command line inside the namespace, it doesn't assume
        // that command is `ip` itself, so the program name has to be
        // supplied again as part of the wrapped args.
        let in_ns = |args: Vec<String>| {
            let mut full = vec![
                "netns".to_string(),
                "exec".to_string(),
                netns.clone(),
                "ip".to_string(),
            ];
            full.extend(args);
            full
        };
        run_checked(
            "ip",
            &in_ns(vec!["link".into(), "set".into(), "lo".into(), "up".into()]),
        )
        .await
        .context("bringing up loopback in namespace")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "link".into(),
                "add".into(),
                bridge.clone(),
                "type".into(),
                "bridge".into(),
            ]),
        )
        .await
        .context("creating internal bridge in namespace")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "link".into(),
                "set".into(),
                veth_ns.clone(),
                "master".into(),
                bridge.clone(),
            ]),
        )
        .await
        .context("attaching veth namespace-end to internal bridge")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "tuntap".into(),
                "add".into(),
                "dev".into(),
                tap.clone(),
                "mode".into(),
                "tap".into(),
            ]),
        )
        .await
        .context("creating tap device in namespace")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                tap.clone(),
                "address".into(),
                mac.to_string(),
            ]),
        )
        .await
        .context("setting tap MAC address")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "link".into(),
                "set".into(),
                tap.clone(),
                "master".into(),
                bridge.clone(),
            ]),
        )
        .await
        .context("attaching tap to internal bridge")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "addr".into(),
                "add".into(),
                ns_ip,
                "dev".into(),
                bridge.clone(),
            ]),
        )
        .await
        .context("assigning internal bridge address")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "link".into(),
                "set".into(),
                veth_ns.clone(),
                "up".into(),
            ]),
        )
        .await
        .context("bringing up veth namespace-end")?;
        run_checked(
            "ip",
            &in_ns(vec!["link".into(), "set".into(), tap.clone(), "up".into()]),
        )
        .await
        .context("bringing up tap")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "link".into(),
                "set".into(),
                bridge.clone(),
                "up".into(),
            ]),
        )
        .await
        .context("bringing up internal bridge")?;
        run_checked(
            "ip",
            &in_ns(vec![
                "route".into(),
                "add".into(),
                "default".into(),
                "via".into(),
                gateway.clone(),
            ]),
        )
        .await
        .context("adding default route in namespace")?;

        // Host-level: allow the namespace to reach the outside world.
        run_checked("sysctl", &["-w".into(), "net.ipv4.ip_forward=1".into()])
            .await
            .context("enabling IP forwarding")?;
        dataplane::apply_subnet_masquerade(&nft_table, &ns_subnet)
            .context("adding NAT masquerade rule")?;

        // Give the guest (via tap -> bridge) a real, usable address: a
        // dnsmasq DHCP server bound only to this namespace's bridge
        // (--bind-interfaces keeps it off the wildcard :67/:53 sockets, so
        // it can't collide with any other DHCP/DNS server already running
        // on the host in the default namespace). --server= pins upstream
        // DNS explicitly since this namespace has no /etc/resolv.conf of
        // its own to forward against.
        std::fs::create_dir_all(&dhcp_dir).context("creating dnsmasq state dir")?;
        let dnsmasq_log = dhcp_dir.join("dnsmasq.log");
        let child = fluxvm_core::process::spawn_logged(
            "ip",
            &[
                "netns".into(),
                "exec".into(),
                netns.clone(),
                "dnsmasq".into(),
                "--no-daemon".into(),
                format!("--interface={bridge}"),
                "--bind-interfaces".into(),
                "--except-interface=lo".into(),
                format!("--dhcp-range={dhcp_range_start},{dhcp_range_end},1h"),
                // Pins this MAC to guest_ip specifically, rather than
                // "whichever free address it asks for first" -- makes the
                // address deterministic and known (see NetnsHandle.guest_ip)
                // from the moment the namespace exists, not only after the
                // guest actually completes a DHCP handshake.
                format!("--dhcp-host={mac},{guest_ip}"),
                format!("--dhcp-leasefile={}", dhcp_leasefile.display()),
                "--server=1.1.1.1".into(),
                "--server=8.8.8.8".into(),
            ],
            &dnsmasq_log,
        )
        .await
        .context("spawning dnsmasq DHCP server")?;
        let dnsmasq_pid = child.id().context("dnsmasq exited immediately")?;
        std::fs::write(dhcp_dir.join("dnsmasq.pid"), dnsmasq_pid.to_string())
            .context("recording dnsmasq pid")?;
        // spawn_logged detaches the process into its own process group
        // (see its doc comment) — it's meant to outlive this call, so drop
        // the handle without waiting on it, same as every other
        // long-running process this crate launches this way.
        drop(child);

        Ok(())
    }
    .await;

    match result {
        Ok(()) => Ok(NetnsHandle {
            netns,
            tap_name: tap,
            dhcp_leasefile,
            guest_ip,
            guest_cidr,
            gateway,
        }),
        Err(e) => {
            let _ = cleanup(&state_dir_buf, id, &netns).await;
            Err(e)
        }
    }
}

/// Deletes the namespace (which cascades: every interface inside it,
/// including the veth namespace-end and — since deleting either end of a
/// veth pair deletes both — the host-side veth end too) and removes the
/// nftables NAT table plus the ipam allocation. Best-effort: logs nothing on
/// its own, callers already log/ignore per the existing
/// `cleanup_tap`/`cleanup_macvtap` convention.
///
/// dnsmasq is killed explicitly *before* deleting the namespace: `ip netns
/// del` only removes the `/var/run/netns/<name>` handle, it doesn't touch
/// processes that still hold the namespace open (found live -- a namespace
/// with a still-running dnsmasq inside it survives its own deletion as a
/// nameless orphan, leaking every interface and the DHCP server along with
/// it, until that process is killed some other way).
pub async fn cleanup(state_dir: &Path, id: Uuid, netns: &str) -> Result<()> {
    let nft_table = nft_table_name(&short_id(id));
    let dir = dhcp_dir(netns);
    if let Ok(pid_str) = std::fs::read_to_string(dir.join("dnsmasq.pid")) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            let _ = fluxvm_core::process::terminate_pid(pid).await;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = dataplane::remove_nft_table(&nft_table);
    let state_dir = state_dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || IpamStore::load(&state_dir).release(id))
        .await
        .context("ipam release worker panicked")?;
    let _ = run_checked("ip", &["netns".into(), "del".into(), netns.into()]).await;
    Ok(())
}

/// Looks up the guest's current DHCP-leased IP by MAC address from a
/// dnsmasq lease file (`<timestamp> <mac> <ip> <hostname> <client-id>` per
/// line, one per active lease). Returns `None` if the file doesn't exist
/// yet (guest hasn't completed a DHCP handshake), the MAC has no current
/// lease, or the file can't be read -- all treated as "not known yet"
/// rather than an error, since this is polled repeatedly until the guest
/// boots far enough to request an address.
pub fn guest_ip_from_lease(leasefile: &std::path::Path, mac: &str) -> Option<String> {
    let contents = std::fs::read_to_string(leasefile).ok()?;
    let mac = mac.to_ascii_lowercase();
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let _timestamp = fields.next()?;
        let lease_mac = fields.next()?;
        let ip = fields.next()?;
        if lease_mac.eq_ignore_ascii_case(&mac) {
            Some(ip.to_string())
        } else {
            None
        }
    })
}
