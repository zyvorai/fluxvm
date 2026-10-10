// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Private networks between `vz` guests: addresses, MACs, and the `fluxvm-vz-switch` process behind each network.

use anyhow::{Context, Result, bail};
use fluxvm_core::model::AppleNetwork;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

/// Networks are `10.89.N.0/24`, one `N` per network name.
const BASE: [u8; 2] = [10, 89];
pub const PREFIX_LEN: u8 = 24;
/// How many private networks one guest may join.
pub const MAX_PER_VM: usize = 4;

pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `10.89.N.H/24` -> (N, H).
fn parse_address(a: &str) -> Result<(u8, u8)> {
    let (ip, len) = a
        .split_once('/')
        .with_context(|| format!("network address {a:?} must be IP/24"))?;
    let ip: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("network address {a:?}"))?;
    if len != PREFIX_LEN.to_string() {
        bail!("network address {a:?} must be a /{PREFIX_LEN}");
    }
    let o = ip.octets();
    if o[..2] != BASE || !(2..=254).contains(&o[3]) {
        bail!(
            "network address {a:?} must be in {}.{}.0.0/16 with a host part of 2-254",
            BASE[0],
            BASE[1]
        );
    }
    Ok((o[2], o[3]))
}

fn format_address(n: u8, h: u8) -> String {
    format!("{}.{}.{n}.{h}/{PREFIX_LEN}", BASE[0], BASE[1])
}

/// Checks a request's networks before anything is assigned.
pub fn validate(networks: &[AppleNetwork]) -> Result<()> {
    if networks.len() > MAX_PER_VM {
        bail!("at most {MAX_PER_VM} networks per VM");
    }
    let mut seen = BTreeSet::new();
    for n in networks {
        if !valid_name(&n.name) {
            bail!(
                "network name {:?}: use a-z, 0-9 and -, at most 40 characters",
                n.name
            );
        }
        if !seen.insert(&n.name) {
            bail!("network {:?} is listed twice", n.name);
        }
        if let Some(a) = &n.address {
            parse_address(a)?;
        }
        if let Some(m) = &n.mac
            && fluxvm_vz_switch::parse_mac(m).is_none()
        {
            bail!(
                "network {:?}: MAC {m:?} must be a unicast aa:bb:cc:dd:ee:ff",
                n.name
            );
        }
    }
    Ok(())
}

/// Fills in each network's `address` and `mac`. `existing` are the networks of the VMs that already exist.
pub fn assign(networks: &mut [AppleNetwork], existing: &[AppleNetwork]) -> Result<()> {
    validate(networks)?;
    // Subnet of each network, and the hosts and MACs in use.
    let mut subnet: BTreeMap<&str, u8> = BTreeMap::new();
    let mut used: BTreeSet<(u8, u8)> = BTreeSet::new();
    let mut macs: BTreeSet<String> = BTreeSet::new();
    for e in existing {
        if let Some(Ok((n, h))) = e.address.as_deref().map(parse_address) {
            subnet.entry(&e.name).or_insert(n);
            used.insert((n, h));
        }
        if let Some(m) = &e.mac {
            macs.insert(m.to_ascii_lowercase());
        }
    }
    let mut new_subnets: BTreeMap<String, u8> = BTreeMap::new();
    for net in networks.iter_mut() {
        let n = match subnet.get(net.name.as_str()).or(new_subnets.get(&net.name)) {
            Some(n) => *n,
            None => {
                let taken: BTreeSet<u8> = subnet
                    .values()
                    .chain(new_subnets.values())
                    .copied()
                    .collect();
                let n = match &net.address {
                    Some(a) => parse_address(a)?.0,
                    None => (0..=255u8)
                        .find(|n| !taken.contains(n))
                        .context("all 256 private networks are in use")?,
                };
                if taken.contains(&n) {
                    bail!(
                        "network {:?}: {} belongs to another network",
                        net.name,
                        format_address(n, 0)
                    );
                }
                new_subnets.insert(net.name.clone(), n);
                n
            }
        };
        let h = match &net.address {
            Some(a) => {
                let (an, h) = parse_address(a)?;
                if an != n {
                    bail!(
                        "network {:?} is {}, so {a} is not in it",
                        net.name,
                        format_address(n, 0)
                    );
                }
                if used.contains(&(n, h)) {
                    bail!("network {:?}: {a} is already in use", net.name);
                }
                h
            }
            None => (2..=254u8)
                .find(|h| !used.contains(&(n, *h)))
                .with_context(|| format!("network {:?} is full", net.name))?,
        };
        used.insert((n, h));
        net.address = Some(format_address(n, h));
        match &net.mac {
            Some(m) if macs.contains(&m.to_ascii_lowercase()) => {
                bail!("network {:?}: MAC {m} is already in use", net.name)
            }
            Some(m) => {
                macs.insert(m.to_ascii_lowercase());
            }
            None => loop {
                let b = *uuid::Uuid::new_v4().as_bytes();
                let m = format!(
                    "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    b[0], b[1], b[2], b[3], b[4]
                );
                if macs.insert(m.clone()) {
                    net.mac = Some(m);
                    break;
                }
            },
        }
    }
    Ok(())
}

/// The IP part of an assigned address.
pub fn ip_of(net: &AppleNetwork) -> Option<Ipv4Addr> {
    net.address.as_deref()?.split('/').next()?.parse().ok()
}

/// The switch's socket. Short, because Unix socket paths are limited to 104 bytes on macOS.
pub fn socket_path(name: &str) -> Result<PathBuf> {
    Ok(crate::runner::socket_dir()?.join(format!("vznet-{name}.sock")))
}

pub fn find_switch() -> Result<PathBuf> {
    let mut tried = Vec::new();
    if let Some(p) = std::env::var_os("FLUXVM_VZ_SWITCH") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        tried.push(p);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        // `cargo test` binaries live one level below the built binaries, in `deps/`.
        for d in [Some(dir), dir.parent()].into_iter().flatten() {
            let p = d.join("fluxvm-vz-switch");
            if p.is_file() {
                return Ok(p);
            }
            tried.push(p);
        }
    }
    bail!(
        "fluxvm-vz-switch not found (tried {}); install it next to fluxctl or set FLUXVM_VZ_SWITCH",
        tried
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Starts the switch for `name` unless it is already running. It exits by itself once no guest has used it for 30 s.
pub async fn ensure_switch(name: &str) -> Result<PathBuf> {
    let socket = socket_path(name)?;
    if tokio::net::UnixStream::connect(&socket).await.is_ok() {
        return Ok(socket);
    }
    let bin = find_switch()?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(socket.with_extension("log"))
        .context("opening the switch log")?;
    let mut child = tokio::process::Command::new(&bin)
        .arg("--socket")
        .arg(&socket)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            // It runs on after this process; reap it if it exits while we are still here.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            return Ok(socket);
        }
        if let Ok(Some(status)) = child.try_wait() {
            // A switch started at the same moment by another launch may have won the socket.
            if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                return Ok(socket);
            }
            bail!("the switch for network {name} exited ({status})");
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.start_kill();
            bail!("the switch for network {name} did not start");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The cloud-init `write_files` (path, content, mode) and `runcmd` that give a full VM guest its private addresses: a
/// systemd-networkd unit per card, and a oneshot service that sets the same addresses with `ip` for guests that do not
/// use networkd (and on every boot, since `runcmd` only runs on the first).
pub fn cloud_init(networks: &[AppleNetwork]) -> (Vec<(String, String, String)>, Vec<String>) {
    let mut files = Vec::new();
    let mut script = String::from(
        "#!/bin/sh\n# Written by FluxVM: private network addresses, matched by MAC.\nset -u\nup() {\n  for d in /sys/class/net/*; do\n    [ \"$(cat \"$d/address\" 2>/dev/null)\" = \"$1\" ] || continue\n    ip link set \"${d##*/}\" up && ip addr replace \"$2\" dev \"${d##*/}\"\n  done\n}\n",
    );
    for net in networks {
        let (Some(mac), Some(address)) = (net.mac.as_deref(), net.address.as_deref()) else {
            continue;
        };
        files.push((
            format!("/etc/systemd/network/10-fluxvm-{}.network", net.name),
            format!(
                "[Match]\nMACAddress={mac}\n\n[Network]\nAddress={address}\nLinkLocalAddressing=no\nIPv6AcceptRA=no\n"
            ),
            "0644".to_string(),
        ));
        script.push_str(&format!("up {mac} {address}\n"));
    }
    if files.is_empty() {
        return (files, Vec::new());
    }
    files.push(("/usr/local/sbin/fluxvm-vznet".into(), script, "0755".into()));
    files.push((
        "/etc/systemd/system/fluxvm-vznet.service".into(),
        "[Unit]\nDescription=FluxVM private networks\nAfter=network.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/sbin/fluxvm-vznet\n\n[Install]\nWantedBy=multi-user.target\n".into(),
        "0644".into(),
    ));
    let runcmd = vec![
        "networkctl reload 2>/dev/null || true".into(),
        "systemctl daemon-reload && systemctl enable --now fluxvm-vznet.service || /usr/local/sbin/fluxvm-vznet".into(),
    ];
    (files, runcmd)
}

/// One private network as `GET /v1/vznets` reports it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct NetworkSummary {
    pub name: String,
    /// `10.89.N.0/24`.
    pub subnet: String,
    pub members: Vec<Member>,
    /// Whether its switch process is up (it exits on its own 30 s after the last guest leaves).
    pub switch_running: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Member {
    pub vm_id: uuid::Uuid,
    pub vm_name: String,
    pub address: String,
    pub mac: String,
    pub status: String,
}

/// The networks used by `vms` (id, name, status, networks), by name.
pub fn summarize<'a>(
    vms: impl IntoIterator<Item = (uuid::Uuid, &'a str, String, &'a [AppleNetwork])>,
) -> Vec<NetworkSummary> {
    let mut by_name: BTreeMap<String, NetworkSummary> = BTreeMap::new();
    for (id, vm_name, status, nets) in vms {
        for n in nets {
            let (Some(address), Some(mac)) = (n.address.clone(), n.mac.clone()) else {
                continue;
            };
            let Ok((subnet, _)) = parse_address(&address) else {
                continue;
            };
            let entry = by_name
                .entry(n.name.clone())
                .or_insert_with(|| NetworkSummary {
                    name: n.name.clone(),
                    subnet: format!("{}.{}.{subnet}.0/{PREFIX_LEN}", BASE[0], BASE[1]),
                    members: Vec::new(),
                    switch_running: false,
                });
            entry.members.push(Member {
                vm_id: id,
                vm_name: vm_name.to_string(),
                address,
                mac,
                status: status.clone(),
            });
        }
    }
    let mut out: Vec<_> = by_name.into_values().collect();
    for n in &mut out {
        n.members.sort_by(|a, b| a.address.cmp(&b.address));
        n.switch_running = socket_path(&n.name)
            .map(|p| std::os::unix::net::UnixStream::connect(p).is_ok())
            .unwrap_or(false);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(name: &str) -> AppleNetwork {
        AppleNetwork {
            name: name.into(),
            address: None,
            mac: None,
        }
    }

    #[test]
    fn each_network_gets_its_own_subnet_and_each_guest_its_own_host() {
        let mut a = vec![net("shop"), net("lab")];
        assign(&mut a, &[]).unwrap();
        assert_eq!(a[0].address.as_deref(), Some("10.89.0.2/24"));
        assert_eq!(a[1].address.as_deref(), Some("10.89.1.2/24"));
        assert!(fluxvm_vz_switch::parse_mac(a[0].mac.as_deref().unwrap()).is_some());

        let mut b = vec![net("shop")];
        assign(&mut b, &a).unwrap();
        assert_eq!(b[0].address.as_deref(), Some("10.89.0.3/24"));
        assert_ne!(b[0].mac, a[0].mac);

        let existing: Vec<_> = a.iter().chain(&b).cloned().collect();
        let mut c = vec![net("new")];
        assign(&mut c, &existing).unwrap();
        assert_eq!(c[0].address.as_deref(), Some("10.89.2.2/24"));
    }

    #[test]
    fn requested_addresses_must_fit_and_be_free() {
        let mut a = vec![AppleNetwork {
            address: Some("10.89.7.10/24".into()),
            ..net("shop")
        }];
        assign(&mut a, &[]).unwrap();
        assert_eq!(a[0].address.as_deref(), Some("10.89.7.10/24"));
        let mut same = a.clone();
        same[0].mac = None;
        assert!(
            assign(&mut same, &a)
                .unwrap_err()
                .to_string()
                .contains("in use")
        );
        let mut wrong_subnet = vec![AppleNetwork {
            address: Some("10.89.8.10/24".into()),
            ..net("shop")
        }];
        assert!(
            assign(&mut wrong_subnet, &a)
                .unwrap_err()
                .to_string()
                .contains("not in it")
        );
        let mut other_net = vec![AppleNetwork {
            address: Some("10.89.7.11/24".into()),
            ..net("lab")
        }];
        assert!(
            assign(&mut other_net, &a)
                .unwrap_err()
                .to_string()
                .contains("another network")
        );
        for bad in [
            "10.88.0.2/24",
            "10.89.0.1/24",
            "10.89.0.255/24",
            "10.89.0.2/16",
            "10.89.0.2",
        ] {
            let mut n = vec![AppleNetwork {
                address: Some(bad.into()),
                ..net("x")
            }];
            assert!(assign(&mut n, &[]).is_err(), "{bad}");
        }
    }

    #[test]
    fn names_count_and_macs_are_checked() {
        assert!(validate(&[net("Bad")]).is_err());
        assert!(validate(&[net("a"), net("a")]).is_err());
        assert!(validate(&(0..5).map(|i| net(&format!("n{i}"))).collect::<Vec<_>>()).is_err());
        let multicast = AppleNetwork {
            mac: Some("01:00:5e:00:00:01".into()),
            ..net("a")
        };
        assert!(validate(&[multicast]).is_err());
    }

    #[test]
    fn full_vm_guests_get_a_networkd_unit_and_a_fallback_script() {
        let mut a = vec![net("shop")];
        assign(&mut a, &[]).unwrap();
        let mac = a[0].mac.clone().unwrap();
        let (files, runcmd) = cloud_init(&a);
        let unit = files
            .iter()
            .find(|f| f.0 == "/etc/systemd/network/10-fluxvm-shop.network")
            .unwrap();
        assert!(unit.1.contains(&format!("MACAddress={mac}")));
        assert!(unit.1.contains("Address=10.89.0.2/24"));
        let script = files
            .iter()
            .find(|f| f.0 == "/usr/local/sbin/fluxvm-vznet")
            .unwrap();
        assert!(script.1.contains(&format!("up {mac} 10.89.0.2/24")));
        assert_eq!(script.2, "0755");
        assert!(runcmd.iter().any(|c| c.contains("fluxvm-vznet.service")));
        assert!(cloud_init(&[net("unassigned")]).0.is_empty());
    }

    #[test]
    fn summaries_group_members_by_network() {
        let mut a = vec![net("shop")];
        assign(&mut a, &[]).unwrap();
        let mut b = vec![net("shop"), net("lab")];
        assign(&mut b, &a).unwrap();
        let (ia, ib) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let s = summarize([
            (ia, "a", "running".to_string(), a.as_slice()),
            (ib, "b", "stopped".to_string(), b.as_slice()),
        ]);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, "lab");
        assert_eq!(s[1].subnet, "10.89.0.0/24");
        assert_eq!(
            s[1].members
                .iter()
                .map(|m| m.vm_name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }
}
