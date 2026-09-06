// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Optional standalone-node XDP guard.
//!
//! Disabled in Cilium coexistence mode because Cilium may itself own XDP on
//! the physical interface. FluxVM records the program ID it attached and
//! refuses to detach/replace anything it cannot prove is FluxVM-owned.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::{DataplaneConfig, DataplaneMode, XdpConfig};
use serde_json::Value;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    process::{Command, Stdio},
};
use tracing::info;

#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6Cidr {
    network: Ipv6Addr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy)]
enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

/// Idempotently establish the configured XDP guard.
///
/// - disabling XDP removes only a previously FluxVM-owned attachment;
/// - switching to Cilium removes a prior FluxVM XDP attachment before
///   refusing standalone XDP mode;
/// - a healthy FluxVM attachment is reconfigured in place without detach;
/// - third-party XDP is never replaced or detached.
pub fn ensure(cfg: &DataplaneConfig) -> Result<()> {
    if !cfg.xdp.enabled {
        return remove(&cfg.xdp);
    }
    if cfg.mode == DataplaneMode::Cilium {
        let _ = remove(&cfg.xdp);
        bail!(
            "FluxVM XDP guard is disabled in dataplane.mode=cilium to avoid replacing Cilium XDP; use Cilium's node XDP features instead"
        );
    }

    let xdp = &cfg.xdp;
    let iface = xdp
        .interface
        .as_deref()
        .context("xdp.enabled=true requires xdp.interface")?;
    validate_block_cidrs(&xdp.block_cidrs)?;
    require_bpftool()?;
    require_ip()?;

    if attachment_is_ours(xdp, iface)? {
        reconfigure_maps(xdp)?;
        info!(%iface, blocks = xdp.block_cidrs.len(), "reconfigured existing FluxVM XDP guard in place");
        return Ok(());
    }

    apply(xdp)
}

pub fn apply(cfg: &XdpConfig) -> Result<()> {
    let iface = cfg
        .interface
        .as_deref()
        .context("xdp.enabled=true requires xdp.interface")?;
    if !cfg.bpf_object.exists() {
        bail!("XDP object does not exist at {}", cfg.bpf_object.display());
    }
    validate_block_cidrs(&cfg.block_cidrs)?;
    require_bpftool()?;
    require_ip()?;
    crate::ebpf::raise_memlock()?;

    // Remove only our own prior attachment (identified by state markers),
    // then refuse to stomp on any remaining external XDP program.
    let _ = remove(cfg);
    if interface_xdp_state(iface)?.0 {
        bail!("interface {iface} already has an XDP program; FluxVM will not replace it");
    }

    let root = cfg.pin_root.join("xdp");
    let prog_dir = root.join("progs");
    let map_dir = root.join("maps");
    fs::create_dir_all(&prog_dir)?;
    fs::create_dir_all(&map_dir)?;
    // bpffs accepts BPF objects, not regular ownership sidecars. Keep state
    // under /run/fluxvm just like the TC loader does.
    let meta = xdp_meta_dir();
    fs::create_dir_all(&meta)?;
    fs::write(meta.join("iface"), iface)?;

    let prog = prog_dir.join("fluxvm_xdp_guard");
    let result = (|| -> Result<()> {
        run(
            "bpftool",
            &[
                "prog".into(),
                "load".into(),
                cfg.bpf_object.display().to_string(),
                prog.display().to_string(),
                "type".into(),
                "xdp".into(),
                "pinmaps".into(),
                map_dir.display().to_string(),
            ],
        )?;
        let program_id = pinned_program_id(&prog)?;
        fs::write(meta.join("prog_id"), program_id.to_string())?;
        reconfigure_maps(cfg)?;
        run(
            "ip",
            &[
                "link".into(),
                "set".into(),
                "dev".into(),
                iface.into(),
                "xdp".into(),
                "pinned".into(),
                prog.display().to_string(),
            ],
        )?;
        info!(%iface, blocks = cfg.block_cidrs.len(), "attached FluxVM XDP node guard");
        Ok(())
    })();

    if result.is_err() {
        let _ = remove(cfg);
    }
    result
}

fn reconfigure_maps(cfg: &XdpConfig) -> Result<()> {
    let map_dir = cfg.pin_root.join("xdp/maps");
    let map4 = map_dir.join("fvm_xdp_block4");
    let map6 = map_dir.join("fvm_xdp_block6");
    let mut desired4 = Vec::new();
    let mut desired6 = Vec::new();
    for cidr in &cfg.block_cidrs {
        match parse_ip_cidr(cidr)? {
            IpCidr::V4(c) => {
                let mut key = Vec::with_capacity(8);
                key.extend_from_slice(&(c.prefix as u32).to_ne_bytes());
                key.extend_from_slice(&c.network.octets());
                desired4.push(key);
            }
            IpCidr::V6(c) => {
                let mut key = Vec::with_capacity(20);
                key.extend_from_slice(&(c.prefix as u32).to_ne_bytes());
                key.extend_from_slice(&c.network.octets());
                desired6.push(key);
            }
        }
    }
    // Add the new blocklist before deleting stale entries. During an update
    // XDP can therefore briefly over-block, but never becomes fail-open.
    sync_block_map(&map4, &desired4)?;
    sync_block_map(&map6, &desired6)?;
    Ok(())
}

pub fn remove(cfg: &XdpConfig) -> Result<()> {
    let root = cfg.pin_root.join("xdp");
    let meta = xdp_meta_dir();
    if !root.exists() && !meta.exists() {
        return Ok(());
    }

    let iface = read_xdp_marker(&meta, &root, "iface")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let owned_id = read_xdp_marker(&meta, &root, "prog_id")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .or_else(|| pinned_program_id(&root.join("progs/fluxvm_xdp_guard")).ok());

    if let (Some(iface), Some(owned_id)) = (iface.as_deref(), owned_id) {
        let (attached, current_id) = interface_xdp_state(iface)?;
        match (attached, current_id) {
            (false, _) => {}
            (true, Some(id)) if id == owned_id => {
                run(
                    "ip",
                    &[
                        "link".into(), "set".into(), "dev".into(), iface.into(),
                        "xdp".into(), "off".into(),
                    ],
                )
                .context("detaching FluxVM-owned XDP program")?;
            }
            (true, Some(id)) => tracing::warn!(
                %iface, fluxvm_program_id = owned_id, current_program_id = id,
                "XDP attachment is no longer FluxVM-owned; leaving it untouched"
            ),
            (true, None) => tracing::warn!(
                %iface, fluxvm_program_id = owned_id,
                "XDP is attached but its program id is unavailable; refusing detach"
            ),
        }
    } else {
        tracing::warn!(
            pin_root = %root.display(),
            "incomplete FluxVM XDP ownership markers; removing stale pins without touching interface"
        );
    }

    if root.exists() {
        fs::remove_dir_all(&root)
            .with_context(|| format!("removing XDP pin directory {}", root.display()))?;
    }
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

fn attachment_is_ours(cfg: &XdpConfig, expected_iface: &str) -> Result<bool> {
    let root = cfg.pin_root.join("xdp");
    let meta = xdp_meta_dir();
    let iface = read_xdp_marker(&meta, &root, "iface")
        .map(|s| s.trim().to_string());
    if iface.as_deref() != Some(expected_iface) {
        return Ok(false);
    }
    let owned_id = read_xdp_marker(&meta, &root, "prog_id")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .or_else(|| pinned_program_id(&root.join("progs/fluxvm_xdp_guard")).ok());
    let Some(owned_id) = owned_id else { return Ok(false) };
    let (attached, current_id) = interface_xdp_state(expected_iface)?;
    Ok(attached && current_id == Some(owned_id))
}

fn xdp_meta_dir() -> std::path::PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return std::path::PathBuf::from(root).join("xdp");
    }
    std::path::PathBuf::from("/run/fluxvm/xdp")
}

fn read_xdp_marker(meta: &Path, pin_root: &Path, name: &str) -> Option<String> {
    let normal = meta.join(name);
    if let Ok(value) = fs::read_to_string(&normal) {
        return Some(value);
    }
    // Compatibility with early development builds that tried to place
    // regular sidecars under bpffs. This usually does not exist.
    fs::read_to_string(pin_root.join(name)).ok()
}

/// Returns `(attached, program_id)`. Modern iproute2 emits
/// `xdp.prog.id`; older releases may expose `prog_id`.
fn interface_xdp_state(iface: &str) -> Result<(bool, Option<u32>)> {
    let out = Command::new("ip")
        .args(["-j", "-d", "link", "show", "dev", iface])
        .output()
        .context("querying link XDP state")?;
    if !out.status.success() {
        bail!(
            "ip link show {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let value: Value = serde_json::from_slice(&out.stdout).context("parsing ip -j link output")?;
    let Some(xdp) = value
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.get("xdp"))
        .filter(|v| !v.is_null())
    else {
        return Ok((false, None));
    };

    let id = xdp
        .get("prog")
        .and_then(|p| p.get("id"))
        .and_then(Value::as_u64)
        .or_else(|| xdp.get("prog_id").and_then(Value::as_u64))
        .and_then(|n| u32::try_from(n).ok());
    let attached = id.is_some()
        || xdp.get("attached").is_some()
        || xdp.get("mode").is_some()
        || xdp.as_object().is_some_and(|o| !o.is_empty());
    Ok((attached, id))
}

fn pinned_program_id(path: &Path) -> Result<u32> {
    let out = Command::new("bpftool")
        .args(["-j", "prog", "show", "pinned"])
        .arg(path)
        .output()
        .context("querying pinned XDP program")?;
    if !out.status.success() {
        bail!(
            "bpftool prog show pinned {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let json: Value = serde_json::from_slice(&out.stdout).context("parsing bpftool program JSON")?;
    let object = if let Some(array) = json.as_array() {
        array.first().context("bpftool returned an empty program array")?
    } else {
        &json
    };
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .context("bpftool program JSON is missing id")?;
    u32::try_from(id).context("BPF program id does not fit u32")
}

fn validate_block_cidrs(cidrs: &[String]) -> Result<()> {
    for cidr in cidrs {
        parse_ip_cidr(cidr).with_context(|| format!("invalid XDP block CIDR {cidr:?}"))?;
    }
    Ok(())
}

fn parse_ip_cidr(raw: &str) -> Result<IpCidr> {
    let (ip, prefix) = raw.split_once('/').context("XDP CIDR must include /prefix")?;
    let ip: IpAddr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    match ip {
        IpAddr::V4(ip) => {
            if prefix > 32 {
                bail!("IPv4 prefix must be <= 32");
            }
            let raw = u32::from(ip);
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Ok(IpCidr::V4(Ipv4Cidr { network: Ipv4Addr::from(raw & mask), prefix }))
        }
        IpAddr::V6(ip) => {
            if prefix > 128 {
                bail!("IPv6 prefix must be <= 128");
            }
            let raw = u128::from_be_bytes(ip.octets());
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            Ok(IpCidr::V6(Ipv6Cidr {
                network: Ipv6Addr::from((raw & mask).to_be_bytes()),
                prefix,
            }))
        }
    }
}

fn sync_block_map(map: &Path, desired: &[Vec<u8>]) -> Result<()> {
    if !map.exists() {
        bail!("XDP map is not pinned at {}", map.display());
    }
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()
        .context("dumping XDP map")?;
    if !out.status.success() {
        bail!(
            "bpftool map dump pinned {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let root: Value = serde_json::from_slice(&out.stdout).context("parsing XDP map JSON")?;
    let entries = root.as_array().context("bpftool XDP map dump must be an array")?;
    let mut existing = Vec::with_capacity(entries.len());
    for entry in entries {
        existing.push(json_bytes(&entry["key"])?);
    }

    for key in desired {
        bpftool_map_update(map, key, &1u32.to_ne_bytes())?;
    }
    for key in existing {
        if desired.iter().any(|wanted| wanted == &key) {
            continue;
        }
        let mut args = vec![
            "map".into(), "delete".into(), "pinned".into(), map.display().to_string(),
            "key".into(), "hex".into(),
        ];
        args.extend(key.iter().map(|b| format!("{b:02x}")));
        run("bpftool", &args)?;
    }
    Ok(())
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    if let Some(a) = v.as_array() {
        return a
            .iter()
            .map(|x| {
                if let Some(n) = x.as_u64().filter(|n| *n <= 255) {
                    return Ok(n as u8);
                }
                if let Some(n) = x.as_i64().filter(|n| (0..=255).contains(n)) {
                    return Ok(n as u8);
                }
                if let Some(s) = x.as_str() {
                    let s = s.trim().trim_start_matches("0x");
                    return u8::from_str_radix(s, 16)
                        .with_context(|| format!("invalid bpftool hex byte {s:?}"));
                }
                bail!("bpftool JSON byte must be 0..255 or hex string, got {x}")
            })
            .collect();
    }
    if let Some(s) = v.as_str() {
        let normalized = s.replace(':', " ").replace(',', " ");
        return normalized
            .split_whitespace()
            .map(|x| u8::from_str_radix(x.trim_start_matches("0x"), 16).context("invalid hex byte"))
            .collect();
    }
    bail!("unsupported bpftool JSON byte representation: {v}")
}

fn bpftool_map_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".into(), "update".into(), "pinned".into(), map.display().to_string(),
        "key".into(), "hex".into(),
    ];
    args.extend(key.iter().map(|b| format!("{b:02x}")));
    args.push("value".into());
    args.push("hex".into());
    args.extend(value.iter().map(|b| format!("{b:02x}")));
    run("bpftool", &args)
}

fn require_bpftool() -> Result<()> {
    require_version("bpftool", &["version"])
}

fn require_ip() -> Result<()> {
    require_version("ip", &["-V"])
}

fn require_version(name: &str, args: &[&str]) -> Result<()> {
    // Capture/discard banners: bpftool/ip print version text on stdout.
    let status = Command::new(name)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("{name} is required"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{} {} exited with {status}", name, args.join(" "))
    }
}

fn run(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program).args(args).output()?;
    if !out.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_normalization_v4_and_v6() {
        match parse_ip_cidr("198.51.100.99/24").unwrap() {
            IpCidr::V4(c) => assert_eq!(c.network, Ipv4Addr::new(198, 51, 100, 0)),
            _ => panic!("expected v4"),
        }
        match parse_ip_cidr("2001:db8:abcd::99/48").unwrap() {
            IpCidr::V6(c) => assert_eq!(c.network, "2001:db8:abcd::".parse::<Ipv6Addr>().unwrap()),
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn invalid_prefixes_fail() {
        assert!(parse_ip_cidr("10.0.0.1/33").is_err());
        assert!(parse_ip_cidr("2001:db8::1/129").is_err());
    }

    #[test]
    fn modern_iproute2_xdp_shape_is_understood() {
        let json = serde_json::json!({"xdp":{"mode":2,"prog":{"id":77,"name":"guard"}}});
        let xdp = &json["xdp"];
        let id = xdp.get("prog").and_then(|p| p.get("id")).and_then(Value::as_u64);
        assert_eq!(id, Some(77));
    }
}
