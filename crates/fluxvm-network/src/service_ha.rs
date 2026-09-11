// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Event-assisted Service Fabric HA mutation feed.
//!
//! The v5 snapshot-diff journal remains authoritative. v6 adds a bounded BPF
//! queue that lets userspace append create/delete mutations earlier, reducing
//! standby lag without making queue delivery a correctness dependency.

use crate::service;
use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::CString,
    os::fd::RawFd,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

const BPF_OBJ_GET: libc::c_long = 7;
const BPF_MAP_LOOKUP_AND_DELETE_ELEM: libc::c_long = 21;
const EVENT_SIZE: usize = 128;
const EVENT_HEADER: usize = 24;
const EVENT_KEY_MAX: usize = 48;
const EVENT_VALUE_MAX: usize = 56;
const OP_UPSERT: u8 = 1;
const OP_DELETE: u8 = 2;
const MAP_FCT4: u8 = 1;
const MAP_FCT6: u8 = 2;
const MAP_NAT4: u8 = 3;
const MAP_NAT6: u8 = 4;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaEventDrainReport {
    pub service: String,
    pub queue_maps: usize,
    pub drained: usize,
    pub dispatched_other_services: usize,
    pub ignored_unknown_services: usize,
    pub malformed: usize,
}

#[derive(Debug)]
struct ParsedEvent {
    service_id: u32,
    operation: service::HaDeltaOperation,
    map: &'static str,
    key_hex: String,
    value_hex: Option<String>,
}

#[repr(C)]
struct BpfObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: u32,
}

#[repr(C)]
struct BpfMapElemAttr {
    map_fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

struct MapFd(RawFd);
impl Drop for MapFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

pub fn drain_service_events(
    cfg: &Config,
    name: &str,
    max_events: usize,
) -> Result<HaEventDrainReport> {
    let spec = service::get(cfg, name)?.with_context(|| format!("service {name:?} not found"))?;
    let requested_sid = service::service_id(&spec.name);
    let service_names: HashMap<u32, String> = service::list(cfg)?
        .into_iter()
        .map(|spec| (service::service_id(&spec.name), spec.name))
        .collect();
    let mut report = HaEventDrainReport {
        service: name.to_string(),
        ..Default::default()
    };
    let mut remaining = max_events.clamp(1, 65_536);

    // `fluxvm_haq` is shared by every service on an interface. Popping is
    // destructive, so every valid event must be dispatched to its owning
    // service journal even when this drain was triggered by another service.
    for map_dir in host_map_dirs(cfg) {
        if remaining == 0 {
            break;
        }
        let queue = map_dir.join("fluxvm_haq");
        if !queue.exists() {
            continue;
        }
        report.queue_maps += 1;
        let fd = obj_get(&queue)?;
        while remaining > 0 {
            let Some(raw) = pop_queue(fd.0)? else {
                break;
            };
            remaining -= 1;
            match parse_event(&raw) {
                Ok(event) => {
                    let Some(owner) = service_names.get(&event.service_id) else {
                        report.ignored_unknown_services += 1;
                        continue;
                    };
                    service::append_ha_delta_event(
                        cfg,
                        owner,
                        event.operation,
                        event.map,
                        &event.key_hex,
                        event.value_hex.as_deref(),
                    )?;
                    if event.service_id == requested_sid {
                        report.drained += 1;
                    } else {
                        report.dispatched_other_services += 1;
                    }
                }
                Err(_) => report.malformed += 1,
            }
        }
    }
    Ok(report)
}

pub fn queue_drop_count(cfg: &Config, name: &str) -> Result<u64> {
    let spec = service::get(cfg, name)?.with_context(|| format!("service {name:?} not found"))?;
    let sid = service::service_id(&spec.name);
    let mut total = 0u64;
    for map_dir in host_map_dirs(cfg) {
        let map = map_dir.join("fluxvm_hadrop");
        if !map.exists() {
            continue;
        }
        let out = std::process::Command::new("bpftool")
            .args(["-j", "map", "lookup", "pinned"])
            .arg(&map)
            .arg("key")
            .arg("hex")
            .args(sid.to_ne_bytes().iter().map(|b| format!("{b:02x}")))
            .output()?;
        if !out.status.success() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        if let Some(v) = value.get("value") {
            total = total.saturating_add(sum_percpu_u64(v)?);
        }
    }
    Ok(total)
}

fn sum_percpu_u64(value: &serde_json::Value) -> Result<u64> {
    // bpftool may return one byte array or an array of per-CPU byte arrays.
    if let Some(arr) = value.as_array() {
        if arr.first().and_then(|v| v.as_array()).is_some() {
            let mut total = 0u64;
            for cpu in arr {
                let bytes = json_bytes(cpu)?;
                if bytes.len() >= 8 {
                    total =
                        total.saturating_add(u64::from_ne_bytes(bytes[..8].try_into().unwrap()));
                }
            }
            return Ok(total);
        }
        let bytes = json_bytes(value)?;
        if bytes.len() >= 8 {
            return Ok(u64::from_ne_bytes(bytes[..8].try_into().unwrap()));
        }
    }
    Ok(0)
}

fn json_bytes(v: &serde_json::Value) -> Result<Vec<u8>> {
    let arr = v
        .as_array()
        .context("bpftool byte field must be an array")?;
    arr.iter()
        .map(|x| {
            if let Some(n) = x.as_u64() {
                return u8::try_from(n).context("bpftool byte out of range");
            }
            let s = x
                .as_str()
                .context("bpftool byte must be number or hex string")?
                .trim_start_matches("0x");
            u8::from_str_radix(s, 16).context("invalid bpftool hex byte")
        })
        .collect()
}

fn host_map_dirs(cfg: &Config) -> Vec<PathBuf> {
    cfg.sandbox
        .dataplane
        .service
        .north_south_interfaces
        .iter()
        .map(|iface| {
            cfg.sandbox
                .dataplane
                .pin_root
                .join("service-host")
                .join(iface)
                .join("maps")
        })
        .filter(|p| p.is_dir())
        .collect()
}

fn obj_get(path: &Path) -> Result<MapFd> {
    let c = CString::new(path.as_os_str().as_bytes()).context("BPF pin path contains NUL")?;
    let attr = BpfObjGetAttr {
        pathname: c.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
        path_fd: 0,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET,
            &attr,
            std::mem::size_of::<BpfObjGetAttr>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("BPF_OBJ_GET {}", path.display()));
    }
    Ok(MapFd(fd as RawFd))
}

fn pop_queue(fd: RawFd) -> Result<Option<[u8; EVENT_SIZE]>> {
    let mut value = [0u8; EVENT_SIZE];
    let attr = BpfMapElemAttr {
        map_fd: fd as u32,
        pad: 0,
        key: 0,
        value: value.as_mut_ptr() as u64,
        flags: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_LOOKUP_AND_DELETE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapElemAttr>(),
        )
    };
    if rc == 0 {
        return Ok(Some(value));
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        return Ok(None);
    }
    Err(err).context("BPF_MAP_LOOKUP_AND_DELETE_ELEM fluxvm_haq")
}

fn parse_event(raw: &[u8; EVENT_SIZE]) -> Result<ParsedEvent> {
    let service_id = u32::from_ne_bytes(raw[8..12].try_into().unwrap());
    let op = match raw[16] {
        OP_UPSERT => service::HaDeltaOperation::Upsert,
        OP_DELETE => service::HaDeltaOperation::Delete,
        other => bail!("unknown HA event operation {other}"),
    };
    let map = match raw[17] {
        MAP_FCT4 => "fluxvm_fct4",
        MAP_FCT6 => "fluxvm_fct6",
        MAP_NAT4 => "fluxvm_nat4",
        MAP_NAT6 => "fluxvm_nat6",
        other => bail!("unknown HA event map code {other}"),
    };
    let key_len = usize::from(raw[20]);
    let value_len = usize::from(raw[21]);
    if key_len == 0 || key_len > EVENT_KEY_MAX || value_len > EVENT_VALUE_MAX {
        bail!("invalid HA event key/value lengths {key_len}/{value_len}");
    }
    let key = &raw[EVENT_HEADER..EVENT_HEADER + key_len];
    let value_start = EVENT_HEADER + EVENT_KEY_MAX;
    let value = &raw[value_start..value_start + value_len];
    Ok(ParsedEvent {
        service_id,
        operation: op,
        map,
        key_hex: encode_hex(key),
        value_hex: if matches!(op, service::HaDeltaOperation::Upsert) {
            if value_len == 0 {
                bail!("HA upsert event has no value");
            }
            Some(encode_hex(value))
        } else {
            None
        },
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_128_byte_fct4_event() {
        let mut raw = [0u8; EVENT_SIZE];
        raw[8..12].copy_from_slice(&42u32.to_ne_bytes());
        raw[16] = OP_UPSERT;
        raw[17] = MAP_FCT4;
        raw[18] = 4;
        raw[19] = 6;
        raw[20] = 16;
        raw[21] = 24;
        raw[EVENT_HEADER..EVENT_HEADER + 16].copy_from_slice(&[1u8; 16]);
        raw[EVENT_HEADER + EVENT_KEY_MAX..EVENT_HEADER + EVENT_KEY_MAX + 24]
            .copy_from_slice(&[2u8; 24]);
        let e = parse_event(&raw).unwrap();
        assert_eq!(e.service_id, 42);
        assert_eq!(e.map, "fluxvm_fct4");
        assert_eq!(e.key_hex.len(), 32);
        assert_eq!(e.value_hex.unwrap().len(), 48);
    }
}
