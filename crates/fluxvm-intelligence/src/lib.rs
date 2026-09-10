// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

pub mod guard;
pub mod qos;
pub mod shield;
pub mod tcpintel;
pub mod netintel;

use anyhow::{Context, Result, anyhow, bail};
use fluxvm_core::model::{BackendKind, VmRecord, VmStatus};
use fluxvm_network::{dataplane::{PodNetworkPolicy, VmNetworkPolicy}, ebpf::{DropReasonRecord, FlowRecord}};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

pub const INTELLIGENCE_SCHEMA_VERSION: u32 = 2;
pub const DEFAULT_PIN_ROOT: &str = "/sys/fs/bpf/fluxvm/intelligence";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureProbe {
    pub schema_version: u32,
    pub bpffs: bool,
    pub bpftool: bool,
    pub tracefs: bool,
    pub kvm_entry: bool,
    pub kvm_exit: bool,
    pub sched_wakeup: bool,
    pub sched_switch: bool,
    pub sched_migrate_task: bool,
    pub blk_mq_start_request: bool,
    pub blk_account_io_done: bool,
    pub vhost_work_queue: bool,
    pub vhost_poll_wakeup: bool,
    pub maps_loaded: bool,
    pub flight_maps_loaded: bool,
    pub kernel_btf: bool,
}

impl FeatureProbe {
    pub fn ready_for_scheduler(&self) -> bool {
        self.bpffs && self.bpftool && self.tracefs && self.sched_wakeup && self.sched_switch
    }
    pub fn ready_for_kvm(&self) -> bool {
        self.ready_for_scheduler() && self.kvm_entry && self.kvm_exit
    }
    pub fn ready_for_flight_recorder(&self) -> bool {
        self.maps_loaded && self.flight_maps_loaded
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelVmStats {
    pub kvm_exits: u64,
    pub guest_run_ns: u64,
    pub sched_wakeups: u64,
    pub runnable_delay_ns: u64,
    pub runnable_delay_max_ns: u64,
    pub migrations: u64,
    pub last_event_ns: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlightValue {
    pub count: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KvmExitReasonStat {
    pub vcpu_tid: u32,
    pub reason: u32,
    pub reason_label: String,
    pub count: u64,
    pub total_guest_ns: u64,
    pub max_guest_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatencyBucket {
    pub kind: String,
    pub bucket: u32,
    /// Inclusive upper bound in nanoseconds. `None` is +Inf.
    pub le_ns: Option<u64>,
    pub count: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlightCounters {
    pub block_started: u64,
    pub block_completed: u64,
    pub block_orphan_completions: u64,
    pub vhost_queued: u64,
    pub vhost_wakeups: u64,
    pub ringbuf_lost: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlightRecorderSnapshot {
    pub available: bool,
    pub kvm_exits: Vec<KvmExitReasonStat>,
    pub latency: Vec<LatencyBucket>,
    pub counters: FlightCounters,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlightEvent {
    pub timestamp_ns: u64,
    pub vm_key: u64,
    pub event_type: u32,
    pub event: String,
    pub tid: u32,
    pub cpu: u32,
    pub duration_ns: u64,
    pub arg0: u64,
    pub arg1: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcVmStats {
    pub threads: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub voluntary_context_switches: u64,
    pub involuntary_context_switches: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkVmStats {
    pub allowed_packets: u64,
    pub allowed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PressureStats {
    pub cpu_some_avg10: Option<f64>,
    pub memory_some_avg10: Option<f64>,
    pub memory_full_avg10: Option<f64>,
    pub io_some_avg10: Option<f64>,
    pub io_full_avg10: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VmRuntimeSnapshot {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub vm_key: u64,
    pub name: String,
    pub backend: String,
    pub status: String,
    pub pid: u32,
    pub tracked_tids: Vec<u32>,
    pub ebpf_active: bool,
    pub kernel: KernelVmStats,
    pub process: ProcVmStats,
    pub pressure: PressureStats,
    pub network: Option<NetworkVmStats>,
    #[serde(default)]
    pub flight: Option<FlightRecorderSnapshot>,
    pub findings: Vec<String>,
}

pub fn vm_key(id: Uuid) -> u64 {
    // Stable FNV-1a over the full UUID bytes. 0 is reserved as "not tracked".
    let mut h = 0xcbf29ce484222325u64;
    for b in id.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    if h == 0 { 1 } else { h }
}

pub fn probe(pin_root: &Path) -> FeatureProbe {
    let event = |sub: &str| {
        ["/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"]
            .iter()
            .any(|root| Path::new(root).join(sub).exists())
    };
    FeatureProbe {
        schema_version: INTELLIGENCE_SCHEMA_VERSION,
        bpffs: Path::new("/sys/fs/bpf").exists(),
        bpftool: command_exists("bpftool"),
        tracefs: Path::new("/sys/kernel/tracing").exists()
            || Path::new("/sys/kernel/debug/tracing").exists(),
        kvm_entry: event("kvm/kvm_entry"),
        kvm_exit: event("kvm/kvm_exit"),
        sched_wakeup: event("sched/sched_wakeup"),
        sched_switch: event("sched/sched_switch"),
        sched_migrate_task: event("sched/sched_migrate_task"),
        blk_mq_start_request: kernel_symbol_exists("blk_mq_start_request"),
        blk_account_io_done: kernel_symbol_exists("blk_account_io_done"),
        vhost_work_queue: kernel_symbol_exists("vhost_work_queue"),
        vhost_poll_wakeup: kernel_symbol_exists("vhost_poll_wakeup"),
        maps_loaded: pin_root.join("maps/tracked_tgids").exists()
            && pin_root.join("maps/tracked_tids").exists()
            && pin_root.join("maps/vm_stats").exists(),
        flight_maps_loaded: pin_root.join("maps/kvm_exit_hist").exists()
            && pin_root.join("maps/latency_hist").exists()
            && pin_root.join("maps/flight_counts").exists()
            && pin_root.join("maps/flight_events").exists(),
        kernel_btf: Path::new("/sys/kernel/btf/vmlinux").exists(),
    }
}

pub fn register_record(record: &VmRecord, pin_root: &Path) -> Result<Vec<u32>> {
    let pid = record.pid.ok_or_else(|| anyhow!("VM {} has no VMM pid", record.id))?;
    let tids = register_raw(record.id, pid, pin_root)?;
    if let Some(cgroup) = record.cgroup_path.as_deref() {
        let map = pin_root.join("maps/tracked_cgroups");
        if map.exists() {
            let cgroup = if cgroup.is_absolute() { cgroup.to_path_buf() } else { Path::new("/sys/fs/cgroup").join(cgroup) };
            if let Ok(meta) = fs::metadata(cgroup) {
                let _ = bpftool_update_u64_u64(&map, meta.ino(), vm_key(record.id));
            }
        }
    }
    Ok(tids)
}

pub fn register_raw(id: Uuid, pid: u32, pin_root: &Path) -> Result<Vec<u32>> {
    if !Path::new(&format!("/proc/{pid}")).exists() {
        bail!("pid {pid} does not exist");
    }
    let key = vm_key(id);
    let maps = pin_root.join("maps");
    require_map(&maps.join("tracked_tgids"))?;
    require_map(&maps.join("tracked_tids"))?;
    bpftool_update_u32_u64(&maps.join("tracked_tgids"), pid, key)?;
    let mut tids = task_ids(pid)?;
    tids.extend(discover_vhost_tids(pid));
    tids.sort_unstable();
    tids.dedup();
    for tid in &tids {
        bpftool_update_u32_u64(&maps.join("tracked_tids"), *tid, key)?;
    }
    Ok(tids)
}

pub fn unregister_raw(id: Uuid, pid: Option<u32>, pin_root: &Path) -> Result<()> {
    let maps = pin_root.join("maps");
    let key = vm_key(id);
    if let Some(pid) = pid {
        let _ = bpftool_delete_u32(&maps.join("tracked_tgids"), pid);
        if let Ok(tids) = task_ids(pid) {
            for tid in tids { let _ = bpftool_delete_u32(&maps.join("tracked_tids"), tid); }
        }
    }
    let _ = bpftool_delete_u64(&maps.join("vm_stats"), key);
    let _ = clear_vm_aux_maps(pin_root, key);
    Ok(())
}


pub fn unregister_exact(id: Uuid, pid: u32, tids: &[u32], pin_root: &Path) -> Result<()> {
    let maps = pin_root.join("maps");
    let _ = bpftool_delete_u32(&maps.join("tracked_tgids"), pid);
    for tid in tids { let _ = bpftool_delete_u32(&maps.join("tracked_tids"), *tid); }
    let key = vm_key(id);
    let _ = bpftool_delete_u64(&maps.join("vm_stats"), key);
    let _ = clear_vm_aux_maps(pin_root, key);
    Ok(())
}

pub fn unregister_stale_tids(tids: &[u32], pin_root: &Path) -> Result<()> {
    let map = pin_root.join("maps/tracked_tids");
    for tid in tids { let _ = bpftool_delete_u32(&map, *tid); }
    Ok(())
}

pub fn snapshot_record(record: &VmRecord, pin_root: &Path) -> Result<VmRuntimeSnapshot> {
    let pid = record.pid.ok_or_else(|| anyhow!("VM {} has no VMM pid", record.id))?;
    let tids = if probe(pin_root).maps_loaded {
        register_record(record, pin_root).unwrap_or_else(|_| task_ids(pid).unwrap_or_default())
    } else {
        task_ids(pid).unwrap_or_default()
    };
    snapshot_parts(
        record.id,
        &record.name,
        backend_label(record.backend),
        status_label(record.status),
        pid,
        record.cgroup_path.as_deref(),
        tids,
        pin_root,
    )
}

pub fn snapshot_raw(id: Uuid, pid: u32, pin_root: &Path) -> Result<VmRuntimeSnapshot> {
    let tids = if probe(pin_root).maps_loaded {
        register_raw(id, pid, pin_root).unwrap_or_else(|_| task_ids(pid).unwrap_or_default())
    } else { task_ids(pid).unwrap_or_default() };
    snapshot_parts(id, "raw-target", "unknown", "running", pid, None, tids, pin_root)
}

fn snapshot_parts(
    id: Uuid,
    name: &str,
    backend: &str,
    status: &str,
    pid: u32,
    cgroup_path: Option<&Path>,
    tids: Vec<u32>,
    pin_root: &Path,
) -> Result<VmRuntimeSnapshot> {
    let p = probe(pin_root);
    let kernel = if p.maps_loaded { read_kernel_stats(pin_root, vm_key(id)).unwrap_or_default() } else { KernelVmStats::default() };
    let process = read_proc_stats(pid).unwrap_or_default();
    let pressure = cgroup_path.map(read_pressure).transpose().unwrap_or(None).unwrap_or_default();
    let flight = if p.flight_maps_loaded {
        read_flight_snapshot(pin_root, vm_key(id)).ok()
    } else {
        None
    };
    let mut findings = Vec::new();
    if kernel.runnable_delay_max_ns >= 10_000_000 {
        findings.push(format!("high vCPU/thread runnable delay: {:.2} ms max", kernel.runnable_delay_max_ns as f64 / 1_000_000.0));
    }
    if process.major_faults > 0 {
        findings.push(format!("VMM has {} major page faults", process.major_faults));
    }
    if pressure.cpu_some_avg10.unwrap_or(0.0) >= 10.0 {
        findings.push(format!("CPU pressure avg10 is {:.2}%", pressure.cpu_some_avg10.unwrap_or(0.0)));
    }
    if pressure.io_full_avg10.unwrap_or(0.0) >= 1.0 {
        findings.push(format!("full I/O pressure avg10 is {:.2}%", pressure.io_full_avg10.unwrap_or(0.0)));
    }
    if let Some(flight) = &flight {
        if flight.counters.ringbuf_lost > 0 {
            findings.push(format!("Flight Recorder dropped {} live event(s) because the ring buffer was full", flight.counters.ringbuf_lost));
        }
        let block_max = flight.latency.iter().filter(|b| b.kind == "block-io").map(|b| b.max_ns).max().unwrap_or(0);
        if block_max >= 20_000_000 {
            findings.push(format!("slow VM-attributed block I/O observed: {:.2} ms max", block_max as f64 / 1_000_000.0));
        }
    }
    if !p.maps_loaded {
        findings.push("eBPF intelligence maps are not loaded; showing procfs/cgroup fallback only".into());
    } else if !p.ready_for_kvm() {
        findings.push("KVM tracepoints unavailable; scheduler telemetry remains usable".into());
    }
    if p.maps_loaded && !p.flight_maps_loaded {
        findings.push("Flight Recorder maps are unavailable; runtime-intelligence object predates schema v2".into());
    }
    Ok(VmRuntimeSnapshot {
        schema_version: INTELLIGENCE_SCHEMA_VERSION,
        vm_id: id,
        vm_key: vm_key(id),
        name: name.into(),
        backend: backend.into(),
        status: status.into(),
        pid,
        tracked_tids: tids,
        ebpf_active: p.maps_loaded,
        kernel,
        process,
        pressure,
        network: None,
        flight,
        findings,
    })
}

pub fn read_kernel_stats(pin_root: &Path, wanted: u64) -> Result<KernelVmStats> {
    let path = pin_root.join("maps/vm_stats");
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(&path)
        .output()
        .with_context(|| format!("running bpftool for {}", path.display()))?;
    if !out.status.success() {
        bail!("bpftool map dump failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).context("parsing bpftool map JSON")?;
    for row in rows {
        let key = decode_scalar_or_hex_u64(row.get("key"));
        if key != Some(wanted) { continue; }
        if let Some(Value::Object(v)) = row.get("value") {
            return Ok(KernelVmStats {
                kvm_exits: json_u64(v.get("kvm_exits")).unwrap_or(0),
                guest_run_ns: json_u64(v.get("guest_run_ns")).unwrap_or(0),
                sched_wakeups: json_u64(v.get("sched_wakeups")).unwrap_or(0),
                runnable_delay_ns: json_u64(v.get("runnable_delay_ns")).unwrap_or(0),
                runnable_delay_max_ns: json_u64(v.get("runnable_delay_max_ns")).unwrap_or(0),
                migrations: json_u64(v.get("migrations")).unwrap_or(0),
                last_event_ns: json_u64(v.get("last_event_ns")).unwrap_or(0),
            });
        }
        let bytes = decode_hex_field(row.get("value")).ok_or_else(|| anyhow!("vm_stats value is not supported bpftool JSON"))?;
        if bytes.len() < 64 { bail!("vm_stats value too short: {}", bytes.len()); }
        return Ok(KernelVmStats {
            kvm_exits: le_u64(&bytes[0..8]).unwrap_or(0),
            guest_run_ns: le_u64(&bytes[8..16]).unwrap_or(0),
            sched_wakeups: le_u64(&bytes[16..24]).unwrap_or(0),
            runnable_delay_ns: le_u64(&bytes[24..32]).unwrap_or(0),
            runnable_delay_max_ns: le_u64(&bytes[32..40]).unwrap_or(0),
            migrations: le_u64(&bytes[40..48]).unwrap_or(0),
            last_event_ns: le_u64(&bytes[48..56]).unwrap_or(0),
        });
    }
    Ok(KernelVmStats::default())
}

pub fn task_ids(pid: u32) -> Result<Vec<u32>> {
    let mut tids = BTreeSet::new();
    for ent in fs::read_dir(format!("/proc/{pid}/task")).with_context(|| format!("reading /proc/{pid}/task"))? {
        let ent = ent?;
        if let Ok(tid) = ent.file_name().to_string_lossy().parse::<u32>() { tids.insert(tid); }
    }
    Ok(tids.into_iter().collect())
}

pub fn read_flight_snapshot(pin_root: &Path, wanted: u64) -> Result<FlightRecorderSnapshot> {
    let kvm_path = pin_root.join("maps/kvm_exit_hist");
    let latency_path = pin_root.join("maps/latency_hist");
    let counts_path = pin_root.join("maps/flight_counts");
    if !kvm_path.exists() || !latency_path.exists() || !counts_path.exists() {
        return Ok(FlightRecorderSnapshot::default());
    }
    Ok(FlightRecorderSnapshot {
        available: true,
        kvm_exits: read_kvm_exit_hist(&kvm_path, wanted)?,
        latency: read_latency_hist(&latency_path, wanted)?,
        counters: read_flight_counts(&counts_path, wanted)?,
    })
}

pub fn trace_events(
    id: Uuid,
    pin_root: &Path,
    seconds: u64,
    limit: usize,
) -> Result<Vec<FlightEvent>> {
    let map = pin_root.join("maps/flight_events");
    require_map(&map)?;
    let helper = std::env::var("FLUXVM_FLIGHT_READER")
        .unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-flight-reader".into());
    let args = vec![
        "--map".to_string(), map.display().to_string(),
        "--vm-key".to_string(), vm_key(id).to_string(),
        "--seconds".to_string(), seconds.clamp(1, 3600).to_string(),
        "--limit".to_string(), limit.clamp(1, 10000).to_string(),
    ];
    let out = Command::new(&helper)
        .args(&args)
        .output()
        .with_context(|| format!("running Flight Recorder reader {helper}"))?;
    if !out.status.success() {
        bail!("Flight Recorder reader failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let text = String::from_utf8(out.stdout).context("Flight Recorder reader emitted non-UTF8 output")?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<FlightEvent>(line).context("decoding Flight Recorder JSONL"))
        .collect()
}

fn read_kvm_exit_hist(path: &Path, wanted: u64) -> Result<Vec<KvmExitReasonStat>> {
    let rows = bpftool_rows(path)?;
    let mut out = Vec::new();
    for row in rows {
        let (vm_key, vcpu_tid, reason) = if let Some(Value::Object(key)) = row.get("key") {
            (
                json_u64(key.get("vm_key")).unwrap_or(0),
                json_u64(key.get("vcpu_tid")).unwrap_or(0) as u32,
                json_u64(key.get("reason")).unwrap_or(0) as u32,
            )
        } else {
            let Some(raw) = decode_hex_field(row.get("key")) else { continue; };
            if raw.len() < 16 { continue; }
            (le_u64(&raw[0..8]).unwrap_or(0), le_u32(&raw[8..12]).unwrap_or(0), le_u32(&raw[12..16]).unwrap_or(0))
        };
        if vm_key != wanted { continue; }
        let value = flight_value_from_row(row.get("value"));
        out.push(KvmExitReasonStat {
            vcpu_tid,
            reason,
            reason_label: kvm_exit_reason_label(reason).into(),
            count: value.count,
            total_guest_ns: value.total_ns,
            max_guest_ns: value.max_ns,
        });
    }
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.vcpu_tid.cmp(&b.vcpu_tid)).then_with(|| a.reason.cmp(&b.reason)));
    Ok(out)
}

fn read_latency_hist(path: &Path, wanted: u64) -> Result<Vec<LatencyBucket>> {
    let rows = bpftool_rows(path)?;
    let mut out = Vec::new();
    for row in rows {
        let (vm_key, kind, bucket) = if let Some(Value::Object(key)) = row.get("key") {
            (
                json_u64(key.get("vm_key")).unwrap_or(0),
                json_u64(key.get("kind")).unwrap_or(0) as u32,
                json_u64(key.get("bucket")).unwrap_or(0) as u32,
            )
        } else {
            let Some(raw) = decode_hex_field(row.get("key")) else { continue; };
            if raw.len() < 16 { continue; }
            (le_u64(&raw[0..8]).unwrap_or(0), le_u32(&raw[8..12]).unwrap_or(0), le_u32(&raw[12..16]).unwrap_or(0))
        };
        if vm_key != wanted { continue; }
        let value = flight_value_from_row(row.get("value"));
        out.push(LatencyBucket {
            kind: latency_kind_label(kind).into(),
            bucket,
            le_ns: latency_upper_bound_ns(bucket),
            count: value.count,
            total_ns: value.total_ns,
            max_ns: value.max_ns,
        });
    }
    out.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.bucket.cmp(&b.bucket)));
    Ok(out)
}

fn read_flight_counts(path: &Path, wanted: u64) -> Result<FlightCounters> {
    let rows = bpftool_rows(path)?;
    let mut out = FlightCounters::default();
    for row in rows {
        let (vm_key, kind) = if let Some(Value::Object(key)) = row.get("key") {
            (json_u64(key.get("vm_key")).unwrap_or(0), json_u64(key.get("kind")).unwrap_or(0) as u32)
        } else {
            let Some(raw) = decode_hex_field(row.get("key")) else { continue; };
            if raw.len() < 12 { continue; }
            (le_u64(&raw[0..8]).unwrap_or(0), le_u32(&raw[8..12]).unwrap_or(0))
        };
        if vm_key != wanted { continue; }
        let value = decode_scalar_or_hex_u64(row.get("value")).unwrap_or(0);
        match kind {
            1 => out.block_started = value,
            2 => out.block_completed = value,
            3 => out.block_orphan_completions = value,
            4 => out.vhost_queued = value,
            5 => out.vhost_wakeups = value,
            6 => out.ringbuf_lost = value,
            _ => {}
        }
    }
    Ok(out)
}

fn flight_value_from_row(v: Option<&Value>) -> FlightValue {
    if let Some(Value::Object(value)) = v {
        return FlightValue {
            count: json_u64(value.get("count")).unwrap_or(0),
            total_ns: json_u64(value.get("total_ns")).unwrap_or(0),
            max_ns: json_u64(value.get("max_ns")).unwrap_or(0),
        };
    }
    let raw = decode_hex_field(v).unwrap_or_default();
    FlightValue {
        count: raw.get(0..8).and_then(le_u64).unwrap_or(0),
        total_ns: raw.get(8..16).and_then(le_u64).unwrap_or(0),
        max_ns: raw.get(16..24).and_then(le_u64).unwrap_or(0),
    }
}

fn bpftool_rows(path: &Path) -> Result<Vec<Value>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(path)
        .output()
        .with_context(|| format!("running bpftool for {}", path.display()))?;
    if !out.status.success() {
        bail!("bpftool map dump {} failed: {}", path.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).context("parsing Flight Recorder bpftool JSON")
}

fn latency_kind_label(kind: u32) -> &'static str {
    match kind { 1 => "kvm-run", 2 => "runnable", 3 => "block-io", _ => "unknown" }
}

fn latency_upper_bound_ns(bucket: u32) -> Option<u64> {
    if bucket >= 24 { return None; }
    Some(1000u64.saturating_mul(1u64 << bucket))
}

fn kvm_exit_reason_label(reason: u32) -> &'static str {
    if !cfg!(target_arch = "x86_64") { return "architecture-specific"; }
    match reason {
        0 => "exception-or-nmi",
        1 => "external-interrupt",
        2 => "triple-fault",
        7 => "interrupt-window",
        10 => "cpuid",
        12 => "hlt",
        18 => "vmcall",
        28 => "control-register",
        30 => "io-instruction",
        31 => "msr-read",
        32 => "msr-write",
        44 => "ept-misconfig",
        48 => "ept-violation",
        _ => "other",
    }
}

fn discover_vhost_tids(vmm_pid: u32) -> Vec<u32> {
    let prefix = format!("vhost-{vmm_pid}");
    let mut out = Vec::new();
    let Ok(proc) = fs::read_dir("/proc") else { return out; };
    for ent in proc.flatten() {
        let Ok(tid) = ent.file_name().to_string_lossy().parse::<u32>() else { continue; };
        let Ok(comm) = fs::read_to_string(ent.path().join("comm")) else { continue; };
        let comm = comm.trim();
        if comm == prefix || comm.starts_with(&(prefix.clone() + "-")) { out.push(tid); }
    }
    out
}

fn clear_vm_aux_maps(pin_root: &Path, wanted: u64) -> Result<()> {
    clear_scalar_value_map(&pin_root.join("maps/tracked_cgroups"), wanted)?;
    clear_struct_vm_map(&pin_root.join("maps/kvm_exit_hist"), wanted, 16)?;
    clear_struct_vm_map(&pin_root.join("maps/latency_hist"), wanted, 16)?;
    clear_struct_vm_map(&pin_root.join("maps/flight_counts"), wanted, 16)?;
    Ok(())
}

fn clear_scalar_value_map(path: &Path, wanted: u64) -> Result<()> {
    if !path.exists() { return Ok(()); }
    for row in bpftool_rows(path)? {
        let value = decode_scalar_or_hex_u64(row.get("value")).unwrap_or(0);
        if value != wanted { continue; }
        if let Some(key) = map_key_bytes(row.get("key"), 8) { let _ = bpftool_delete_bytes(path, &key); }
    }
    Ok(())
}

fn clear_struct_vm_map(path: &Path, wanted: u64, key_len: usize) -> Result<()> {
    if !path.exists() { return Ok(()); }
    for row in bpftool_rows(path)? {
        let key = if let Some(raw) = decode_hex_field(row.get("key")) {
            raw
        } else if let Some(Value::Object(obj)) = row.get("key") {
            let vm = json_u64(obj.get("vm_key")).unwrap_or(0);
            if vm != wanted { continue; }
            let mut raw = vm.to_le_bytes().to_vec();
            raw.extend((json_u64(obj.get("kind")).or_else(|| json_u64(obj.get("vcpu_tid"))).unwrap_or(0) as u32).to_le_bytes());
            raw.extend((json_u64(obj.get("bucket")).or_else(|| json_u64(obj.get("reason"))).unwrap_or(0) as u32).to_le_bytes());
            raw
        } else { continue; };
        if key.len() < key_len || le_u64(&key[..8]) != Some(wanted) { continue; }
        let _ = bpftool_delete_bytes(path, &key[..key_len]);
    }
    Ok(())
}

fn map_key_bytes(v: Option<&Value>, width: usize) -> Option<Vec<u8>> {
    if let Some(raw) = decode_hex_field(v) { return (raw.len() >= width).then(|| raw[..width].to_vec()); }
    let scalar = decode_scalar_or_hex_u64(v)?;
    Some(scalar.to_le_bytes()[..width].to_vec())
}

fn bpftool_delete_bytes(map: &Path, key: &[u8]) -> Result<()> {
    let mut args = vec!["map".into(), "delete".into(), "pinned".into(), map.display().to_string(), "key".into(), "hex".into()];
    args.extend(key.iter().map(|b| format!("{b:02x}")));
    run_bpftool(&args)
}

fn read_proc_stats(pid: u32) -> Result<ProcVmStats> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat.rfind(')').ok_or_else(|| anyhow!("malformed /proc/{pid}/stat"))?;
    let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    // fields[0] is stat field 3 (state); minflt=10, majflt=12, utime=14, stime=15.
    let parse = |idx: usize| fields.get(idx).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let mut out = ProcVmStats {
        minor_faults: parse(7), major_faults: parse(9), user_ticks: parse(11), system_ticks: parse(12), ..Default::default()
    };
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for line in status.lines() {
        let mut it = line.split_whitespace();
        match it.next().unwrap_or("") {
            "Threads:" => out.threads = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            "voluntary_ctxt_switches:" => out.voluntary_context_switches = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            "nonvoluntary_ctxt_switches:" => out.involuntary_context_switches = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    let io = fs::read_to_string(format!("/proc/{pid}/io")).unwrap_or_default();
    for line in io.lines() {
        let mut it = line.split_whitespace();
        match it.next().unwrap_or("") {
            "read_bytes:" => out.read_bytes = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            "write_bytes:" => out.write_bytes = it.next().and_then(|s| s.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    Ok(out)
}

fn read_pressure(cgroup_path: &Path) -> Result<PressureStats> {
    let base = if cgroup_path.is_absolute() { cgroup_path.to_path_buf() } else { Path::new("/sys/fs/cgroup").join(cgroup_path) };
    let cpu = read_pressure_file(&base.join("cpu.pressure"));
    let mem = read_pressure_file(&base.join("memory.pressure"));
    let io = read_pressure_file(&base.join("io.pressure"));
    Ok(PressureStats {
        cpu_some_avg10: cpu.get("some").copied(),
        memory_some_avg10: mem.get("some").copied(), memory_full_avg10: mem.get("full").copied(),
        io_some_avg10: io.get("some").copied(), io_full_avg10: io.get("full").copied(),
    })
}

fn read_pressure_file(path: &Path) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    let Ok(s) = fs::read_to_string(path) else { return out; };
    for line in s.lines() {
        let mut parts = line.split_whitespace();
        let Some(kind) = parts.next() else { continue; };
        for item in parts {
            if let Some(v) = item.strip_prefix("avg10=").and_then(|v| v.parse::<f64>().ok()) { out.insert(kind.into(), v); }
        }
    }
    out
}

fn command_exists(name: &str) -> bool {
    Command::new("sh").args(["-c", &format!("command -v {name} >/dev/null 2>&1")]).status().is_ok_and(|s| s.success())
}
fn kernel_symbol_exists(name: &str) -> bool {
    fs::read_to_string("/proc/kallsyms")
        .ok()
        .is_some_and(|s| s.lines().any(|line| line.split_whitespace().last() == Some(name)))
}
fn require_map(path: &Path) -> Result<()> { if path.exists() { Ok(()) } else { bail!("required pinned map missing: {}", path.display()) } }
fn run_bpftool(args: &[String]) -> Result<()> {
    let out = Command::new("bpftool").args(args).output().context("running bpftool")?;
    if out.status.success() { Ok(()) } else { bail!("bpftool failed: {}", String::from_utf8_lossy(&out.stderr)) }
}
fn bpftool_update_u32_u64(map: &Path, key: u32, value: u64) -> Result<()> {
    let mut args = vec!["map".into(), "update".into(), "pinned".into(), map.display().to_string(), "key".into(), "hex".into()];
    args.extend(le_bytes(key as u64, 4)); args.push("value".into()); args.push("hex".into()); args.extend(le_bytes(value, 8)); run_bpftool(&args)
}
fn bpftool_update_u64_u64(map: &Path, key: u64, value: u64) -> Result<()> {
    let mut args = vec!["map".into(), "update".into(), "pinned".into(), map.display().to_string(), "key".into(), "hex".into()];
    args.extend(le_bytes(key, 8)); args.push("value".into()); args.push("hex".into()); args.extend(le_bytes(value, 8)); run_bpftool(&args)
}
fn bpftool_delete_u32(map: &Path, key: u32) -> Result<()> {
    if !map.exists() { return Ok(()); }
    let mut args = vec!["map".into(), "delete".into(), "pinned".into(), map.display().to_string(), "key".into(), "hex".into()];
    args.extend(le_bytes(key as u64, 4)); run_bpftool(&args)
}
fn bpftool_delete_u64(map: &Path, key: u64) -> Result<()> {
    if !map.exists() { return Ok(()); }
    let mut args = vec!["map".into(), "delete".into(), "pinned".into(), map.display().to_string(), "key".into(), "hex".into()];
    args.extend(le_bytes(key, 8)); run_bpftool(&args)
}
fn le_bytes(value: u64, width: usize) -> Vec<String> { value.to_le_bytes()[..width].iter().map(|b| format!("{b:02x}")).collect() }
fn decode_hex_field(v: Option<&Value>) -> Option<Vec<u8>> {
    match v? {
        Value::Array(a) => a
            .iter()
            .map(|x| match x {
                Value::Number(n) => n.as_u64().filter(|n| *n <= 255).map(|n| n as u8),
                Value::String(s) => u8::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
                _ => None,
            })
            .collect(),
        Value::Object(o) => o.get("bytes").and_then(|v| decode_hex_field(Some(v))),
        _ => None,
    }
}
fn json_u64(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok().or_else(|| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()),
        _ => None,
    }
}
fn decode_scalar_or_hex_u64(v: Option<&Value>) -> Option<u64> {
    if let Some(n) = json_u64(v) { return Some(n); }
    if let Some(Value::Object(o)) = v {
        if let Some(n) = o.values().find_map(|x| json_u64(Some(x))) { return Some(n); }
    }
    decode_hex_field(v).and_then(|b| le_u64(&b))
}
fn le_u32(bytes: &[u8]) -> Option<u32> { if bytes.len() < 4 { None } else { Some(u32::from_le_bytes(bytes[..4].try_into().ok()?)) } }
fn le_u64(bytes: &[u8]) -> Option<u64> { if bytes.len() < 8 { None } else { Some(u64::from_le_bytes(bytes[..8].try_into().ok()?)) } }
fn backend_label(v: BackendKind) -> &'static str { match v { BackendKind::Qemu => "qemu", BackendKind::CloudHypervisor => "cloud-hypervisor", BackendKind::Firecracker => "firecracker", BackendKind::FluxVm => "flux-vm", BackendKind::Auto => "auto" } }
fn status_label(v: VmStatus) -> &'static str { match v { VmStatus::Creating => "creating", VmStatus::Running => "running", VmStatus::Paused => "paused", VmStatus::Stopped => "stopped", VmStatus::Failed => "failed" } }


#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropEvidence {
    pub source: String,
    pub destination: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DropFinding {
    /// Dataplane stage that most likely produced the policy verdict.
    pub stage: String,
    /// Stable machine-readable reason code.
    pub code: String,
    /// `exact-kernel` comes from dataplane schema v6 reason accounting;
    /// `exact` is deterministic policy inference; `probable` is a fallback
    /// when the kernel reason map is unavailable.
    pub confidence: String,
    pub explanation: String,
    pub suggestion: String,
    pub audit_only: bool,
    pub evidence: DropEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VmDiagnosis {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub vm_name: String,
    pub severity: String,
    pub summary: String,
    pub runtime_findings: Vec<String>,
    pub network_drop_packets: u64,
    pub network_drop_bytes: u64,
    /// Number of schema-v6 kernel branch-reason records used in this report.
    pub kernel_reason_records: usize,
    pub drop_findings: Vec<DropFinding>,
}

/// Correlate the existing FluxVM eBPF flow map with the effective VM and Pod
/// policy. This deliberately does not pretend to be a generic network
/// analyzer: every finding is scoped to a FluxVM VM identity and names the
/// FluxVM-owned policy stage that can produce that verdict.
pub fn diagnose_vm(
    snapshot: &VmRuntimeSnapshot,
    policy: &VmNetworkPolicy,
    pod_policy: Option<&PodNetworkPolicy>,
    flows: &[FlowRecord],
) -> VmDiagnosis {
    diagnose_vm_with_reasons(snapshot, policy, pod_policy, flows, &[])
}

/// Prefer kernel-native branch reasons from dataplane schema v6, then fall
/// back to Set-2 policy inference only for drop tuples that have no matching
/// reason record. This keeps diagnostics useful during a rolling upgrade
/// while eliminating ambiguity for rate, migration and compiled-policy hits
/// once every node is on schema v6.
pub fn diagnose_vm_with_reasons(
    snapshot: &VmRuntimeSnapshot,
    policy: &VmNetworkPolicy,
    pod_policy: Option<&PodNetworkPolicy>,
    flows: &[FlowRecord],
    reasons: &[DropReasonRecord],
) -> VmDiagnosis {
    let mut kernel: Vec<&DropReasonRecord> = reasons.iter().collect();
    kernel.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| b.last_seen_ns.cmp(&a.last_seen_ns))
    });
    kernel.truncate(128);

    let mut findings: Vec<DropFinding> = kernel.iter().map(|r| kernel_reason_finding(r)).collect();
    let kernel_keys: BTreeSet<(String, String, u16, u16, u8)> = kernel
        .iter()
        .map(|r| {
            (
                r.source.clone(),
                r.destination.clone(),
                r.source_port,
                r.destination_port,
                r.protocol,
            )
        })
        .collect();

    let mut drops: Vec<&FlowRecord> = flows.iter().filter(|f| f.verdict == "drop").collect();
    drops.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| b.last_seen_ns.cmp(&a.last_seen_ns))
    });
    drops.truncate(128);

    let mut total_packets = 0u64;
    let mut total_bytes = 0u64;
    for flow in drops {
        total_packets = total_packets.saturating_add(flow.packets);
        total_bytes = total_bytes.saturating_add(flow.bytes);
        let key = (
            flow.source.clone(),
            flow.destination.clone(),
            flow.source_port,
            flow.destination_port,
            flow.protocol,
        );
        if !kernel_keys.contains(&key) {
            findings.push(explain_drop(flow, policy, pod_policy));
        }
    }
    findings.sort_by(|a, b| {
        b.evidence
            .packets
            .cmp(&a.evidence.packets)
            .then_with(|| b.evidence.last_seen_ns.cmp(&a.evidence.last_seen_ns))
    });

    let severity = if findings.iter().any(|f| {
        !f.audit_only
            && matches!(
                f.code.as_str(),
                "explicit-cidr-deny" | "pod-policy-deny" | "explicit-deny" | "pod-explicit-deny"
            )
    }) || snapshot.kernel.runnable_delay_max_ns >= 50_000_000
    {
        "critical"
    } else if !findings.is_empty() || !snapshot.findings.is_empty() {
        "warning"
    } else {
        "healthy"
    };
    let summary = if findings.is_empty() {
        if snapshot.findings.is_empty() {
            "No current FluxVM runtime or VM-edge drop finding in the sampled state.".to_string()
        } else {
            format!("No VM-edge drops found; {} runtime finding(s) remain.", snapshot.findings.len())
        }
    } else {
        let top = &findings[0];
        format!(
            "{} VM-edge finding(s); top cause {} at {} ({} packet(s)); {} kernel reason record(s).",
            findings.len(), top.code, top.stage, top.evidence.packets, kernel.len()
        )
    };

    VmDiagnosis {
        schema_version: 3,
        vm_id: snapshot.vm_id,
        vm_name: snapshot.name.clone(),
        severity: severity.into(),
        summary,
        runtime_findings: snapshot.findings.clone(),
        network_drop_packets: total_packets,
        network_drop_bytes: total_bytes,
        kernel_reason_records: kernel.len(),
        drop_findings: findings,
    }
}

fn kernel_reason_finding(reason: &DropReasonRecord) -> DropFinding {
    let (stage, explanation, suggestion) = match reason.reason.as_str() {
        "malformed-l4" => (
            "vm-edge/parser",
            "The kernel could not safely parse the packet's L4 header.",
            "Inspect guest packet construction, fragmentation and offload settings before weakening policy.",
        ),
        "fragmented-l4" => (
            "vm-edge/parser",
            "The packet is fragmented while L4 enforcement is enabled.",
            "Avoid fragmented transport traffic or use an MTU that keeps policy-relevant headers in the first packet.",
        ),
        "explicit-cidr-deny" => (
            "vm-policy/cidr-deny",
            "The destination matched an explicit VM/group deny CIDR.",
            "Remove or narrow the deny rule only if this destination is intentionally permitted.",
        ),
        "cidr-miss" => (
            "vm-policy/cidr-allowlist",
            "The destination did not match the effective CIDR allowlist.",
            "Add the smallest required CIDR or correct DNS/service resolution.",
        ),
        "l4-miss" => (
            "vm-policy/l4-allowlist",
            "The destination transport protocol/port did not match the effective L4 allowlist.",
            "Permit only the required protocol/port pair.",
        ),
        "pod-policy-deny" => (
            "pod-policy/peer",
            "The Kubernetes Pod-identity policy rejected the peer.",
            "Fix the Pod peer policy or selector resolution rather than weakening VM-wide policy.",
        ),
        "rate-limit" => (
            "vm-policy/rate",
            "The VM exceeded its configured eBPF packet or bandwidth ceiling.",
            "Confirm sustained legitimate demand, then tune max_egress_pps/max_egress_mbps if required.",
        ),
        "default-deny" => (
            "vm-policy/default",
            "No explicit allow dimension applied and the VM default action is deny.",
            "Add a narrow CIDR and/or L4 allow rule for the required dependency.",
        ),
        "migration-quiesce" => (
            "migration/quiesce",
            "A new flow was rejected while the source VM was quiescing; established conntrack flows remain allowed.",
            "Expected during migration. Complete state export/cutover or resume the source if migration is cancelled.",
        ),
        "migration-restoring" => (
            "migration/restore",
            "A new flow was rejected while the destination VM was restoring eBPF state.",
            "Complete conntrack import and VMM cutover, then explicitly resume the destination dataplane.",
        ),
        "unsupported-ethertype" => (
            "vm-edge/ethertype",
            "A non-ARP/non-IPv4/non-IPv6 frame hit a deny-by-default VM edge.",
            "Permit the protocol only if it is required and has an explicit security model.",
        ),
        _ => (
            "vm-edge",
            "The kernel reported a VM-edge policy branch not recognized by this userspace build.",
            "Upgrade FluxVM userspace to the same dataplane schema as the node.",
        ),
    };
    DropFinding {
        stage: stage.into(),
        code: reason.reason.clone(),
        confidence: "exact-kernel".into(),
        explanation: explanation.into(),
        suggestion: suggestion.into(),
        audit_only: reason.action == "audit",
        evidence: DropEvidence {
            source: reason.source.clone(),
            destination: reason.destination.clone(),
            source_port: reason.source_port,
            destination_port: reason.destination_port,
            protocol: reason.protocol,
            packets: reason.packets,
            bytes: reason.bytes,
            last_seen_ns: reason.last_seen_ns,
        },
    }
}

fn explain_drop(
    flow: &FlowRecord,
    policy: &VmNetworkPolicy,
    pod_policy: Option<&PodNetworkPolicy>,
) -> DropFinding {
    let dst = flow.destination.parse::<IpAddr>().ok();
    let evidence = DropEvidence {
        source: flow.source.clone(),
        destination: flow.destination.clone(),
        source_port: flow.source_port,
        destination_port: flow.destination_port,
        protocol: flow.protocol,
        packets: flow.packets,
        bytes: flow.bytes,
        last_seen_ns: flow.last_seen_ns,
    };
    let mk = |stage: &str, code: &str, confidence: &str, explanation: String, suggestion: &str| DropFinding {
        stage: stage.into(),
        code: code.into(),
        confidence: confidence.into(),
        explanation,
        suggestion: suggestion.into(),
        audit_only: policy.audit_mode || pod_policy.is_some_and(|p| p.audit_mode),
        evidence: evidence.clone(),
    };

    if let Some(ip) = dst {
        if policy.deny_cidrs.iter().any(|cidr| ip_in_cidr(ip, cidr)) {
            return mk(
                "vm-policy/cidr-deny",
                "explicit-deny",
                "exact",
                format!("{} matches an explicit deny CIDR.", flow.destination),
                "Remove or narrow the deny CIDR only if this destination is intentionally permitted.",
            );
        }
    }

    if !policy.allow_cidrs.is_empty()
        && !dst.is_some_and(|ip| policy.allow_cidrs.iter().any(|cidr| ip_in_cidr(ip, cidr)))
    {
        return mk(
            "vm-policy/cidr-allowlist",
            "cidr-not-allowed",
            "exact",
            format!("{} does not match the configured destination CIDR allowlist.", flow.destination),
            "Add the smallest required destination CIDR, or fix service/DNS resolution so traffic targets an allowed address.",
        );
    }

    if !policy.allow_ports.is_empty() && !l4_allowed(flow, &policy.allow_ports) {
        return mk(
            "vm-policy/l4-allowlist",
            "l4-not-allowed",
            "exact",
            format!(
                "protocol {} destination port {} is outside the VM L4 allowlist.",
                protocol_name(flow.protocol), flow.destination_port
            ),
            "Permit only the required protocol/port pair in allow_ports.",
        );
    }

    if let (Some(ip), Some(pod)) = (dst, pod_policy) {
        if pod.deny_addresses.contains(&ip) {
            return mk(
                "pod-policy/peer-deny",
                "pod-explicit-deny",
                "exact",
                format!("{} is explicitly denied by the Pod-identity peer policy.", flow.destination),
                "Update the Pod peer policy/selector resolution if this peer should be reachable.",
            );
        }
        if pod.default_deny && !pod.allow_addresses.contains(&ip) {
            return mk(
                "pod-policy/default-deny",
                "pod-peer-not-allowed",
                "exact",
                format!("{} is not in the Pod-identity allow set while default_deny is enabled.", flow.destination),
                "Add the intended peer through the Kubernetes policy resolver rather than weakening the VM-wide policy.",
            );
        }
    }

    if policy.allow_cidrs.is_empty() && policy.allow_ports.is_empty() && !policy.default_allow {
        return mk(
            "vm-policy/default",
            "default-deny",
            "exact",
            "No explicit allow dimension is configured and the VM policy default is deny.".into(),
            "Add a narrow CIDR and/or L4 allow rule for the required dependency.",
        );
    }

    if policy.max_egress_pps.is_some() || policy.max_egress_mbps.is_some() {
        return mk(
            "vm-policy/rate",
            "rate-limit-possible",
            "probable",
            "The flow passes visible CIDR/L4/Pod checks and this VM has an eBPF rate ceiling.".into(),
            "Inspect fluxvm network stats and traffic rate; raise the ceiling only after confirming sustained legitimate demand.",
        );
    }

    if !policy.groups.is_empty() || !policy.labels.is_empty() || !policy.entities.is_empty() || !policy.allow_fqdns.is_empty() {
        return mk(
            "compiled-policy",
            "compiled-policy-possible",
            "probable",
            "The direct VM policy permits this tuple, but group/entity/FQDN-derived policy is also active.".into(),
            "Inspect /v1/vms/<id>/network/effective and the group/CNP compilation result for this destination.",
        );
    }

    mk(
        "vm-edge",
        "unclassified-drop",
        "probable",
        "The sampled flow is marked drop but no visible static policy branch uniquely explains it.".into(),
        "Check the effective policy, Pod policy, rate state, attachment generation, and service dataplane health; kernel reason codes are the next ABI extension.",
    )
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

fn l4_allowed(flow: &FlowRecord, rules: &[String]) -> bool {
    let wanted = protocol_name(flow.protocol);
    rules.iter().any(|rule| {
        let Some((proto, port)) = rule.split_once('/') else { return false; };
        if !proto.trim().eq_ignore_ascii_case(wanted) {
            return false;
        }
        port.trim().parse::<u16>().ok() == Some(flow.destination_port)
    })
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else { return false; };
    let Ok(network) = network.parse::<IpAddr>() else { return false; };
    let Ok(prefix) = prefix.parse::<u8>() else { return false; };
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) if prefix <= 32 => {
            let ip = u32::from_be_bytes(ip.octets());
            let net = u32::from_be_bytes(net.octets());
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (ip & mask) == (net & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) if prefix <= 128 => {
            let ip = u128::from_be_bytes(ip.octets());
            let net = u128::from_be_bytes(net.octets());
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            (ip & mask) == (net & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vm_key_is_stable_and_nonzero() {
        let id = Uuid::parse_str("12345678-1234-5678-9abc-def012345678").unwrap();
        assert_eq!(vm_key(id), vm_key(id)); assert_ne!(vm_key(id), 0);
    }
    #[test]
    fn pressure_parser_handles_avg10() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("cpu.pressure"), "some avg10=12.50 avg60=1.0 avg300=0.1 total=42\n").unwrap();
        fs::write(d.path().join("memory.pressure"), "some avg10=2.25 avg60=1 avg300=1 total=1\nfull avg10=0.50 avg60=0 avg300=0 total=1\n").unwrap();
        fs::write(d.path().join("io.pressure"), "some avg10=3.00 avg60=1 avg300=1 total=1\nfull avg10=1.25 avg60=0 avg300=0 total=1\n").unwrap();
        let p = read_pressure(d.path()).unwrap();
        assert_eq!(p.cpu_some_avg10, Some(12.5)); assert_eq!(p.io_full_avg10, Some(1.25));
    }
    #[test]
    fn byte_encoding_is_little_endian() { assert_eq!(le_bytes(0x01020304, 4), vec!["04","03","02","01"]); }
    #[test]
    fn cidr_matching_is_dual_stack() {
        assert!(ip_in_cidr("10.4.5.6".parse().unwrap(), "10.4.0.0/16"));
        assert!(!ip_in_cidr("10.5.5.6".parse().unwrap(), "10.4.0.0/16"));
        assert!(ip_in_cidr("2001:db8::5".parse().unwrap(), "2001:db8::/32"));
    }
    #[test]
    fn detective_identifies_exact_l4_drop() {
        let id=Uuid::new_v4();
        let snap=VmRuntimeSnapshot{schema_version:1,vm_id:id,vm_key:vm_key(id),name:"t".into(),backend:"qemu".into(),status:"running".into(),pid:1,tracked_tids:vec![],ebpf_active:true,kernel:Default::default(),process:Default::default(),pressure:Default::default(),network:None,flight:None,findings:vec![]};
        let policy=VmNetworkPolicy{allow_ports:vec!["tcp/443".into()],..Default::default()};
        let flow=FlowRecord{identity:1,family:4,source:"10.0.0.2".into(),destination:"1.1.1.1".into(),source_port:1234,destination_port:80,protocol:6,verdict:"drop".into(),packets:7,bytes:700,last_seen_ns:1};
        let d=diagnose_vm(&snap,&policy,None,&[flow]);
        assert_eq!(d.drop_findings[0].code,"l4-not-allowed");
        assert_eq!(d.drop_findings[0].confidence,"exact");
    }
    #[test]
    fn detective_prefers_exact_default_deny_over_rate_hint() {
        let id=Uuid::new_v4();
        let snap=VmRuntimeSnapshot{schema_version:1,vm_id:id,vm_key:vm_key(id),name:"t".into(),backend:"qemu".into(),status:"running".into(),pid:1,tracked_tids:vec![],ebpf_active:true,kernel:Default::default(),process:Default::default(),pressure:Default::default(),network:None,flight:None,findings:vec![]};
        let policy=VmNetworkPolicy{default_allow:false,max_egress_pps:Some(100),..Default::default()};
        let flow=FlowRecord{identity:1,family:4,source:"10.0.0.2".into(),destination:"1.1.1.1".into(),source_port:1234,destination_port:443,protocol:6,verdict:"drop".into(),packets:1,bytes:64,last_seen_ns:1};
        let d=diagnose_vm(&snap,&policy,None,&[flow]);
        assert_eq!(d.drop_findings[0].code,"default-deny");
        assert_eq!(d.drop_findings[0].confidence,"exact");
    }
    #[test]
    fn audit_only_explicit_deny_is_not_critical() {
        let id=Uuid::new_v4();
        let snap=VmRuntimeSnapshot{schema_version:1,vm_id:id,vm_key:vm_key(id),name:"t".into(),backend:"qemu".into(),status:"running".into(),pid:1,tracked_tids:vec![],ebpf_active:true,kernel:Default::default(),process:Default::default(),pressure:Default::default(),network:None,flight:None,findings:vec![]};
        let policy=VmNetworkPolicy{deny_cidrs:vec!["1.1.1.1/32".into()],audit_mode:true,..Default::default()};
        let flow=FlowRecord{identity:1,family:4,source:"10.0.0.2".into(),destination:"1.1.1.1".into(),source_port:1234,destination_port:443,protocol:6,verdict:"drop".into(),packets:1,bytes:64,last_seen_ns:1};
        let d=diagnose_vm(&snap,&policy,None,&[flow]);
        assert!(d.drop_findings[0].audit_only);
        assert_eq!(d.severity,"warning");
    }
    #[test]
    fn kernel_reason_overrides_policy_inference() {
        let id=Uuid::new_v4();
        let snap=VmRuntimeSnapshot{schema_version:1,vm_id:id,vm_key:vm_key(id),name:"t".into(),backend:"qemu".into(),status:"running".into(),pid:1,tracked_tids:vec![],ebpf_active:true,kernel:Default::default(),process:Default::default(),pressure:Default::default(),network:None,flight:None,findings:vec![]};
        let policy=VmNetworkPolicy{max_egress_pps:Some(10),..Default::default()};
        let flow=FlowRecord{identity:1,family:4,source:"10.0.0.2".into(),destination:"1.1.1.1".into(),source_port:1234,destination_port:443,protocol:6,verdict:"drop".into(),packets:3,bytes:192,last_seen_ns:2};
        let reason=DropReasonRecord{identity:1,family:4,source:flow.source.clone(),destination:flow.destination.clone(),source_port:1234,destination_port:443,protocol:6,reason_code:6,reason:"rate-limit".into(),action:"drop".into(),packets:3,bytes:192,last_seen_ns:2};
        let d=diagnose_vm_with_reasons(&snap,&policy,None,&[flow],&[reason]);
        assert_eq!(d.kernel_reason_records,1);
        assert_eq!(d.drop_findings[0].code,"rate-limit");
        assert_eq!(d.drop_findings[0].confidence,"exact-kernel");
    }

    #[test]
    fn migration_reason_is_warning_not_critical() {
        let id=Uuid::new_v4();
        let snap=VmRuntimeSnapshot{schema_version:1,vm_id:id,vm_key:vm_key(id),name:"t".into(),backend:"qemu".into(),status:"running".into(),pid:1,tracked_tids:vec![],ebpf_active:true,kernel:Default::default(),process:Default::default(),pressure:Default::default(),network:None,flight:None,findings:vec![]};
        let reason=DropReasonRecord{identity:1,family:4,source:"10.0.0.2".into(),destination:"1.1.1.1".into(),source_port:1234,destination_port:443,protocol:6,reason_code:9,reason:"migration-quiesce".into(),action:"drop".into(),packets:1,bytes:64,last_seen_ns:1};
        let d=diagnose_vm_with_reasons(&snap,&VmNetworkPolicy::default(),None,&[],&[reason]);
        assert_eq!(d.severity,"warning");
        assert_eq!(d.drop_findings[0].stage,"migration/quiesce");
    }

    #[test]
    fn flight_latency_bounds_are_stable() {
        assert_eq!(latency_upper_bound_ns(0), Some(1_000));
        assert_eq!(latency_upper_bound_ns(10), Some(1_024_000));
        assert_eq!(latency_upper_bound_ns(24), None);
    }

    #[test]
    fn flight_value_parser_accepts_btf_json() {
        let row = serde_json::json!({"count": 7, "total_ns": 9000, "max_ns": 4000});
        assert_eq!(flight_value_from_row(Some(&row)), FlightValue { count: 7, total_ns: 9000, max_ns: 4000 });
    }

    #[test]
    fn x86_kvm_reason_labels_remain_numeric_safe() {
        if cfg!(target_arch = "x86_64") {
            assert_eq!(kvm_exit_reason_label(10), "cpuid");
            assert_eq!(kvm_exit_reason_label(30), "io-instruction");
        }
        assert!(!kvm_exit_reason_label(0xffff).is_empty());
    }

}
