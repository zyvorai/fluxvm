// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! VM-scoped memory pressure and boot/snapshot profiling (Set 7).
//! The eBPF side records fault/reclaim latency and first KVM/vhost activity;
//! cgroup-v2 remains authoritative for OOM/high/max events and memory PSI.

use crate::{DEFAULT_PIN_ROOT, register_raw, register_record, vm_key};
use anyhow::{Context, Result, anyhow, bail};
use fluxvm_core::model::VmRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

pub const MEMPROF_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MARKER_ROOT: &str = "/run/fluxvm/memprof";
const HIST_BUCKETS: usize = 25;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemprofProbe {
    pub bpffs: bool,
    pub bpftool: bool,
    pub shared_runtime_maps: bool,
    pub maps_loaded: bool,
    pub kvm_entry_link: bool,
    pub page_fault_link: bool,
    pub direct_reclaim_link: bool,
    pub vhost_link: bool,
    pub cgroup_v2: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelMemoryStats {
    pub faults: u64,
    pub major_faults: u64,
    pub fault_total_ns: u64,
    pub fault_max_ns: u64,
    pub reclaim_events: u64,
    pub reclaim_total_ns: u64,
    pub reclaim_max_ns: u64,
    pub ringbuf_lost: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryHistogramBucket {
    pub kind: String,
    pub bucket: u32,
    pub le_ns: Option<u64>,
    pub count: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CgroupMemoryStats {
    pub current_bytes: Option<u64>,
    pub peak_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub anon_bytes: Option<u64>,
    pub file_bytes: Option<u64>,
    pub kernel_bytes: Option<u64>,
    pub pgfault: Option<u64>,
    pub pgmajfault: Option<u64>,
    pub pgscan: Option<u64>,
    pub pgsteal: Option<u64>,
    pub workingset_refault_anon: Option<u64>,
    pub workingset_refault_file: Option<u64>,
    pub events_low: u64,
    pub events_high: u64,
    pub events_max: u64,
    pub events_oom: u64,
    pub events_oom_kill: u64,
    pub events_oom_group_kill: u64,
    pub psi_some_avg10: Option<f64>,
    pub psi_full_avg10: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelBootFirst {
    pub first_kvm_entry_ns: Option<u64>,
    pub first_vhost_activity_ns: Option<u64>,
    pub first_major_fault_ns: Option<u64>,
    pub first_reclaim_ns: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarkerState {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub markers_ns: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BootProfile {
    pub process_start_monotonic_ns: Option<u64>,
    pub process_start_ticks_assumed: Option<u64>,
    pub kernel: KernelBootFirst,
    pub markers_ns: BTreeMap<String, u64>,
    pub process_to_first_kvm_ms: Option<f64>,
    pub process_to_first_vhost_ms: Option<f64>,
    pub process_to_guest_ready_ms: Option<f64>,
    pub pause_control_ms: Option<f64>,
    pub resume_control_ms: Option<f64>,
    pub snapshot_ms: Option<f64>,
    pub restore_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryProfileSnapshot {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub vm_key: u64,
    pub pid: u32,
    pub cgroup_path: Option<PathBuf>,
    pub ebpf_available: bool,
    pub kernel: KernelMemoryStats,
    pub histogram: Vec<MemoryHistogramBucket>,
    pub cgroup: CgroupMemoryStats,
    pub boot: BootProfile,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryEvent {
    pub timestamp_ns: u64,
    pub vm_key: u64,
    pub event_type: u32,
    pub event: String,
    pub tid: u32,
    pub cpu: u32,
    pub duration_ns: u64,
    pub arg0: u64,
}

pub fn probe(pin_root: &Path) -> MemprofProbe {
    let links = pin_root.join("memprof/links");
    MemprofProbe {
        bpffs: Path::new("/sys/fs/bpf").exists(),
        bpftool: command_exists("bpftool"),
        shared_runtime_maps: pin_root.join("maps/tracked_tgids").exists()
            && pin_root.join("maps/tracked_tids").exists()
            && pin_root.join("maps/tracked_cgroups").exists(),
        maps_loaded: mem_map(pin_root, "memprof_stats").exists()
            && mem_map(pin_root, "memprof_hist").exists()
            && mem_map(pin_root, "memprof_first").exists()
            && mem_map(pin_root, "memprof_events").exists(),
        kvm_entry_link: links.join("kvm_entry").exists(),
        page_fault_link: links.join("fault_enter").exists() && links.join("fault_exit").exists(),
        direct_reclaim_link: links.join("reclaim_begin").exists()
            && links.join("reclaim_end").exists(),
        vhost_link: links.join("vhost_wakeup").exists(),
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
    }
}

pub fn load(pin_root: &Path, replace_links: bool) -> Result<Value> {
    let helper = helper_path(
        "FLUXVM_MEMPROF_LOADER",
        "/usr/libexec/fluxvm/fluxvm-memprof-loader",
        "fluxvm-memprof-loader",
    );
    let object = env::var("FLUXVM_MEMPROF_BPF_OBJECT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| "/usr/lib/fluxvm/bpf/fluxvm_memprof.bpf.o".into());
    let mut cmd = Command::new(&helper);
    cmd.arg(&object).arg(pin_root);
    if replace_links {
        cmd.arg("--replace-links");
    }
    let out = cmd
        .output()
        .with_context(|| format!("running {}", helper.display()))?;
    if !out.status.success() {
        bail!(
            "memprof loader failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("decoding memprof loader response")
}

pub fn snapshot_record(
    record: &VmRecord,
    pin_root: &Path,
    marker_root: &Path,
) -> Result<MemoryProfileSnapshot> {
    let pid = record
        .pid
        .ok_or_else(|| anyhow!("VM {} has no VMM pid", record.id))?;
    if probe(pin_root).shared_runtime_maps {
        let _ = register_record(record, pin_root);
    }
    snapshot(
        record.id,
        pid,
        record.cgroup_path.as_deref(),
        pin_root,
        marker_root,
    )
}

pub fn snapshot_raw(
    id: Uuid,
    pid: u32,
    cgroup: Option<&Path>,
    pin_root: &Path,
    marker_root: &Path,
) -> Result<MemoryProfileSnapshot> {
    if probe(pin_root).shared_runtime_maps {
        let _ = register_raw(id, pid, pin_root);
    }
    snapshot(id, pid, cgroup, pin_root, marker_root)
}

pub fn snapshot(
    id: Uuid,
    pid: u32,
    cgroup: Option<&Path>,
    pin_root: &Path,
    marker_root: &Path,
) -> Result<MemoryProfileSnapshot> {
    if !Path::new(&format!("/proc/{pid}")).exists() {
        bail!("pid {pid} does not exist");
    }
    let p = probe(pin_root);
    let key = vm_key(id);
    let kernel = if p.maps_loaded {
        read_kernel(pin_root, key).unwrap_or_default()
    } else {
        KernelMemoryStats::default()
    };
    let histogram = if p.maps_loaded {
        read_histogram(pin_root, key).unwrap_or_default()
    } else {
        Vec::new()
    };
    let first = if p.maps_loaded {
        read_first(pin_root, key).unwrap_or_default()
    } else {
        KernelBootFirst::default()
    };
    let cgroup_path = cgroup.map(normalize_cgroup);
    let (cgroup_stats, cgroup_error) = match cgroup_path.as_deref() {
        Some(path) => match read_cgroup_memory(path) {
            Ok(stats) => (stats, None),
            Err(error) => (CgroupMemoryStats::default(), Some(format!("{error:#}"))),
        },
        None => (CgroupMemoryStats::default(), None),
    };
    let markers = read_markers(id, marker_root).unwrap_or(MarkerState {
        schema_version: MEMPROF_SCHEMA_VERSION,
        vm_id: id,
        markers_ns: BTreeMap::new(),
    });
    let (process_start, ticks) = process_start_monotonic_ns(pid).unwrap_or((0, 0));
    let boot = boot_profile(process_start, ticks, first, markers.markers_ns);
    let mut findings = Vec::new();

    if kernel.major_faults > 0 {
        findings.push(format!(
            "{} eBPF-attributed major page fault(s)",
            kernel.major_faults
        ));
    }
    if kernel.fault_max_ns >= 5_000_000 {
        findings.push(format!(
            "slow page-fault path: {:.2} ms max",
            kernel.fault_max_ns as f64 / 1e6
        ));
    }
    if kernel.reclaim_max_ns >= 20_000_000 {
        findings.push(format!(
            "slow direct reclaim: {:.2} ms max",
            kernel.reclaim_max_ns as f64 / 1e6
        ));
    }
    if kernel.ringbuf_lost > 0 {
        findings.push(format!(
            "{} memory-profiler live event(s) lost to ring-buffer pressure",
            kernel.ringbuf_lost
        ));
    }
    if cgroup_stats.events_high > 0 {
        findings.push(format!(
            "memory.high throttling observed {} time(s)",
            cgroup_stats.events_high
        ));
    }
    if cgroup_stats.events_oom > 0 {
        findings.push(format!(
            "cgroup OOM observed {} time(s)",
            cgroup_stats.events_oom
        ));
    }
    if cgroup_stats.events_oom_kill > 0 {
        findings.push(format!(
            "cgroup OOM killed {} task(s)",
            cgroup_stats.events_oom_kill
        ));
    }
    if cgroup_stats.psi_full_avg10.unwrap_or(0.0) >= 1.0 {
        findings.push(format!(
            "full memory PSI avg10 is {:.2}%",
            cgroup_stats.psi_full_avg10.unwrap_or(0.0)
        ));
    }
    if let (Some(current), Some(max)) = (cgroup_stats.current_bytes, cgroup_stats.max_bytes) {
        if max > 0 && current.saturating_mul(100) >= max.saturating_mul(90) {
            findings.push(format!(
                "memory.current is {:.1}% of memory.max",
                current as f64 * 100.0 / max as f64
            ));
        }
    }
    if let Some(error) = cgroup_error {
        findings.push(format!("cgroup-v2 memory telemetry unavailable: {error}"));
    }
    if !p.maps_loaded {
        findings.push("Set-7 eBPF maps are not loaded; cgroup-v2 memory telemetry remains available when a valid cgroup is supplied".into());
    }
    if p.maps_loaded && !p.page_fault_link {
        findings.push(
            "handle_mm_fault probes unavailable; kernel fault-latency samples are disabled".into(),
        );
    }
    if p.maps_loaded && !p.direct_reclaim_link {
        findings.push("direct-reclaim tracepoint pair unavailable; cgroup memory.events/PSI remain authoritative".into());
    }

    Ok(MemoryProfileSnapshot {
        schema_version: MEMPROF_SCHEMA_VERSION,
        vm_id: id,
        vm_key: key,
        pid,
        cgroup_path,
        ebpf_available: p.maps_loaded,
        kernel,
        histogram,
        cgroup: cgroup_stats,
        boot,
        findings,
    })
}

pub fn mark(id: Uuid, phase: &str, marker_root: &Path) -> Result<MarkerState> {
    validate_phase(phase)?;
    fs::create_dir_all(marker_root)
        .with_context(|| format!("creating {}", marker_root.display()))?;
    let mut state = read_markers(id, marker_root).unwrap_or(MarkerState {
        schema_version: MEMPROF_SCHEMA_VERSION,
        vm_id: id,
        markers_ns: BTreeMap::new(),
    });
    state.schema_version = MEMPROF_SCHEMA_VERSION;
    state.vm_id = id;
    state.markers_ns.insert(phase.to_string(), monotonic_ns()?);
    let path = marker_path(id, marker_root);
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("publishing {}", path.display()))?;
    Ok(state)
}

pub fn clear_markers(id: Uuid, marker_root: &Path) -> Result<()> {
    let path = marker_path(id, marker_root);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

pub fn events(id: Uuid, pin_root: &Path, seconds: u64, limit: usize) -> Result<Vec<MemoryEvent>> {
    let helper = helper_path(
        "FLUXVM_MEMPROF_EVENTS",
        "/usr/libexec/fluxvm/fluxvm-memprof-events",
        "fluxvm-memprof-events",
    );
    let pin = mem_map(pin_root, "memprof_events");
    if !pin.exists() {
        bail!("{} is not loaded", pin.display());
    }
    let out = Command::new(&helper)
        .arg(&pin)
        .arg(vm_key(id).to_string())
        .arg(seconds.clamp(1, 3600).to_string())
        .arg(limit.clamp(1, 100_000).to_string())
        .output()
        .with_context(|| format!("running {}", helper.display()))?;
    if !out.status.success() {
        bail!(
            "memprof event reader failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8(out.stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("decoding memprof event"))
        .collect()
}

pub fn prometheus(rows: &[MemoryProfileSnapshot]) -> String {
    let mut out = String::new();
    out.push_str("# HELP fluxvm_memprof_cgroup_memory_current_bytes Current cgroup memory usage.\n# TYPE fluxvm_memprof_cgroup_memory_current_bytes gauge\n");
    for row in rows {
        let labels = format!("vm=\"{}\"", row.vm_id);
        metric_opt_u64(
            &mut out,
            "fluxvm_memprof_cgroup_memory_current_bytes",
            &labels,
            row.cgroup.current_bytes,
        );
        metric_opt_u64(
            &mut out,
            "fluxvm_memprof_cgroup_memory_peak_bytes",
            &labels,
            row.cgroup.peak_bytes,
        );
        metric_opt_u64(
            &mut out,
            "fluxvm_memprof_cgroup_memory_max_bytes",
            &labels,
            row.cgroup.max_bytes,
        );
        out.push_str(&format!(
            "fluxvm_memprof_faults_total{{{labels}}} {}\n",
            row.kernel.faults
        ));
        out.push_str(&format!(
            "fluxvm_memprof_major_faults_total{{{labels}}} {}\n",
            row.kernel.major_faults
        ));
        out.push_str(&format!(
            "fluxvm_memprof_direct_reclaim_total{{{labels}}} {}\n",
            row.kernel.reclaim_events
        ));
        out.push_str(&format!(
            "fluxvm_memprof_events_oom_total{{{labels}}} {}\n",
            row.cgroup.events_oom
        ));
        out.push_str(&format!(
            "fluxvm_memprof_events_oom_kill_total{{{labels}}} {}\n",
            row.cgroup.events_oom_kill
        ));
        out.push_str(&format!(
            "fluxvm_memprof_events_high_total{{{labels}}} {}\n",
            row.cgroup.events_high
        ));
        if let Some(v) = row.cgroup.psi_some_avg10 {
            out.push_str(&format!(
                "fluxvm_memprof_memory_psi_some_avg10{{{labels}}} {v}\n"
            ));
        }
        if let Some(v) = row.cgroup.psi_full_avg10 {
            out.push_str(&format!(
                "fluxvm_memprof_memory_psi_full_avg10{{{labels}}} {v}\n"
            ));
        }
        metric_opt_f64(
            &mut out,
            "fluxvm_memprof_process_to_first_kvm_seconds",
            &labels,
            row.boot.process_to_first_kvm_ms.map(|v| v / 1000.0),
        );
        metric_opt_f64(
            &mut out,
            "fluxvm_memprof_process_to_first_vhost_seconds",
            &labels,
            row.boot.process_to_first_vhost_ms.map(|v| v / 1000.0),
        );
        metric_opt_f64(
            &mut out,
            "fluxvm_memprof_process_to_guest_ready_seconds",
            &labels,
            row.boot.process_to_guest_ready_ms.map(|v| v / 1000.0),
        );
        metric_opt_f64(
            &mut out,
            "fluxvm_memprof_snapshot_seconds",
            &labels,
            row.boot.snapshot_ms.map(|v| v / 1000.0),
        );
        metric_opt_f64(
            &mut out,
            "fluxvm_memprof_restore_seconds",
            &labels,
            row.boot.restore_ms.map(|v| v / 1000.0),
        );
        append_histogram(
            &mut out,
            &labels,
            &row.histogram,
            "page-fault",
            "fluxvm_memprof_page_fault_seconds",
        );
        append_histogram(
            &mut out,
            &labels,
            &row.histogram,
            "direct-reclaim",
            "fluxvm_memprof_direct_reclaim_seconds",
        );
    }
    out
}

fn append_histogram(
    out: &mut String,
    labels: &str,
    rows: &[MemoryHistogramBucket],
    kind: &str,
    metric: &str,
) {
    let mut counts = [0u64; HIST_BUCKETS];
    let mut sum_ns = 0u64;
    for row in rows.iter().filter(|r| r.kind == kind) {
        if let Some(slot) = counts.get_mut(row.bucket as usize) {
            *slot = slot.saturating_add(row.count);
        }
        sum_ns = sum_ns.saturating_add(row.total_ns);
    }
    let mut cumulative = 0u64;
    for (bucket, count) in counts.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        let le = if bucket + 1 == HIST_BUCKETS {
            "+Inf".to_string()
        } else {
            format!(
                "{:.9}",
                bucket_le_ns(bucket as u32).unwrap_or(0) as f64 / 1e9
            )
        };
        out.push_str(&format!(
            "{metric}_bucket{{{labels},le=\"{le}\"}} {cumulative}\n"
        ));
    }
    out.push_str(&format!("{metric}_count{{{labels}}} {cumulative}\n"));
    out.push_str(&format!(
        "{metric}_sum{{{labels}}} {:.9}\n",
        sum_ns as f64 / 1e9
    ));
}

fn metric_opt_u64(out: &mut String, name: &str, labels: &str, value: Option<u64>) {
    if let Some(v) = value {
        out.push_str(&format!("{name}{{{labels}}} {v}\n"));
    }
}
fn metric_opt_f64(out: &mut String, name: &str, labels: &str, value: Option<f64>) {
    if let Some(v) = value {
        out.push_str(&format!("{name}{{{labels}}} {v}\n"));
    }
}

fn boot_profile(
    start: u64,
    ticks: u64,
    kernel: KernelBootFirst,
    markers: BTreeMap<String, u64>,
) -> BootProfile {
    let start_opt = (start > 0).then_some(start);
    BootProfile {
        process_start_monotonic_ns: start_opt,
        process_start_ticks_assumed: (ticks > 0).then_some(ticks),
        process_to_first_kvm_ms: delta_ms(start_opt, kernel.first_kvm_entry_ns),
        process_to_first_vhost_ms: delta_ms(start_opt, kernel.first_vhost_activity_ns),
        process_to_guest_ready_ms: delta_ms(start_opt, markers.get("guest-ready").copied()),
        pause_control_ms: delta_ms(
            markers.get("pause-request").copied(),
            markers.get("paused").copied(),
        ),
        resume_control_ms: delta_ms(
            markers.get("resume-request").copied(),
            markers.get("resumed").copied(),
        ),
        snapshot_ms: delta_ms(
            markers.get("snapshot-begin").copied(),
            markers.get("snapshot-end").copied(),
        ),
        restore_ms: delta_ms(
            markers.get("restore-begin").copied(),
            markers.get("restore-end").copied(),
        ),
        kernel,
        markers_ns: markers,
    }
}

fn delta_ms(start: Option<u64>, end: Option<u64>) -> Option<f64> {
    match (start, end) {
        (Some(a), Some(b)) if b >= a => Some((b - a) as f64 / 1e6),
        _ => None,
    }
}

fn read_kernel(pin_root: &Path, wanted: u64) -> Result<KernelMemoryStats> {
    for row in bpftool_rows(&mem_map(pin_root, "memprof_stats"))? {
        let key = bytes(row.get("key"))?;
        if read_u64(&key, 0)? != wanted {
            continue;
        }
        let value = bytes(row.get("value"))?;
        if value.len() < 64 {
            bail!("memprof_stats value is {} bytes, expected 64", value.len());
        }
        return Ok(KernelMemoryStats {
            faults: read_u64(&value, 0)?,
            major_faults: read_u64(&value, 8)?,
            fault_total_ns: read_u64(&value, 16)?,
            fault_max_ns: read_u64(&value, 24)?,
            reclaim_events: read_u64(&value, 32)?,
            reclaim_total_ns: read_u64(&value, 40)?,
            reclaim_max_ns: read_u64(&value, 48)?,
            ringbuf_lost: read_u64(&value, 56)?,
        });
    }
    Ok(KernelMemoryStats::default())
}

fn read_histogram(pin_root: &Path, wanted: u64) -> Result<Vec<MemoryHistogramBucket>> {
    let mut out = Vec::new();
    for row in bpftool_rows(&mem_map(pin_root, "memprof_hist"))? {
        let key = bytes(row.get("key"))?;
        if key.len() < 16 || read_u64(&key, 0)? != wanted {
            continue;
        }
        let kind = read_u32(&key, 8)?;
        let bucket = read_u32(&key, 12)?;
        let value = bytes(row.get("value"))?;
        if value.len() < 24 {
            continue;
        }
        out.push(MemoryHistogramBucket {
            kind: match kind {
                1 => "page-fault",
                2 => "direct-reclaim",
                _ => "unknown",
            }
            .into(),
            bucket,
            le_ns: bucket_le_ns(bucket),
            count: read_u64(&value, 0)?,
            total_ns: read_u64(&value, 8)?,
            max_ns: read_u64(&value, 16)?,
        });
    }
    out.sort_by_key(|v| (v.kind.clone(), v.bucket));
    Ok(out)
}

fn read_first(pin_root: &Path, wanted: u64) -> Result<KernelBootFirst> {
    for row in bpftool_rows(&mem_map(pin_root, "memprof_first"))? {
        let key = bytes(row.get("key"))?;
        if read_u64(&key, 0)? != wanted {
            continue;
        }
        let value = bytes(row.get("value"))?;
        if value.len() < 32 {
            continue;
        }
        return Ok(KernelBootFirst {
            first_kvm_entry_ns: nonzero(read_u64(&value, 0)?),
            first_vhost_activity_ns: nonzero(read_u64(&value, 8)?),
            first_major_fault_ns: nonzero(read_u64(&value, 16)?),
            first_reclaim_ns: nonzero(read_u64(&value, 24)?),
        });
    }
    Ok(KernelBootFirst::default())
}

fn read_cgroup_memory(path: &Path) -> Result<CgroupMemoryStats> {
    if !path.exists() {
        bail!("cgroup {} does not exist", path.display());
    }
    let stat = kv_u64(&path.join("memory.stat"));
    let events = kv_u64(&path.join("memory.events"));
    let psi = pressure(&path.join("memory.pressure"));
    Ok(CgroupMemoryStats {
        current_bytes: scalar_u64(&path.join("memory.current")),
        peak_bytes: scalar_u64(&path.join("memory.peak")),
        max_bytes: scalar_u64(&path.join("memory.max")),
        anon_bytes: stat.get("anon").copied(),
        file_bytes: stat.get("file").copied(),
        kernel_bytes: stat.get("kernel").copied(),
        pgfault: stat.get("pgfault").copied(),
        pgmajfault: stat.get("pgmajfault").copied(),
        pgscan: stat.get("pgscan").copied(),
        pgsteal: stat.get("pgsteal").copied(),
        workingset_refault_anon: stat.get("workingset_refault_anon").copied(),
        workingset_refault_file: stat.get("workingset_refault_file").copied(),
        events_low: events.get("low").copied().unwrap_or(0),
        events_high: events.get("high").copied().unwrap_or(0),
        events_max: events.get("max").copied().unwrap_or(0),
        events_oom: events.get("oom").copied().unwrap_or(0),
        events_oom_kill: events.get("oom_kill").copied().unwrap_or(0),
        events_oom_group_kill: events.get("oom_group_kill").copied().unwrap_or(0),
        psi_some_avg10: psi.get("some.avg10").copied(),
        psi_full_avg10: psi.get("full.avg10").copied(),
    })
}

fn normalize_cgroup(path: &Path) -> PathBuf {
    if path.is_absolute() && path.starts_with("/sys/fs/cgroup") {
        path.to_path_buf()
    } else if path.is_absolute() {
        Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").unwrap_or(path))
    } else {
        Path::new("/sys/fs/cgroup").join(path)
    }
}

fn kv_u64(path: &Path) -> BTreeMap<String, u64> {
    fs::read_to_string(path)
        .ok()
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    let mut it = line.split_whitespace();
                    Some((it.next()?.to_string(), it.next()?.parse().ok()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn pressure(path: &Path) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let Some(kind) = parts.next() else {
                continue;
            };
            for field in parts {
                if let Some((name, value)) = field.split_once('=') {
                    if name == "avg10" {
                        if let Ok(v) = value.parse() {
                            out.insert(format!("{kind}.avg10"), v);
                        }
                    }
                }
            }
        }
    }
    out
}

fn scalar_u64(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;
    let text = text.trim();
    if text == "max" {
        None
    } else {
        text.parse().ok()
    }
}

fn process_start_monotonic_ns(pid: u32) -> Result<(u64, u64)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat.rfind(')').context("malformed /proc pid/stat comm")?;
    let rest = stat.get(end + 2..).context("malformed /proc pid/stat")?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let start_ticks: u64 = fields
        .get(19)
        .context("/proc pid/stat missing starttime")?
        .parse()?;
    let hz = Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(100);
    Ok((start_ticks.saturating_mul(1_000_000_000) / hz, hz))
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}
unsafe extern "C" {
    fn clock_gettime(clockid: i32, tp: *mut Timespec) -> i32;
}

fn monotonic_ns() -> Result<u64> {
    const CLOCK_MONOTONIC: i32 = 1;
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        bail!("CLOCK_MONOTONIC returned a negative timestamp");
    }
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
}

fn validate_phase(phase: &str) -> Result<()> {
    const PHASES: &[&str] = &[
        "guest-ready",
        "pause-request",
        "paused",
        "resume-request",
        "resumed",
        "snapshot-begin",
        "snapshot-end",
        "restore-begin",
        "restore-end",
    ];
    if PHASES.contains(&phase) {
        Ok(())
    } else {
        bail!(
            "invalid phase {phase}; expected one of {}",
            PHASES.join(", ")
        )
    }
}

fn marker_path(id: Uuid, root: &Path) -> PathBuf {
    root.join(format!("{id}.json"))
}
fn read_markers(id: Uuid, root: &Path) -> Result<MarkerState> {
    let path = marker_path(id, root);
    let state: MarkerState = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    if state.vm_id != id {
        bail!("marker file VM id mismatch");
    }
    Ok(state)
}

fn mem_map(root: &Path, name: &str) -> PathBuf {
    root.join("memprof/maps").join(name)
}
fn helper_path(env_name: &str, installed: &str, fallback: &str) -> PathBuf {
    env::var(env_name).map(PathBuf::from).unwrap_or_else(|_| {
        let installed = PathBuf::from(installed);
        if installed.exists() {
            installed
        } else {
            PathBuf::from(fallback)
        }
    })
}
fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v -- {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn bpftool_rows(path: &Path) -> Result<Vec<Value>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(path)
        .output()
        .with_context(|| format!("dumping {}", path.display()))?;
    if !out.status.success() {
        bail!(
            "bpftool dump {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let value: Value = serde_json::from_slice(&out.stdout)?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("bpftool returned non-array JSON for {}", path.display()))
}

fn bytes(value: Option<&Value>) -> Result<Vec<u8>> {
    let arr = value
        .and_then(Value::as_array)
        .context("bpftool key/value is not a byte array")?;
    arr.iter()
        .map(|v| {
            if let Some(n) = v.as_u64() {
                return u8::try_from(n).context("bpftool byte >255");
            }
            if let Some(s) = v.as_str() {
                let s = s.strip_prefix("0x").unwrap_or(s);
                return u8::from_str_radix(s, 16).context("bpftool hex byte");
            }
            bail!("invalid bpftool byte {v}")
        })
        .collect()
}
fn read_u64(v: &[u8], at: usize) -> Result<u64> {
    let b: [u8; 8] = v.get(at..at + 8).context("short u64")?.try_into().unwrap();
    Ok(u64::from_le_bytes(b))
}
fn read_u32(v: &[u8], at: usize) -> Result<u32> {
    let b: [u8; 4] = v.get(at..at + 4).context("short u32")?.try_into().unwrap();
    Ok(u32::from_le_bytes(b))
}
fn nonzero(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}
fn bucket_le_ns(bucket: u32) -> Option<u64> {
    if bucket as usize + 1 >= HIST_BUCKETS {
        None
    } else {
        Some(1000u64.saturating_mul(1u64 << bucket))
    }
}

pub fn default_pin_root() -> PathBuf {
    env::var("FLUXVM_INTEL_PIN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_PIN_ROOT.into())
}
pub fn default_marker_root() -> PathBuf {
    env::var("FLUXVM_MEMPROF_MARKER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_MARKER_ROOT.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_durations_are_monotonic_and_never_negative() {
        let mut markers = BTreeMap::new();
        markers.insert("guest-ready".into(), 3_000_000_000);
        markers.insert("snapshot-begin".into(), 4_000_000_000);
        markers.insert("snapshot-end".into(), 4_250_000_000);
        let boot = boot_profile(
            1_000_000_000,
            100,
            KernelBootFirst {
                first_kvm_entry_ns: Some(1_500_000_000),
                ..Default::default()
            },
            markers,
        );
        assert_eq!(boot.process_to_first_kvm_ms, Some(500.0));
        assert_eq!(boot.process_to_guest_ready_ms, Some(2000.0));
        assert_eq!(boot.snapshot_ms, Some(250.0));
        assert_eq!(delta_ms(Some(5), Some(4)), None);
    }

    #[test]
    fn bucket_bounds_match_bpf_contract() {
        assert_eq!(bucket_le_ns(0), Some(1000));
        assert_eq!(bucket_le_ns(10), Some(1_024_000));
        assert_eq!(bucket_le_ns(24), None);
    }

    #[test]
    fn phases_are_closed_set() {
        assert!(validate_phase("guest-ready").is_ok());
        assert!(validate_phase("snapshot-begin").is_ok());
        assert!(validate_phase("arbitrary").is_err());
    }
}
