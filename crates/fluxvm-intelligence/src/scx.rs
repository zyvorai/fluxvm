// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Sentinel Set 11E: VM-aware sched_ext control plane.
//!
//! The BPF scheduler itself runs in partial-switch mode. This module discovers
//! VMM vCPU threads, derives a topology-aware CPU placement, stores per-thread
//! VM weight/slice/latency policy, and then opts only those TIDs into SCHED_EXT.
//! No host-wide scheduler takeover is performed.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::{DEFAULT_PIN_ROOT, vm_key};
use crate::topology::{self, SteeringAction};

pub const SCX_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_SCX_PIN_ROOT: &str = "/sys/fs/bpf/fluxvm/scx";
pub const DEFAULT_SCX_STATE_ROOT: &str = "/var/lib/fluxvm/scx";
pub const DEFAULT_SCX_OBJECT: &str = "/usr/lib/fluxvm/bpf/fluxvm_scx.bpf.o";
pub const SCHED_EXT_POLICY: i32 = 7;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScxClass {
    Latency,
    #[default]
    Balanced,
    Throughput,
    Background,
}

impl ScxClass {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "latency" | "low-latency" => Ok(Self::Latency),
            "balanced" | "default" => Ok(Self::Balanced),
            "throughput" => Ok(Self::Throughput),
            "background" | "batch" => Ok(Self::Background),
            _ => bail!("class must be latency|balanced|throughput|background"),
        }
    }

    fn defaults(self) -> (u32, u64, u64) {
        match self {
            Self::Latency => (200, 500_000, 2_000_000),
            Self::Balanced => (100, 1_000_000, 5_000_000),
            Self::Throughput => (120, 2_000_000, 10_000_000),
            Self::Background => (50, 2_000_000, 20_000_000),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskSchedulerState {
    pub tid: u32,
    pub policy: i32,
    pub priority: i32,
    pub cpus: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScxTaskPlan {
    pub tid: u32,
    pub vcpu: u32,
    pub comm: String,
    pub target_cpu: u32,
    pub old: TaskSchedulerState,
    pub weight: u32,
    pub slice_ns: u64,
    pub latency_target_ns: u64,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScxPlan {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub vm_key: u64,
    pub pid: u32,
    pub class: ScxClass,
    pub generated_unix_seconds: u64,
    pub topology_source: String,
    pub observed_runnable_delay_max_ns: u64,
    pub tasks: Vec<ScxTaskPlan>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScxReceipt {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub applied_unix_seconds: u64,
    pub scheduler_started_by_apply: bool,
    pub plan: ScxPlan,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScxVmStats {
    pub enqueues: u64,
    pub direct_dispatches: u64,
    pub shared_dispatches: u64,
    pub dispatch_calls: u64,
    pub running_calls: u64,
    pub stopping_calls: u64,
    pub runtime_ns: u64,
    pub queue_delay_ns: u64,
    pub queue_delay_max_ns: u64,
    pub latency_violations: u64,
    pub fallback_enqueues: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScxProbe {
    pub schema_version: u32,
    pub sched_ext_sysfs: bool,
    pub sched_ext_state: String,
    pub current_ops: Option<String>,
    pub kernel_btf: bool,
    pub bpftool: bool,
    pub taskctl: bool,
    pub loader: bool,
    pub bpf_object: bool,
    pub topology_maps: bool,
    pub fluxvm_link_pinned: bool,
    pub supported_for_apply: bool,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScxStatus {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub probe: ScxProbe,
    pub receipt: Option<ScxReceipt>,
    pub stats: Option<ScxVmStats>,
    pub findings: Vec<String>,
}

pub fn probe(pin_root: &Path) -> ScxProbe {
    let sched_root = Path::new("/sys/kernel/sched_ext");
    let state = fs::read_to_string(sched_root.join("state"))
        .unwrap_or_else(|_| "unavailable".into())
        .trim()
        .to_string();
    let current_ops = current_ops();
    let bpftool = command_exists("bpftool");
    let taskctl = command_exists(&taskctl_helper());
    let loader = command_exists(&loader_helper());
    let object = Path::new(&object_path()).exists();
    let topology_maps = Path::new(topology::DEFAULT_TOPOLOGY_PIN_ROOT)
        .join("maps/topo_tracked_vcpus")
        .exists();
    let fluxvm_link = pin_root.join("links/scheduler").exists();
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    if !sched_root.join("state").exists() {
        blockers.push("kernel does not expose /sys/kernel/sched_ext/state; CONFIG_SCHED_CLASS_EXT or a sufficiently new kernel is required".into());
    }
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        blockers.push("kernel BTF is missing; target-specific sched_ext CO-RE object cannot be verified".into());
    }
    if !bpftool {
        blockers.push("bpftool is required for task-profile/stat map control".into());
    }
    if !taskctl {
        blockers.push("fluxvm-scx-taskctl is not installed".into());
    }
    if !loader {
        blockers.push("fluxvm-scx-loader is not installed".into());
    }
    if !object {
        blockers.push("target-kernel fluxvm_scx.bpf.o is not installed".into());
    }
    if state == "enabled" && current_ops.as_deref() != Some("fluxvm_scx") {
        blockers.push(format!("another sched_ext scheduler is already active: {}", current_ops.clone().unwrap_or_else(|| "unknown".into())));
    }
    if !topology_maps {
        warnings.push("Set-8 topology maps are not loaded; planner will preserve each vCPU's current allowed CPU set instead of deriving NUMA/IRQ placement".into());
    }
    warnings.push("sched_ext BPF APIs are kernel-version dependent; rebuild fluxvm_scx.bpf.o against the target kernel's sched_ext headers after a kernel upgrade".into());
    ScxProbe {
        schema_version: SCX_SCHEMA_VERSION,
        sched_ext_sysfs: sched_root.join("state").exists(),
        sched_ext_state: state,
        current_ops,
        kernel_btf: Path::new("/sys/kernel/btf/vmlinux").exists(),
        bpftool,
        taskctl,
        loader,
        bpf_object: object,
        topology_maps,
        fluxvm_link_pinned: fluxvm_link,
        supported_for_apply: blockers.is_empty(),
        blockers,
        warnings,
    }
}

pub fn build_plan(
    id: Uuid,
    pid: u32,
    class: ScxClass,
    weight_override: Option<u32>,
    slice_us_override: Option<u64>,
    latency_target_us_override: Option<u64>,
) -> Result<ScxPlan> {
    ensure_pid(pid)?;
    let threads = topology::discover_vcpus(pid)?;
    let (base_weight, base_slice, base_target) = class.defaults();
    let mut weight = weight_override.unwrap_or(base_weight);
    let mut slice_ns = slice_us_override.unwrap_or(base_slice / 1_000).saturating_mul(1_000);
    let target_ns = latency_target_us_override.unwrap_or(base_target / 1_000).saturating_mul(1_000);
    if !(25..=400).contains(&weight) {
        bail!("weight must be 25..=400");
    }
    if !(100_000..=10_000_000).contains(&slice_ns) {
        bail!("slice must be 100..=10000 microseconds");
    }
    if target_ns > 10_000_000_000 {
        bail!("latency target must be <= 10 seconds");
    }

    let observed_delay = crate::snapshot_raw(id, pid, Path::new(DEFAULT_PIN_ROOT))
        .map(|s| s.kernel.runnable_delay_max_ns)
        .unwrap_or(0);
    let mut warnings = Vec::new();
    if target_ns > 0 && observed_delay > target_ns.saturating_mul(2) {
        let old = weight;
        weight = weight.saturating_mul(2).min(400);
        if matches!(class, ScxClass::Latency | ScxClass::Balanced) {
            slice_ns = slice_ns.min(500_000);
        }
        warnings.push(format!(
            "observed runnable delay {:.2} ms exceeds 2x the {:.2} ms target; plan boosts weight {}→{} and caps latency-oriented slice at {:.2} ms",
            observed_delay as f64 / 1e6,
            target_ns as f64 / 1e6,
            old,
            weight,
            slice_ns as f64 / 1e6,
        ));
    }

    let mut cpu_for_tid = BTreeMap::<u32, u32>::new();
    let topology_source;
    match topology::snapshot(id, pid, None, Path::new(topology::DEFAULT_TOPOLOGY_PIN_ROOT))
        .and_then(|s| topology::plan(&s))
    {
        Ok(plan) => {
            for action in plan.actions {
                if let SteeringAction::TaskAffinity { tid, new, .. } = action {
                    if let Ok(cpu) = new.parse::<u32>() {
                        cpu_for_tid.insert(tid, cpu);
                    }
                }
            }
            topology_source = "set8-topology-intelligence".to_string();
        }
        Err(err) => {
            topology_source = "current-affinity-fallback".to_string();
            warnings.push(format!("topology planner unavailable: {err:#}; preserving one CPU from each current vCPU affinity"));
        }
    }

    let mut tasks = Vec::new();
    for thread in threads {
        let old = task_state(thread.tid)?;
        if !matches!(old.policy, 0 | 3 | 5 | SCHED_EXT_POLICY) {
            bail!("vCPU tid {} uses scheduler policy {}; refusing to override RT/deadline policy", thread.tid, old.policy);
        }
        let allowed = parse_cpu_list(&old.cpus)?;
        if allowed.is_empty() {
            bail!("vCPU tid {} has empty CPU affinity", thread.tid);
        }
        let proposed = cpu_for_tid.get(&thread.tid).copied();
        let target_cpu = proposed.filter(|c| allowed.contains(c)).unwrap_or(allowed[0]);
        let mut rationale = Vec::new();
        if proposed == Some(target_cpu) {
            rationale.push("CPU selected by Set-8 NUMA/IRQ topology planner and still permitted by the task's current affinity".into());
        } else if proposed.is_some() {
            rationale.push("Set-8 proposed CPU is outside the task's current allowed affinity/cpuset; kept the first currently allowed CPU".into());
        } else {
            rationale.push("Set-8 topology plan unavailable; kept the first CPU from the current affinity".into());
        }
        rationale.push(format!("class {:?}: weight={}, slice={:.3} ms, queue-latency target={:.3} ms", class, weight, slice_ns as f64 / 1e6, target_ns as f64 / 1e6));
        tasks.push(ScxTaskPlan {
            tid: thread.tid,
            vcpu: thread.vcpu,
            comm: thread.comm,
            target_cpu,
            old,
            weight,
            slice_ns,
            latency_target_ns: target_ns,
            rationale,
        });
    }
    tasks.sort_by_key(|t| t.vcpu);
    Ok(ScxPlan {
        schema_version: SCX_SCHEMA_VERSION,
        vm_id: id,
        vm_key: vm_key(id),
        pid,
        class,
        generated_unix_seconds: unix_seconds(),
        topology_source,
        observed_runnable_delay_max_ns: observed_delay,
        tasks,
        warnings,
    })
}

pub fn apply_plan(plan: &ScxPlan, pin_root: &Path, state_root: &Path) -> Result<ScxReceipt> {
    validate_plan(plan)?;
    fs::create_dir_all(state_root)?;
    let receipt_path = receipt_path(state_root, plan.vm_id);
    if receipt_path.exists() {
        bail!("{} already has an active sched_ext receipt; rollback it before applying another plan", plan.vm_id);
    }
    for task in &plan.tasks {
        preflight_task(plan.pid, task)?;
    }

    let before = probe(pin_root);
    if !before.supported_for_apply {
        bail!("sched_ext preflight failed: {}", before.blockers.join("; "));
    }
    let mut started = false;
    if before.sched_ext_state != "enabled" {
        start_scheduler(pin_root)?;
        started = true;
    } else if before.current_ops.as_deref() != Some("fluxvm_scx") || !before.fluxvm_link_pinned {
        bail!("sched_ext is enabled but not through FluxVM's pinned scheduler link");
    }

    let profiles = pin_root.join("maps/scx_task_profiles");
    let stats_map = pin_root.join("maps/scx_vm_stats");
    if !profiles.exists() || !stats_map.exists() {
        if started {
            let _ = stop_scheduler(pin_root);
        }
        bail!("required sched_ext maps are missing after scheduler attach under {}", pin_root.display());
    }
    let zero_stats = vec![0u8; 88];
    if let Err(err) = bpftool_update(&stats_map, &plan.vm_key.to_ne_bytes(), &zero_stats) {
        if started {
            let _ = stop_scheduler(pin_root);
        }
        return Err(err.context("pre-seeding sched_ext VM statistics map"));
    }

    let mut applied: Vec<&ScxTaskPlan> = Vec::new();
    for task in &plan.tasks {
        if let Err(err) = update_profile(&profiles, plan.vm_key, plan.pid, task)
            .and_then(|_| set_ext(task.tid, task.target_cpu))
        {
            let _ = delete_profile(&profiles, task.tid);
            for done in applied.into_iter().rev() {
                let _ = restore_task(&done.old);
                let _ = delete_profile(&profiles, done.tid);
            }
            let _ = cleanup_vm_stats(plan.vm_id, pin_root);
            if started {
                let _ = stop_scheduler(pin_root);
            }
            return Err(err.context("sched_ext apply failed; already-converted vCPUs were rolled back best-effort"));
        }
        applied.push(task);
    }

    let receipt = ScxReceipt {
        schema_version: SCX_SCHEMA_VERSION,
        vm_id: plan.vm_id,
        applied_unix_seconds: unix_seconds(),
        scheduler_started_by_apply: started,
        plan: plan.clone(),
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
    if let Err(err) = atomic_write(&receipt_path, &receipt_bytes) {
        for done in applied.iter().rev() {
            let _ = restore_task(&done.old);
            let _ = delete_profile(&profiles, done.tid);
        }
        let _ = cleanup_vm_stats(plan.vm_id, pin_root);
        if started {
            let _ = stop_scheduler(pin_root);
        }
        return Err(err.context("persisting sched_ext receipt; converted vCPUs were rolled back best-effort"));
    }
    Ok(receipt)
}

pub fn rollback(id: Uuid, pin_root: &Path, state_root: &Path) -> Result<()> {
    let path = receipt_path(state_root, id);
    let receipt: ScxReceipt = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    let profiles = pin_root.join("maps/scx_task_profiles");

    for task in &receipt.plan.tasks {
        if tgid_of(task.tid) != Some(receipt.plan.pid) {
            bail!("refuse rollback: tid {} no longer belongs to VMM tgid {}; this may be PID reuse", task.tid, receipt.plan.pid);
        }
    }
    for task in receipt.plan.tasks.iter().rev() {
        restore_task(&task.old).with_context(|| format!("restoring vCPU tid {}", task.tid))?;
        if profiles.exists() {
            let _ = delete_profile(&profiles, task.tid);
        }
    }
    fs::remove_file(&path)?;
    cleanup_vm_stats(id, pin_root).ok();
    if no_receipts(state_root)? && current_ops().as_deref() == Some("fluxvm_scx") {
        stop_scheduler(pin_root)?;
    }
    Ok(())
}

pub fn reconcile(pin_root: &Path, state_root: &Path) -> Result<usize> {
    if !state_root.exists() {
        return Ok(0);
    }
    let profiles = pin_root.join("maps/scx_task_profiles");
    let mut cleaned = 0;
    for ent in fs::read_dir(state_root)? {
        let ent = ent?;
        if !ent.file_name().to_string_lossy().ends_with(".receipt.json") {
            continue;
        }
        let Ok(receipt) = serde_json::from_slice::<ScxReceipt>(&fs::read(ent.path())?) else {
            continue;
        };
        let mut live = false;
        for task in &receipt.plan.tasks {
            if tgid_of(task.tid) == Some(receipt.plan.pid) {
                live = true;
            } else if profiles.exists() {
                let _ = delete_profile(&profiles, task.tid);
            }
        }
        if !live {
            fs::remove_file(ent.path())?;
            cleanup_vm_stats(receipt.vm_id, pin_root).ok();
            cleaned += 1;
        }
    }
    if no_receipts(state_root)? && current_ops().as_deref() == Some("fluxvm_scx") {
        let _ = stop_scheduler(pin_root);
    }
    Ok(cleaned)
}

pub fn active_ids(state_root: &Path) -> Result<Vec<Uuid>> {
    let mut ids = Vec::new();
    if !state_root.exists() {
        return Ok(ids);
    }
    for ent in fs::read_dir(state_root)? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().to_string();
        let Some(raw) = name.strip_suffix(".receipt.json") else { continue; };
        if let Ok(id) = raw.parse::<Uuid>() {
            ids.push(id);
        }
    }
    ids.sort();
    Ok(ids)
}

pub fn status(id: Uuid, pin_root: &Path, state_root: &Path) -> Result<ScxStatus> {
    let receipt = fs::read(receipt_path(state_root, id))
        .ok()
        .and_then(|v| serde_json::from_slice::<ScxReceipt>(&v).ok());
    let stats = read_stats(id, pin_root).ok();
    let p = probe(pin_root);
    let mut findings = Vec::new();
    if let Some(s) = &stats {
        if s.latency_violations > 0 {
            findings.push(format!("{} queue-latency target violation(s) observed", s.latency_violations));
        }
        if s.queue_delay_max_ns >= 5_000_000 {
            findings.push(format!("max sched_ext queue delay is {:.2} ms", s.queue_delay_max_ns as f64 / 1e6));
        }
        if s.fallback_enqueues > 0 {
            findings.push(format!("{} SCHED_EXT enqueue(s) had no valid FluxVM task profile", s.fallback_enqueues));
        }
    }
    if receipt.is_some() && p.sched_ext_state != "enabled" {
        findings.push("receipt exists but sched_ext is not currently enabled; kernel fallback is active and rollback should reconcile task policy/affinity".into());
    }
    Ok(ScxStatus { schema_version: SCX_SCHEMA_VERSION, vm_id: id, probe: p, receipt, stats, findings })
}

pub fn stream_events(id: Uuid, pin_root: &Path, seconds: u64, limit: usize) -> Result<()> {
    let helper = env::var("FLUXVM_SCX_EVENTS").unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-scx-events".into());
    let status = Command::new(helper)
        .args([
            pin_root.display().to_string(),
            vm_key(id).to_string(),
            seconds.clamp(1, 3600).to_string(),
            limit.clamp(1, 10000).to_string(),
        ])
        .status()?;
    if !status.success() {
        bail!("sched_ext event reader exited with {status}");
    }
    Ok(())
}

pub fn prometheus(id: Uuid, pin_root: &Path) -> Result<String> {
    let s = read_stats(id, pin_root)?;
    let mut out = String::from("# FluxVM Sentinel Set 11E sched_ext\n");
    macro_rules! metric {
        ($name:literal, $value:expr) => {
            out.push_str(&format!(concat!($name, "{{vm_id=\"{}\"}} {}\n"), id, $value));
        };
    }
    metric!("fluxvm_scx_enqueues_total", s.enqueues);
    metric!("fluxvm_scx_direct_dispatches_total", s.direct_dispatches);
    metric!("fluxvm_scx_shared_dispatches_total", s.shared_dispatches);
    metric!("fluxvm_scx_running_total", s.running_calls);
    metric!("fluxvm_scx_runtime_ns_total", s.runtime_ns);
    metric!("fluxvm_scx_queue_delay_ns_total", s.queue_delay_ns);
    metric!("fluxvm_scx_queue_delay_max_ns", s.queue_delay_max_ns);
    metric!("fluxvm_scx_latency_violations_total", s.latency_violations);
    metric!("fluxvm_scx_fallback_enqueues_total", s.fallback_enqueues);
    Ok(out)
}

pub fn verify_object() -> Result<()> {
    let helper = loader_helper();
    let object = object_path();
    let out = Command::new(&helper).arg("verify").arg(&object).output()?;
    if !out.status.success() {
        bail!("sched_ext object verification failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn validate_plan(plan: &ScxPlan) -> Result<()> {
    if plan.schema_version != SCX_SCHEMA_VERSION {
        bail!("unsupported sched_ext plan schema {}", plan.schema_version);
    }
    if plan.vm_key != vm_key(plan.vm_id) {
        bail!("plan vm_key does not match vm_id");
    }
    ensure_pid(plan.pid)?;
    if plan.tasks.is_empty() {
        bail!("plan has no vCPU tasks");
    }
    let mut tids = BTreeSet::new();
    for task in &plan.tasks {
        if !tids.insert(task.tid) {
            bail!("duplicate tid {} in plan", task.tid);
        }
        if !(25..=400).contains(&task.weight) {
            bail!("tid {} weight is outside 25..=400", task.tid);
        }
        if !(100_000..=10_000_000).contains(&task.slice_ns) {
            bail!("tid {} slice is outside 100us..10ms", task.tid);
        }
    }
    Ok(())
}

fn preflight_task(tgid: u32, task: &ScxTaskPlan) -> Result<()> {
    if tgid_of(task.tid) != Some(tgid) {
        bail!("tid {} no longer belongs to VMM tgid {}; possible restart or TID reuse", task.tid, tgid);
    }
    let now = task_state(task.tid)?;
    if now != task.old {
        bail!("tid {} scheduling state drifted since plan: planned {:?}, current {:?}", task.tid, task.old, now);
    }
    let allowed = parse_cpu_list(&now.cpus)?;
    if !allowed.contains(&task.target_cpu) {
        bail!("tid {} target CPU {} is no longer allowed by current affinity {}", task.tid, task.target_cpu, now.cpus);
    }
    Ok(())
}

fn start_scheduler(pin_root: &Path) -> Result<()> {
    let helper = loader_helper();
    let object = object_path();
    let out = Command::new(&helper)
        .arg("start").arg(&object).arg(pin_root)
        .output()
        .with_context(|| format!("running {helper}"))?;
    if !out.status.success() {
        bail!("sched_ext loader start failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let p = probe(pin_root);
    if p.sched_ext_state != "enabled" || p.current_ops.as_deref() != Some("fluxvm_scx") {
        let _ = stop_scheduler(pin_root);
        bail!("loader returned success but kernel did not report fluxvm_scx as active ops");
    }
    Ok(())
}

fn stop_scheduler(pin_root: &Path) -> Result<()> {
    let helper = loader_helper();
    let out = Command::new(&helper)
        .arg("stop").arg(pin_root)
        .output()?;
    if !out.status.success() {
        bail!("sched_ext loader stop failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn task_state(tid: u32) -> Result<TaskSchedulerState> {
    let helper = taskctl_helper();
    let out = Command::new(&helper).arg("get").arg(tid.to_string()).output()?;
    if !out.status.success() {
        bail!("task scheduler query failed for tid {}: {}", tid, String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).context("decoding fluxvm-scx-taskctl JSON")
}

fn set_ext(tid: u32, cpu: u32) -> Result<()> {
    let helper = taskctl_helper();
    let out = Command::new(&helper)
        .arg("set-ext").arg(tid.to_string()).arg(cpu.to_string())
        .output()?;
    if !out.status.success() {
        bail!("setting tid {} to SCHED_EXT/cpu {} failed: {}", tid, cpu, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn restore_task(state: &TaskSchedulerState) -> Result<()> {
    let helper = taskctl_helper();
    let out = Command::new(&helper)
        .arg("restore")
        .arg(state.tid.to_string())
        .arg(state.policy.to_string())
        .arg(state.priority.to_string())
        .arg(&state.cpus)
        .output()?;
    if !out.status.success() {
        bail!("restoring tid {} failed: {}", state.tid, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn update_profile(map: &Path, key: u64, tgid: u32, task: &ScxTaskPlan) -> Result<()> {
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(&key.to_ne_bytes());
    value.extend_from_slice(&tgid.to_ne_bytes());
    value.extend_from_slice(&task.weight.to_ne_bytes());
    value.extend_from_slice(&task.slice_ns.to_ne_bytes());
    value.extend_from_slice(&task.latency_target_ns.to_ne_bytes());
    value.extend_from_slice(&0u32.to_ne_bytes());
    value.extend_from_slice(&0u32.to_ne_bytes());
    bpftool_update(map, &task.tid.to_ne_bytes(), &value)
}

fn delete_profile(map: &Path, tid: u32) -> Result<()> {
    bpftool_delete(map, &tid.to_ne_bytes())
}

fn cleanup_vm_stats(id: Uuid, pin_root: &Path) -> Result<()> {
    let map = pin_root.join("maps/scx_vm_stats");
    if map.exists() {
        let _ = bpftool_delete(&map, &vm_key(id).to_ne_bytes());
    }
    Ok(())
}

fn read_stats(id: Uuid, pin_root: &Path) -> Result<ScxVmStats> {
    let map = pin_root.join("maps/scx_vm_stats");
    if !map.exists() {
        bail!("sched_ext stats map missing: {}", map.display());
    }
    let wanted = vm_key(id);
    for row in dump_rows(&map)? {
        let Some(key) = value_bytes(row.get("key")) else { continue; };
        let Some(value) = value_bytes(row.get("value")) else { continue; };
        if key.len() < 8 || value.len() < 88 {
            continue;
        }
        if u64::from_ne_bytes(key[0..8].try_into().unwrap()) != wanted {
            continue;
        }
        let u = |o: usize| u64::from_ne_bytes(value[o..o + 8].try_into().unwrap());
        return Ok(ScxVmStats {
            enqueues: u(0),
            direct_dispatches: u(8),
            shared_dispatches: u(16),
            dispatch_calls: u(24),
            running_calls: u(32),
            stopping_calls: u(40),
            runtime_ns: u(48),
            queue_delay_ns: u(56),
            queue_delay_max_ns: u(64),
            latency_violations: u(72),
            fallback_enqueues: u(80),
        });
    }
    Ok(ScxVmStats::default())
}

fn current_ops() -> Option<String> {
    let root = Path::new("/sys/kernel/sched_ext");
    for path in [root.join("root/ops"), root.join("ops")] {
        if let Ok(value) = fs::read_to_string(path) {
            let value = value.trim();
            if !value.is_empty() && value != "none" {
                return Some(value.to_string());
            }
        }
    }
    if let Ok(entries) = fs::read_dir(root) {
        for ent in entries.flatten() {
            let path = ent.path().join("ops");
            if let Ok(value) = fs::read_to_string(path) {
                let value = value.trim();
                if !value.is_empty() && value != "none" {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn ensure_pid(pid: u32) -> Result<()> {
    if !Path::new(&format!("/proc/{pid}")).exists() {
        bail!("VMM pid {pid} does not exist");
    }
    Ok(())
}

fn tgid_of(tid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    text.lines().find_map(|line| line.strip_prefix("Tgid:").and_then(|v| v.trim().parse().ok()))
}

fn parse_cpu_list(input: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for part in input.trim().split(',').filter(|p| !p.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let (a, b) = (a.parse::<u32>()?, b.parse::<u32>()?);
            if b < a {
                bail!("invalid CPU range {part}");
            }
            out.extend(a..=b);
        } else {
            out.push(part.parse::<u32>()?);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn bpftool_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut cmd = Command::new("bpftool");
    cmd.args(["map", "update", "pinned"]).arg(map).args(["key", "hex"]);
    for byte in key {
        cmd.arg(format!("{byte:02x}"));
    }
    cmd.args(["value", "hex"]);
    for byte in value {
        cmd.arg(format!("{byte:02x}"));
    }
    cmd.arg("any");
    let out = cmd.output()?;
    if !out.status.success() {
        bail!("bpftool update {} failed: {}", map.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn bpftool_delete(map: &Path, key: &[u8]) -> Result<()> {
    let mut cmd = Command::new("bpftool");
    cmd.args(["map", "delete", "pinned"]).arg(map).args(["key", "hex"]);
    for byte in key {
        cmd.arg(format!("{byte:02x}"));
    }
    let out = cmd.output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("No such file or directory") && !stderr.contains("No such") {
            bail!("bpftool delete {} failed: {}", map.display(), stderr.trim());
        }
    }
    Ok(())
}

fn dump_rows(map: &Path) -> Result<Vec<Value>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()?;
    if !out.status.success() {
        bail!("bpftool dump {} failed: {}", map.display(), String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).context("decoding bpftool JSON")
}

fn value_bytes(value: Option<&Value>) -> Option<Vec<u8>> {
    match value? {
        Value::Array(items) => items.iter().map(|item| match item {
            Value::Number(n) => n.as_u64().filter(|v| *v <= 255).map(|v| v as u8),
            Value::String(s) => u8::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
            _ => None,
        }).collect(),
        Value::Object(object) => object.get("bytes").and_then(|v| value_bytes(Some(v))),
        _ => None,
    }
}

fn receipt_path(root: &Path, id: Uuid) -> PathBuf {
    root.join(format!("{id}.receipt.json"))
}

fn no_receipts(root: &Path) -> Result<bool> {
    if !root.exists() {
        return Ok(true);
    }
    for ent in fs::read_dir(root)? {
        if ent?.file_name().to_string_lossy().ends_with(".receipt.json") {
            return Ok(false);
        }
    }
    Ok(true)
}

fn loader_helper() -> String {
    env::var("FLUXVM_SCX_LOADER").unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-scx-loader".into())
}

fn taskctl_helper() -> String {
    env::var("FLUXVM_SCX_TASKCTL").unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-scx-taskctl".into())
}

fn object_path() -> String {
    env::var("FLUXVM_SCX_OBJECT").unwrap_or_else(|_| DEFAULT_SCX_OBJECT.into())
}

fn command_exists(name: &str) -> bool {
    if name.contains('/') {
        Path::new(name).is_file()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v -- {name} >/dev/null 2>&1"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_defaults_are_bounded() {
        for class in [ScxClass::Latency, ScxClass::Balanced, ScxClass::Throughput, ScxClass::Background] {
            let (weight, slice, target) = class.defaults();
            assert!((25..=400).contains(&weight));
            assert!((100_000..=10_000_000).contains(&slice));
            assert!(target > 0);
        }
    }

    #[test]
    fn parse_cpu_ranges() {
        assert_eq!(parse_cpu_list("0-2,4,8-9").unwrap(), vec![0, 1, 2, 4, 8, 9]);
        assert!(parse_cpu_list("4-2").is_err());
    }

    #[test]
    fn profile_abi_is_40_bytes() {
        let task = ScxTaskPlan {
            tid: 1,
            vcpu: 0,
            comm: "CPU 0/KVM".into(),
            target_cpu: 0,
            old: TaskSchedulerState { tid: 1, policy: 0, priority: 0, cpus: "0".into() },
            weight: 100,
            slice_ns: 1_000_000,
            latency_target_ns: 5_000_000,
            rationale: vec![],
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_ne_bytes());
        bytes.extend_from_slice(&1u32.to_ne_bytes());
        bytes.extend_from_slice(&task.weight.to_ne_bytes());
        bytes.extend_from_slice(&task.slice_ns.to_ne_bytes());
        bytes.extend_from_slice(&task.latency_target_ns.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        assert_eq!(bytes.len(), 40);
    }
}
