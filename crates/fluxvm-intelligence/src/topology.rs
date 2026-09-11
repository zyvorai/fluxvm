// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

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

use crate::vm_key;

pub const DEFAULT_TOPOLOGY_PIN_ROOT: &str = "/sys/fs/bpf/fluxvm/topology";
pub const DEFAULT_TOPOLOGY_STATE_ROOT: &str = "/var/lib/fluxvm/topology";
const DEFAULT_OBJECT: &str = "/usr/lib/fluxvm/bpf/fluxvm_topology.bpf.o";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyProbe {
    pub bpffs: bool,
    pub bpftool: bool,
    pub sched_switch: bool,
    pub sched_migrate_task: bool,
    pub hardirq: bool,
    pub softirq: bool,
    pub maps_loaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcpuThread {
    pub tid: u32,
    pub vcpu: u32,
    pub comm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcpuCpuSample {
    pub vcpu: u32,
    pub cpu: u32,
    pub numa_node: Option<u32>,
    pub package: Option<i32>,
    pub core: Option<i32>,
    pub run_ns: u64,
    pub switches: u64,
    pub migrations: u64,
    pub max_slice_ns: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcpuSummary {
    pub vcpu: u32,
    pub tid: Option<u32>,
    pub primary_cpu: Option<u32>,
    pub primary_numa_node: Option<u32>,
    pub active_cpus: Vec<u32>,
    pub active_nodes: Vec<u32>,
    pub run_ns: u64,
    pub switches: u64,
    pub migrations: u64,
    pub max_slice_ns: u64,
    pub cross_numa: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuIrqSample {
    pub cpu: u32,
    pub numa_node: Option<u32>,
    pub hardirq_count: u64,
    pub hardirq_ns: u64,
    pub hardirq_max_ns: u64,
    pub softirq_count: u64,
    pub softirq_ns: u64,
    pub softirq_max_ns: u64,
    pub net_rx_ns: u64,
    pub net_tx_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueState {
    pub queue: String,
    pub rps_cpus: Option<String>,
    pub xps_cpus: Option<String>,
    pub rx_packets: Option<u64>,
    pub tx_packets: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterruptLine {
    pub irq: u32,
    pub label: String,
    pub affinity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologySnapshot {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub vm_key: u64,
    pub pid: u32,
    pub interface: Option<String>,
    pub vcpu_threads: Vec<VcpuThread>,
    pub vcpu_cpu: Vec<VcpuCpuSample>,
    pub vcpus: Vec<VcpuSummary>,
    pub cpu_irq: Vec<CpuIrqSample>,
    pub memory_pages_by_node: BTreeMap<u32, u64>,
    pub queues: Vec<QueueState>,
    pub interrupts: Vec<InterruptLine>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SteeringAction {
    TaskAffinity {
        tid: u32,
        old: String,
        new: String,
    },
    SysfsWrite {
        path: String,
        old: String,
        new: String,
    },
    IrqAffinity {
        irq: u32,
        path: String,
        old: String,
        new: String,
    },
    Advisory {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteeringPlan {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub pid: u32,
    pub generated_unix_seconds: u64,
    pub preferred_numa_node: Option<u32>,
    pub selected_cpus: Vec<u32>,
    pub interface: Option<String>,
    pub actions: Vec<SteeringAction>,
    pub rationale: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteeringReceipt {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub applied_unix_seconds: u64,
    pub plan: SteeringPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyEvent {
    pub timestamp_ns: u64,
    pub vm_key: u64,
    pub event_type: u32,
    pub event: String,
    pub tid: u32,
    pub vcpu: u32,
    pub cpu: u32,
    pub from_cpu: u32,
    pub to_cpu: u32,
    pub duration_ns: u64,
}

pub fn probe(pin_root: &Path) -> TopologyProbe {
    let event = |path: &str| {
        [
            "/sys/kernel/tracing/events",
            "/sys/kernel/debug/tracing/events",
        ]
        .iter()
        .any(|root| Path::new(root).join(path).exists())
    };
    TopologyProbe {
        bpffs: Path::new("/sys/fs/bpf").exists(),
        bpftool: command_exists("bpftool"),
        sched_switch: event("sched/sched_switch"),
        sched_migrate_task: event("sched/sched_migrate_task"),
        hardirq: event("irq/irq_handler_entry") && event("irq/irq_handler_exit"),
        softirq: event("irq/softirq_entry") && event("irq/softirq_exit"),
        maps_loaded: pin_root.join("maps/topo_tracked_vcpus").exists()
            && pin_root.join("maps/topo_vcpu_cpu").exists()
            && pin_root.join("maps/topo_cpu_irq").exists(),
    }
}

pub fn load(pin_root: &Path) -> Result<()> {
    let helper = env::var("FLUXVM_TOPOLOGY_LOADER")
        .unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-topology-loader".into());
    let object = env::var("FLUXVM_TOPOLOGY_OBJECT").unwrap_or_else(|_| DEFAULT_OBJECT.into());
    let out = Command::new(&helper)
        .arg("load")
        .arg(object)
        .arg(pin_root)
        .output()
        .with_context(|| format!("running {helper}"))?;
    if !out.status.success() {
        bail!(
            "topology loader failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn unload(pin_root: &Path) -> Result<()> {
    let helper = env::var("FLUXVM_TOPOLOGY_LOADER")
        .unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-topology-loader".into());
    let status = Command::new(&helper).arg("unload").arg(pin_root).status()?;
    if !status.success() {
        bail!("topology unload failed with {status}");
    }
    Ok(())
}

pub fn discover_vcpus(pid: u32) -> Result<Vec<VcpuThread>> {
    let root = PathBuf::from(format!("/proc/{pid}/task"));
    let mut found = Vec::new();
    for ent in fs::read_dir(&root).with_context(|| format!("reading {}", root.display()))? {
        let ent = ent?;
        let Some(tid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm = fs::read_to_string(ent.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let lower = comm.to_ascii_lowercase();
        if lower.contains("vcpu")
            || lower.contains("cpu ") && lower.contains("kvm")
            || lower.starts_with("cpu-")
        {
            found.push((tid, comm));
        }
    }
    found.sort_by_key(|(tid, _)| *tid);
    if found.is_empty() {
        bail!(
            "no vCPU threads recognized under /proc/{pid}/task; refuse to pin arbitrary VMM helper threads"
        );
    }
    Ok(found
        .into_iter()
        .enumerate()
        .map(|(i, (tid, comm))| VcpuThread {
            tid,
            vcpu: i as u32,
            comm,
        })
        .collect())
}

pub fn register(id: Uuid, pid: u32, pin_root: &Path) -> Result<Vec<VcpuThread>> {
    let map = pin_root.join("maps/topo_tracked_vcpus");
    if !map.exists() {
        bail!(
            "topology map missing: {}; run fluxvm-topology load first",
            map.display()
        );
    }
    cleanup_stale_tracked(&map)?;
    remove_vm_tracking(id, &map)?;
    let threads = discover_vcpus(pid)?;
    let key = vm_key(id);
    for t in &threads {
        update_tracked_vcpu(&map, t.tid, key, t.vcpu, pid)?;
    }
    Ok(threads)
}

pub fn unregister(id: Uuid, _pid: u32, pin_root: &Path) -> Result<()> {
    let map = pin_root.join("maps/topo_tracked_vcpus");
    remove_vm_tracking(id, &map)?;
    let key = vm_key(id);
    let run = pin_root.join("maps/topo_vcpu_cpu");
    for row in dump_rows(&run).unwrap_or_default() {
        if let Some(bytes) = value_bytes(row.get("key")) {
            if bytes.len() >= 16 && u64::from_ne_bytes(bytes[0..8].try_into().unwrap()) == key {
                let _ = delete_hex_key(&run, &bytes);
            }
        }
    }
    Ok(())
}

pub fn snapshot(
    id: Uuid,
    pid: u32,
    interface: Option<&str>,
    pin_root: &Path,
) -> Result<TopologySnapshot> {
    let threads = register(id, pid, pin_root)?;
    let samples = read_vcpu_cpu(id, pin_root)?;
    let summaries = summarize_vcpus(&threads, &samples);
    let cpus: BTreeSet<u32> = samples.iter().map(|s| s.cpu).collect();
    let irq = read_cpu_irq(pin_root, &cpus)?;
    let pages = read_numa_pages(pid).unwrap_or_default();
    let queues = interface.map(read_queues).transpose()?.unwrap_or_default();
    let interrupts = interface
        .map(read_interrupts)
        .transpose()?
        .unwrap_or_default();
    let mut findings = Vec::new();
    for v in &summaries {
        if v.cross_numa {
            findings.push(format!(
                "vCPU {} ran across NUMA nodes {:?}; consider pinning",
                v.vcpu, v.active_nodes
            ));
        }
        if v.migrations > 100 {
            findings.push(format!(
                "vCPU {} has {} observed scheduler migrations",
                v.vcpu, v.migrations
            ));
        }
    }
    let irq_total: u64 = irq.iter().map(|s| s.hardirq_ns + s.softirq_ns).sum();
    if irq_total > 100_000_000 {
        findings.push(format!(
            "vCPU-resident CPUs accumulated {:.1} ms of hardirq+softirq time",
            irq_total as f64 / 1e6
        ));
    }
    if queues.iter().any(|q| {
        q.rps_cpus
            .as_deref()
            .is_some_and(|v| v == "0" || v.is_empty())
    }) {
        findings.push("one or more RX queues have RPS disabled; a dedicated VM edge may benefit from explicit RPS steering".into());
    }
    let rx: Vec<u64> = queues
        .iter()
        .filter_map(|q| q.rx_packets)
        .filter(|v| *v > 0)
        .collect();
    if rx.len() > 1 {
        let min = *rx.iter().min().unwrap();
        let max = *rx.iter().max().unwrap();
        if min > 0 && max / min >= 4 {
            findings.push(format!(
                "RX queue packet imbalance is at least {}x across observable queues",
                max / min
            ));
        }
    }
    Ok(TopologySnapshot {
        schema_version: 1,
        vm_id: id,
        vm_key: vm_key(id),
        pid,
        interface: interface.map(str::to_string),
        vcpu_threads: threads,
        vcpu_cpu: samples,
        vcpus: summaries,
        cpu_irq: irq,
        memory_pages_by_node: pages,
        queues,
        interrupts,
        findings,
    })
}

pub fn plan(snapshot: &TopologySnapshot) -> Result<SteeringPlan> {
    if snapshot.vcpu_threads.is_empty() {
        bail!("cannot plan without recognized vCPU threads");
    }
    let nodes = node_cpus()?;
    if nodes.is_empty() {
        bail!("no NUMA CPU topology found under /sys/devices/system/node");
    }
    let preferred = choose_node(snapshot, &nodes);
    let candidates = preferred
        .and_then(|n| nodes.get(&n).cloned())
        .or_else(|| nodes.values().next().cloned())
        .unwrap_or_default();
    if candidates.is_empty() {
        bail!("preferred NUMA node has no online CPUs");
    }
    let irq_cost: BTreeMap<u32, u64> = snapshot
        .cpu_irq
        .iter()
        .map(|s| (s.cpu, s.hardirq_ns.saturating_add(s.softirq_ns)))
        .collect();
    let mut selected = candidates;
    selected.sort_by_key(|cpu| (irq_cost.get(cpu).copied().unwrap_or(0), *cpu));
    selected = prefer_distinct_cores(&selected);
    selected.truncate(snapshot.vcpu_threads.len().min(selected.len()));
    if selected.is_empty() {
        bail!("no CPUs available for vCPU steering");
    }

    let mut actions = Vec::new();
    for (i, vcpu) in snapshot.vcpu_threads.iter().enumerate() {
        let cpu = selected[i % selected.len()];
        actions.push(SteeringAction::TaskAffinity {
            tid: vcpu.tid,
            old: task_affinity(vcpu.tid)?,
            new: cpu.to_string(),
        });
    }

    if let Some(iface) = &snapshot.interface {
        let mask = cpumask(&selected);
        for q in &snapshot.queues {
            let qroot = Path::new("/sys/class/net")
                .join(iface)
                .join("queues")
                .join(&q.queue);
            if q.queue.starts_with("rx-") {
                let path = qroot.join("rps_cpus");
                if path.exists() {
                    actions.push(SteeringAction::SysfsWrite {
                        path: path.display().to_string(),
                        old: fs::read_to_string(&path)?.trim().to_string(),
                        new: mask.clone(),
                    });
                }
            }
            if q.queue.starts_with("tx-") {
                let path = qroot.join("xps_cpus");
                if path.exists() {
                    actions.push(SteeringAction::SysfsWrite {
                        path: path.display().to_string(),
                        old: fs::read_to_string(&path)?.trim().to_string(),
                        new: mask.clone(),
                    });
                }
            }
        }
        for irq in &snapshot.interrupts {
            let path = PathBuf::from(format!("/proc/irq/{}/smp_affinity_list", irq.irq));
            if path.exists() {
                actions.push(SteeringAction::IrqAffinity {
                    irq: irq.irq,
                    path: path.display().to_string(),
                    old: fs::read_to_string(&path)?.trim().to_string(),
                    new: cpu_list(&selected),
                });
            }
        }
        actions.push(SteeringAction::Advisory {
            message: format!("hardware RSS indirection for {iface} is intentionally not mutated automatically; use a dedicated PF/VF and ethtool -X only after validating queue ownership"),
        });
    }

    let mut rationale = Vec::new();
    if let Some(n) = preferred {
        rationale.push(format!(
            "prefer NUMA node {n} using guest-memory locality first, then observed vCPU runtime"
        ));
    }
    rationale.push("vCPU candidates are ordered by observed hardirq+softirq time so noisy CPUs are selected last".into());
    rationale.push("all steering changes are explicit, preflighted against current values, and rollback receipts preserve the exact previous state".into());
    Ok(SteeringPlan {
        schema_version: 1,
        vm_id: snapshot.vm_id,
        pid: snapshot.pid,
        generated_unix_seconds: unix_seconds(),
        preferred_numa_node: preferred,
        selected_cpus: selected,
        interface: snapshot.interface.clone(),
        actions,
        rationale,
    })
}

pub fn apply_plan(plan: &SteeringPlan, state_root: &Path) -> Result<SteeringReceipt> {
    if Path::new(&format!("/proc/{}", plan.pid)).exists() == false {
        bail!("VMM pid {} no longer exists", plan.pid);
    }
    for action in &plan.actions {
        preflight_action(action)?;
    }
    let mut applied: Vec<&SteeringAction> = Vec::new();
    for action in &plan.actions {
        if let Err(err) = apply_action(action, false) {
            for done in applied.into_iter().rev() {
                let _ = apply_action(done, true);
            }
            return Err(err.context(
                "steering apply failed; already-applied actions were rolled back best-effort",
            ));
        }
        if !matches!(action, SteeringAction::Advisory { .. }) {
            applied.push(action);
        }
    }
    let receipt = SteeringReceipt {
        schema_version: 1,
        vm_id: plan.vm_id,
        applied_unix_seconds: unix_seconds(),
        plan: plan.clone(),
    };
    fs::create_dir_all(state_root)?;
    atomic_write(
        &state_root.join(format!("{}.receipt.json", plan.vm_id)),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    Ok(receipt)
}

pub fn rollback(id: Uuid, state_root: &Path) -> Result<()> {
    let path = state_root.join(format!("{id}.receipt.json"));
    let receipt: SteeringReceipt = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    for action in receipt.plan.actions.iter().rev() {
        rollback_preflight(action)?;
    }
    for action in receipt.plan.actions.iter().rev() {
        apply_action(action, true)?;
    }
    fs::remove_file(path)?;
    Ok(())
}

pub fn stream_events(id: Uuid, pin_root: &Path, seconds: u64, limit: usize) -> Result<()> {
    let map = pin_root.join("maps/topo_events");
    if !map.exists() {
        bail!("topology event map missing: {}", map.display());
    }
    let helper = env::var("FLUXVM_TOPOLOGY_EVENTS")
        .unwrap_or_else(|_| "/usr/libexec/fluxvm/fluxvm-topology-events".into());
    let status = Command::new(helper)
        .arg(map)
        .arg(vm_key(id).to_string())
        .arg(seconds.clamp(1, 3600).to_string())
        .arg(limit.clamp(1, 10000).to_string())
        .status()?;
    if !status.success() {
        bail!("topology event reader exited with {status}");
    }
    Ok(())
}

pub fn prometheus(s: &TopologySnapshot) -> String {
    let mut out = String::from("# FluxVM Set 8 topology intelligence\n");
    for v in &s.vcpus {
        out.push_str(&format!(
            "fluxvm_vcpu_run_ns{{vm_id=\"{}\",vcpu=\"{}\"}} {}\n",
            s.vm_id, v.vcpu, v.run_ns
        ));
        out.push_str(&format!(
            "fluxvm_vcpu_migrations_total{{vm_id=\"{}\",vcpu=\"{}\"}} {}\n",
            s.vm_id, v.vcpu, v.migrations
        ));
        out.push_str(&format!(
            "fluxvm_vcpu_cross_numa{{vm_id=\"{}\",vcpu=\"{}\"}} {}\n",
            s.vm_id,
            v.vcpu,
            u8::from(v.cross_numa)
        ));
    }
    for c in &s.cpu_irq {
        out.push_str(&format!(
            "fluxvm_host_irq_ns{{vm_id=\"{}\",cpu=\"{}\",kind=\"hardirq\"}} {}\n",
            s.vm_id, c.cpu, c.hardirq_ns
        ));
        out.push_str(&format!(
            "fluxvm_host_irq_ns{{vm_id=\"{}\",cpu=\"{}\",kind=\"softirq\"}} {}\n",
            s.vm_id, c.cpu, c.softirq_ns
        ));
        out.push_str(&format!(
            "fluxvm_host_irq_ns{{vm_id=\"{}\",cpu=\"{}\",kind=\"net-rx\"}} {}\n",
            s.vm_id, c.cpu, c.net_rx_ns
        ));
        out.push_str(&format!(
            "fluxvm_host_irq_ns{{vm_id=\"{}\",cpu=\"{}\",kind=\"net-tx\"}} {}\n",
            s.vm_id, c.cpu, c.net_tx_ns
        ));
    }
    out
}

fn summarize_vcpus(threads: &[VcpuThread], samples: &[VcpuCpuSample]) -> Vec<VcpuSummary> {
    let tids: BTreeMap<u32, u32> = threads.iter().map(|t| (t.vcpu, t.tid)).collect();
    let mut by: BTreeMap<u32, Vec<&VcpuCpuSample>> = BTreeMap::new();
    for s in samples {
        by.entry(s.vcpu).or_default().push(s);
    }
    let keys: BTreeSet<u32> = threads
        .iter()
        .map(|t| t.vcpu)
        .chain(by.keys().copied())
        .collect();
    keys.into_iter()
        .map(|vcpu| {
            let rows = by.get(&vcpu).cloned().unwrap_or_default();
            let run_ns = rows.iter().map(|r| r.run_ns).sum();
            let switches = rows.iter().map(|r| r.switches).sum();
            let migrations = rows.iter().map(|r| r.migrations).sum();
            let max_slice_ns = rows.iter().map(|r| r.max_slice_ns).max().unwrap_or(0);
            let mut active_cpus: Vec<u32> = rows
                .iter()
                .filter(|r| r.run_ns > 0)
                .map(|r| r.cpu)
                .collect();
            active_cpus.sort_unstable();
            active_cpus.dedup();
            let mut active_nodes: Vec<u32> = rows.iter().filter_map(|r| r.numa_node).collect();
            active_nodes.sort_unstable();
            active_nodes.dedup();
            let primary = rows.iter().max_by_key(|r| r.run_ns).copied();
            VcpuSummary {
                vcpu,
                tid: tids.get(&vcpu).copied(),
                primary_cpu: primary.map(|r| r.cpu),
                primary_numa_node: primary.and_then(|r| r.numa_node),
                active_cpus,
                active_nodes: active_nodes.clone(),
                run_ns,
                switches,
                migrations,
                max_slice_ns,
                cross_numa: active_nodes.len() > 1,
            }
        })
        .collect()
}

fn choose_node(s: &TopologySnapshot, nodes: &BTreeMap<u32, Vec<u32>>) -> Option<u32> {
    if let Some((&n, _)) = s
        .memory_pages_by_node
        .iter()
        .filter(|(n, _)| nodes.contains_key(n))
        .max_by_key(|(_, pages)| *pages)
    {
        return Some(n);
    }
    let mut runtime = BTreeMap::<u32, u64>::new();
    for row in &s.vcpu_cpu {
        if let Some(n) = row.numa_node {
            *runtime.entry(n).or_default() += row.run_ns;
        }
    }
    runtime
        .into_iter()
        .max_by_key(|(_, ns)| *ns)
        .map(|(n, _)| n)
        .or_else(|| nodes.keys().next().copied())
}

fn read_vcpu_cpu(id: Uuid, pin_root: &Path) -> Result<Vec<VcpuCpuSample>> {
    let map = pin_root.join("maps/topo_vcpu_cpu");
    let wanted = vm_key(id);
    let mut out = Vec::new();
    for row in dump_rows(&map)? {
        let Some(k) = value_bytes(row.get("key")) else {
            continue;
        };
        let Some(v) = value_bytes(row.get("value")) else {
            continue;
        };
        if k.len() < 16 || v.len() < 40 {
            continue;
        }
        let key = u64::from_ne_bytes(k[0..8].try_into().unwrap());
        if key != wanted {
            continue;
        }
        let vcpu = u32::from_ne_bytes(k[8..12].try_into().unwrap());
        let cpu = u32::from_ne_bytes(k[12..16].try_into().unwrap());
        out.push(VcpuCpuSample {
            vcpu,
            cpu,
            numa_node: cpu_node(cpu),
            package: read_i32(Path::new(&format!(
                "/sys/devices/system/cpu/cpu{cpu}/topology/physical_package_id"
            ))),
            core: read_i32(Path::new(&format!(
                "/sys/devices/system/cpu/cpu{cpu}/topology/core_id"
            ))),
            run_ns: u64::from_ne_bytes(v[0..8].try_into().unwrap()),
            switches: u64::from_ne_bytes(v[8..16].try_into().unwrap()),
            migrations: u64::from_ne_bytes(v[16..24].try_into().unwrap()),
            max_slice_ns: u64::from_ne_bytes(v[24..32].try_into().unwrap()),
            last_seen_ns: u64::from_ne_bytes(v[32..40].try_into().unwrap()),
        });
    }
    out.sort_by_key(|r| (r.vcpu, r.cpu));
    Ok(out)
}

fn read_cpu_irq(pin_root: &Path, cpus: &BTreeSet<u32>) -> Result<Vec<CpuIrqSample>> {
    let map = pin_root.join("maps/topo_cpu_irq");
    let mut out = Vec::new();
    for row in dump_rows(&map)? {
        let Some(k) = value_bytes(row.get("key")) else {
            continue;
        };
        let Some(v) = value_bytes(row.get("value")) else {
            continue;
        };
        if k.len() < 4 || v.len() < 64 {
            continue;
        }
        let cpu = u32::from_ne_bytes(k[0..4].try_into().unwrap());
        if !cpus.is_empty() && !cpus.contains(&cpu) {
            continue;
        }
        let u = |o: usize| u64::from_ne_bytes(v[o..o + 8].try_into().unwrap());
        out.push(CpuIrqSample {
            cpu,
            numa_node: cpu_node(cpu),
            hardirq_count: u(0),
            hardirq_ns: u(8),
            hardirq_max_ns: u(16),
            softirq_count: u(24),
            softirq_ns: u(32),
            softirq_max_ns: u(40),
            net_rx_ns: u(48),
            net_tx_ns: u(56),
        });
    }
    out.sort_by_key(|r| r.cpu);
    Ok(out)
}

fn read_numa_pages(pid: u32) -> Result<BTreeMap<u32, u64>> {
    let text = fs::read_to_string(format!("/proc/{pid}/numa_maps"))?;
    let mut out = BTreeMap::new();
    for token in text.split_whitespace() {
        let Some(rest) = token.strip_prefix('N') else {
            continue;
        };
        let Some((n, pages)) = rest.split_once('=') else {
            continue;
        };
        let (Ok(n), Ok(pages)) = (n.parse::<u32>(), pages.parse::<u64>()) else {
            continue;
        };
        *out.entry(n).or_default() += pages;
    }
    Ok(out)
}

fn read_queues(iface: &str) -> Result<Vec<QueueState>> {
    let root = Path::new("/sys/class/net").join(iface).join("queues");
    if !root.exists() {
        bail!("interface {iface} has no sysfs queue directory");
    }
    let stats = ethtool_queue_packets(iface);
    let mut out = Vec::new();
    for ent in fs::read_dir(root)? {
        let ent = ent?;
        let queue = ent.file_name().to_string_lossy().to_string();
        let rps = ent.path().join("rps_cpus");
        let xps = ent.path().join("xps_cpus");
        let index = queue
            .split_once('-')
            .and_then(|(_, v)| v.parse::<u32>().ok());
        let rx_packets = index.and_then(|q| stats.get(&("rx".to_string(), q)).copied());
        let tx_packets = index.and_then(|q| stats.get(&("tx".to_string(), q)).copied());
        out.push(QueueState {
            queue,
            rps_cpus: rps.exists().then(|| {
                fs::read_to_string(rps)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }),
            xps_cpus: xps.exists().then(|| {
                fs::read_to_string(xps)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }),
            rx_packets,
            tx_packets,
        });
    }
    out.sort_by(|a, b| a.queue.cmp(&b.queue));
    Ok(out)
}

fn ethtool_queue_packets(iface: &str) -> BTreeMap<(String, u32), u64> {
    let mut out = BTreeMap::new();
    let Ok(result) = Command::new("ethtool").args(["-S", iface]).output() else {
        return out;
    };
    if !result.status.success() {
        return out;
    }
    let text = String::from_utf8_lossy(&result.stdout);
    for line in text.lines() {
        let Some((name, value)) = line.trim().split_once(':') else {
            continue;
        };
        let Ok(value) = value.trim().parse::<u64>() else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !lower.contains("packet") {
            continue;
        }
        let direction = if lower.contains("rx") {
            "rx"
        } else if lower.contains("tx") {
            "tx"
        } else {
            continue;
        };
        let mut index = None;
        for token in lower.split(|c: char| !c.is_ascii_digit()) {
            if !token.is_empty() {
                index = token.parse::<u32>().ok();
                if index.is_some() {
                    break;
                }
            }
        }
        if let Some(q) = index {
            out.entry((direction.to_string(), q))
                .and_modify(|v| *v = (*v).max(value))
                .or_insert(value);
        }
    }
    out
}

fn read_interrupts(iface: &str) -> Result<Vec<InterruptLine>> {
    let text = fs::read_to_string("/proc/interrupts")?;
    let mut out = Vec::new();
    for line in text.lines().filter(|line| line.contains(iface)) {
        let Some((irq, _)) = line.split_once(':') else {
            continue;
        };
        let Ok(irq) = irq.trim().parse::<u32>() else {
            continue;
        };
        let path = PathBuf::from(format!("/proc/irq/{irq}/smp_affinity_list"));
        out.push(InterruptLine {
            irq,
            label: line.trim().to_string(),
            affinity: path.exists().then(|| {
                fs::read_to_string(path)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }),
        });
    }
    Ok(out)
}

fn node_cpus() -> Result<BTreeMap<u32, Vec<u32>>> {
    let online: BTreeSet<u32> =
        parse_cpu_list(&fs::read_to_string("/sys/devices/system/cpu/online")?)?
            .into_iter()
            .collect();
    let mut out = BTreeMap::new();
    let root = Path::new("/sys/devices/system/node");
    for ent in fs::read_dir(root)? {
        let ent = ent?;
        let name = ent.file_name().to_string_lossy().to_string();
        let Some(n) = name
            .strip_prefix("node")
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let mut cpus = parse_cpu_list(&fs::read_to_string(ent.path().join("cpulist"))?)?;
        cpus.retain(|cpu| online.contains(cpu));
        if !cpus.is_empty() {
            out.insert(n, cpus);
        }
    }
    if out.is_empty() {
        let cpus: Vec<u32> = online.into_iter().collect();
        if !cpus.is_empty() {
            out.insert(0, cpus);
        }
    }
    Ok(out)
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

fn cpu_node(cpu: u32) -> Option<u32> {
    let root = PathBuf::from(format!("/sys/devices/system/cpu/cpu{cpu}"));
    fs::read_dir(root).ok()?.flatten().find_map(|e| {
        let n = e.file_name().to_string_lossy().to_string();
        n.strip_prefix("node").and_then(|v| v.parse().ok())
    })
}

fn prefer_distinct_cores(cpus: &[u32]) -> Vec<u32> {
    let mut first = Vec::new();
    let mut siblings = Vec::new();
    let mut seen = BTreeSet::new();
    for &cpu in cpus {
        let package = read_i32(Path::new(&format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/physical_package_id"
        )))
        .unwrap_or(-1);
        let core = read_i32(Path::new(&format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/core_id"
        )))
        .unwrap_or(cpu as i32);
        if seen.insert((package, core)) {
            first.push(cpu)
        } else {
            siblings.push(cpu)
        }
    }
    first.extend(siblings);
    first
}

fn cpumask(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return "0".into();
    }
    let max = cpus.iter().copied().max().unwrap_or(0) as usize;
    let mut words = vec![0u32; max / 32 + 1];
    for cpu in cpus {
        words[*cpu as usize / 32] |= 1u32 << (*cpu % 32);
    }
    let mut it = words.iter().rev();
    let first = it.next().copied().unwrap_or(0);
    let mut out = format!("{first:x}");
    for word in it {
        out.push_str(&format!(",{word:08x}"));
    }
    out
}

fn cpu_list(cpus: &[u32]) -> String {
    cpus.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn task_affinity(tid: u32) -> Result<String> {
    let out = Command::new("taskset")
        .args(["-pc", &tid.to_string()])
        .output()
        .context("running taskset")?;
    if !out.status.success() {
        bail!(
            "taskset query failed for tid {tid}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.rsplit(':')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("unexpected taskset output for tid {tid}: {text}"))
}

fn preflight_action(a: &SteeringAction) -> Result<()> {
    match a {
        SteeringAction::TaskAffinity { tid, old, .. } => {
            let now = task_affinity(*tid)?;
            if &now != old {
                bail!("tid {tid} affinity drifted: plan={old}, current={now}");
            }
        }
        SteeringAction::SysfsWrite { path, old, .. }
        | SteeringAction::IrqAffinity { path, old, .. } => {
            let now = fs::read_to_string(path)?.trim().to_string();
            if &now != old {
                bail!("{path} drifted: plan={old}, current={now}");
            }
        }
        SteeringAction::Advisory { .. } => {}
    }
    Ok(())
}

fn rollback_preflight(a: &SteeringAction) -> Result<()> {
    match a {
        SteeringAction::TaskAffinity { tid, new, .. } => {
            let now = task_affinity(*tid)?;
            if &now != new {
                bail!(
                    "refuse rollback: tid {tid} changed since apply: receipt={new}, current={now}"
                );
            }
        }
        SteeringAction::SysfsWrite { path, new, .. }
        | SteeringAction::IrqAffinity { path, new, .. } => {
            let now = fs::read_to_string(path)?.trim().to_string();
            if &now != new {
                bail!("refuse rollback: {path} changed since apply: receipt={new}, current={now}");
            }
        }
        SteeringAction::Advisory { .. } => {}
    }
    Ok(())
}

fn apply_action(a: &SteeringAction, reverse: bool) -> Result<()> {
    match a {
        SteeringAction::TaskAffinity { tid, old, new } => {
            let value = if reverse { old } else { new };
            let status = Command::new("taskset")
                .args(["-pc", value, &tid.to_string()])
                .status()?;
            if !status.success() {
                bail!("taskset failed for tid {tid}");
            }
        }
        SteeringAction::SysfsWrite { path, old, new }
        | SteeringAction::IrqAffinity { path, old, new, .. } => {
            fs::write(path, format!("{}\n", if reverse { old } else { new }))?;
        }
        SteeringAction::Advisory { .. } => {}
    }
    Ok(())
}

fn update_tracked_vcpu(map: &Path, tid: u32, key: u64, vcpu: u32, tgid: u32) -> Result<()> {
    let k = tid.to_ne_bytes();
    let mut v = Vec::new();
    v.extend_from_slice(&key.to_ne_bytes());
    v.extend_from_slice(&vcpu.to_ne_bytes());
    v.extend_from_slice(&tgid.to_ne_bytes());
    bpftool_update(map, &k, &v)
}

fn remove_vm_tracking(id: Uuid, map: &Path) -> Result<()> {
    if !map.exists() {
        return Ok(());
    }
    let wanted = vm_key(id);
    for row in dump_rows(map).unwrap_or_default() {
        let Some(k) = value_bytes(row.get("key")) else {
            continue;
        };
        let Some(v) = value_bytes(row.get("value")) else {
            continue;
        };
        if k.len() < 4 || v.len() < 16 {
            continue;
        }
        if u64::from_ne_bytes(v[0..8].try_into().unwrap()) == wanted {
            let _ = delete_hex_key(map, &k[..4]);
        }
    }
    Ok(())
}

fn cleanup_stale_tracked(map: &Path) -> Result<()> {
    for row in dump_rows(map).unwrap_or_default() {
        let Some(k) = value_bytes(row.get("key")) else {
            continue;
        };
        let Some(v) = value_bytes(row.get("value")) else {
            continue;
        };
        if k.len() < 4 || v.len() < 16 {
            continue;
        }
        let tid = u32::from_ne_bytes(k[0..4].try_into().unwrap());
        let expected = u32::from_ne_bytes(v[12..16].try_into().unwrap());
        if read_tgid(tid) != Some(expected) {
            let _ = delete_hex_key(map, &k[..4]);
        }
    }
    Ok(())
}

fn read_tgid(tid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("Tgid:")
            .and_then(|v| v.trim().parse().ok())
    })
}

fn bpftool_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut cmd = Command::new("bpftool");
    cmd.args(["map", "update", "pinned"])
        .arg(map)
        .arg("key")
        .arg("hex");
    for b in key {
        cmd.arg(format!("{b:02x}"));
    }
    cmd.arg("value").arg("hex");
    for b in value {
        cmd.arg(format!("{b:02x}"));
    }
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "bpftool map update {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
fn delete_u32(map: &Path, key: u32) -> Result<()> {
    delete_hex_key(map, &key.to_ne_bytes())
}
fn delete_hex_key(map: &Path, key: &[u8]) -> Result<()> {
    let mut cmd = Command::new("bpftool");
    cmd.args(["map", "delete", "pinned"])
        .arg(map)
        .arg("key")
        .arg("hex");
    for b in key {
        cmd.arg(format!("{b:02x}"));
    }
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "bpftool map delete {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
fn dump_rows(map: &Path) -> Result<Vec<Value>> {
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()?;
    if !out.status.success() {
        bail!(
            "bpftool map dump {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("decoding bpftool JSON")
}
fn value_bytes(v: Option<&Value>) -> Option<Vec<u8>> {
    match v? {
        Value::Array(a) => a
            .iter()
            .map(|x| match x {
                Value::Number(n) => n.as_u64().filter(|n| *n <= 255).map(|n| n as u8),
                Value::String(s) => u8::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
                _ => None,
            })
            .collect(),
        Value::Object(o) => o.get("bytes").and_then(|x| value_bytes(Some(x))),
        _ => None,
    }
}
fn command_exists(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v -- {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
fn read_i32(path: &Path) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_list_parser() {
        assert_eq!(parse_cpu_list("0-2,4,6-7").unwrap(), vec![0, 1, 2, 4, 6, 7]);
    }
    #[test]
    fn cpumask_small() {
        assert_eq!(cpumask(&[0, 1, 3]), "b");
    }
    #[test]
    fn summary_flags_cross_numa() {
        let t = vec![VcpuThread {
            tid: 10,
            vcpu: 0,
            comm: "CPU 0/KVM".into(),
        }];
        let rows = vec![
            VcpuCpuSample {
                vcpu: 0,
                cpu: 0,
                numa_node: Some(0),
                package: Some(0),
                core: Some(0),
                run_ns: 10,
                switches: 1,
                migrations: 0,
                max_slice_ns: 10,
                last_seen_ns: 1,
            },
            VcpuCpuSample {
                vcpu: 0,
                cpu: 8,
                numa_node: Some(1),
                package: Some(0),
                core: Some(0),
                run_ns: 5,
                switches: 1,
                migrations: 1,
                max_slice_ns: 5,
                last_seen_ns: 2,
            },
        ];
        assert!(summarize_vcpus(&t, &rows)[0].cross_numa);
    }
}
