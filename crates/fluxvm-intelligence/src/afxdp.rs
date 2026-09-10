// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fs,
    fs::File,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::vm_key;

pub const AFXDP_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_AFXDP_PIN_ROOT: &str = "/sys/fs/bpf/fluxvm/afxdp";
pub const DEFAULT_AFXDP_STATE_ROOT: &str = "/run/fluxvm/afxdp";
pub const MAX_QUEUE_ID: u32 = 63;
pub const MAX_SUPPORTED_MTU: u32 = 3500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AfxdpMode {
    Auto,
    Copy,
    Zerocopy,
}
impl AfxdpMode {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(Self::Auto),
            "copy" => Ok(Self::Copy),
            "zerocopy" | "zero-copy" => Ok(Self::Zerocopy),
            _ => bail!("AF_XDP mode must be auto|copy|zerocopy"),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self { Self::Auto => "auto", Self::Copy => "copy", Self::Zerocopy => "zerocopy" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AfxdpProbe {
    pub schema_version: u32,
    pub bpffs: bool,
    pub loader: bool,
    pub worker: bool,
    pub kernel_af_xdp: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceQueue {
    pub interface: String,
    pub ifindex: u32,
    pub queue: u32,
    pub mtu: u32,
    pub master: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AfxdpPlan {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub vm_key: u64,
    pub side_a: InterfaceQueue,
    pub side_b: InterfaceQueue,
    pub mode: AfxdpMode,
    pub dedicated_interfaces_confirmed: bool,
    pub xdp_attach_mode: String,
    pub sample_rate: u32,
    pub batch: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AfxdpControl {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub worker_pid: u32,
    pub pin_root: String,
    pub created_unix_seconds: u64,
    pub plan: AfxdpPlan,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueRuntime {
    pub slot: u32,
    pub queue: u32,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub dropped_packets: u64,
    pub tx_ring_full: u64,
    pub fill_deferred: u64,
    pub poll_wakeups: u64,
    pub multibuf_drops: u64,
    pub last_update_ns: u64,
    pub zero_copy: bool,
    pub worker_pid: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct XdpQueueStat {
    pub slot: u32,
    pub queue: u32,
    pub seen_packets: u64,
    pub seen_bytes: u64,
    pub redirect_attempts: u64,
    pub pass_inactive: u64,
    pub pass_queue_disabled: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AfxdpStatus {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub running: bool,
    pub worker_pid: Option<u32>,
    pub loader: Option<Value>,
    pub runtime: Vec<QueueRuntime>,
    pub xdp: Vec<XdpQueueStat>,
    pub findings: Vec<String>,
}

pub fn probe() -> AfxdpProbe {
    let loader = helper_path("FLUXVM_AFXDP_LOADER", "/usr/libexec/fluxvm/fluxvm-afxdp-loader");
    let worker = helper_path("FLUXVM_AFXDP_WORKER", "/usr/libexec/fluxvm/fluxvm-afxdp-worker");
    let mut notes = Vec::new();
    if !Path::new("/proc/net/xdp").exists() {
        notes.push("/proc/net/xdp is absent; this is not fatal, but AF_XDP runtime support must be verified by bind".into());
    }
    notes.push("zero-copy support is a per-interface/driver property and is verified by the worker after bind".into());
    AfxdpProbe {
        schema_version: AFXDP_SCHEMA_VERSION,
        bpffs: Path::new("/sys/fs/bpf").exists(),
        loader: command_exists(&loader),
        worker: command_exists(&worker),
        kernel_af_xdp: Path::new("/sys/module/xsk_diag").exists() || Path::new("/proc/net/xdp").exists(),
        notes,
    }
}

pub fn build_plan(id: Uuid, ifa: &str, qa: u32, ifb: &str, qb: u32, mode: AfxdpMode,
                  dedicated: bool) -> Result<AfxdpPlan> {
    if !dedicated {
        bail!("refusing AF_XDP fast path without explicit dedicated-interface confirmation (--dedicated)");
    }
    if ifa == ifb { bail!("AF_XDP bridge interfaces must be different"); }
    if qa > MAX_QUEUE_ID || qb > MAX_QUEUE_ID { bail!("AF_XDP queue id must be 0..={MAX_QUEUE_ID}"); }
    let a = inspect_queue(ifa, qa)?;
    let b = inspect_queue(ifb, qb)?;
    if a.mtu > MAX_SUPPORTED_MTU || b.mtu > MAX_SUPPORTED_MTU {
        bail!("Set 9 does not forward AF_XDP multi-buffer packets; MTU must be <= {MAX_SUPPORTED_MTU} ({}={}, {}={})",
              ifa, a.mtu, ifb, b.mtu);
    }
    let mut warnings = Vec::new();
    if let Some(m) = &a.master { warnings.push(format!("{ifa} is enslaved to {m}; dedicated ownership must include that topology")); }
    if let Some(m) = &b.master { warnings.push(format!("{ifb} is enslaved to {m}; dedicated ownership must include that topology")); }
    if mode == AfxdpMode::Auto {
        warnings.push("auto mode permits AF_XDP copy fallback; use zerocopy to require driver zero-copy support".into());
    }
    Ok(AfxdpPlan {
        schema_version: AFXDP_SCHEMA_VERSION,
        vm_id: id,
        vm_key: vm_key(id),
        side_a: a,
        side_b: b,
        mode,
        dedicated_interfaces_confirmed: true,
        xdp_attach_mode: "auto".into(),
        sample_rate: 0,
        batch: 64,
        warnings,
    })
}

pub fn start(plan: &AfxdpPlan, pin_base: &Path, state_root: &Path) -> Result<AfxdpControl> {
    validate_plan_live(plan)?;
    fs::create_dir_all(state_root)?;
    let control_path = control_path(state_root, plan.vm_id);
    if control_path.exists() {
        let old: AfxdpControl = serde_json::from_slice(&fs::read(&control_path)?)?;
        if process_alive(old.worker_pid) {
            bail!("AF_XDP fast path already active for {} with pid {}", plan.vm_id, old.worker_pid);
        }
        bail!("stale AF_XDP control state exists at {}; run stop before start", control_path.display());
    }
    let pin_root = pin_base.join(plan.vm_id.to_string());
    let loader = helper_path("FLUXVM_AFXDP_LOADER", "/usr/libexec/fluxvm/fluxvm-afxdp-loader");
    let object = env::var("FLUXVM_AFXDP_OBJECT").unwrap_or_else(|_| "/usr/lib/fluxvm/bpf/fluxvm_afxdp.bpf.o".into());
    let load = Command::new(&loader)
        .arg("load")
        .arg(&object)
        .arg(&pin_root)
        .arg(&plan.side_a.interface)
        .arg(&plan.side_b.interface)
        .arg(plan.vm_key.to_string())
        .arg(&plan.xdp_attach_mode)
        .arg(plan.sample_rate.to_string())
        .output().with_context(|| format!("running {loader}"))?;
    if !load.status.success() {
        bail!("AF_XDP loader refused attach: {}", String::from_utf8_lossy(&load.stderr).trim());
    }

    let worker = helper_path("FLUXVM_AFXDP_WORKER", "/usr/libexec/fluxvm/fluxvm-afxdp-worker");
    let log_path = state_root.join(format!("{}.worker.log", plan.vm_id));
    let log = File::options().create(true).append(true).open(&log_path)?;
    let log2 = log.try_clone()?;
    let mut child = Command::new(&worker)
        .arg(&pin_root)
        .arg(&plan.side_a.interface)
        .arg(plan.side_a.queue.to_string())
        .arg(&plan.side_b.interface)
        .arg(plan.side_b.queue.to_string())
        .arg(plan.mode.as_str())
        .arg(plan.batch.to_string())
        .stdin(Stdio::null()).stdout(Stdio::from(log)).stderr(Stdio::from(log2))
        .spawn().with_context(|| format!("starting {worker}"))?;
    thread::sleep(Duration::from_millis(250));
    if let Some(status) = child.try_wait()? {
        let _ = unload(&loader, &pin_root, plan);
        bail!("AF_XDP worker exited during startup with {status}; see {}", log_path.display());
    }
    let control = AfxdpControl {
        schema_version: AFXDP_SCHEMA_VERSION,
        vm_id: plan.vm_id,
        worker_pid: child.id(),
        pin_root: pin_root.display().to_string(),
        created_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        plan: plan.clone(),
    };
    write_json_atomic(&control_path, &control)?;
    Ok(control)
}

pub fn stop(id: Uuid, state_root: &Path) -> Result<()> {
    let path = control_path(state_root, id);
    let control: AfxdpControl = serde_json::from_slice(&fs::read(&path).with_context(|| format!("reading {}", path.display()))?)?;
    if process_alive(control.worker_pid) {
        let _ = Command::new("kill").args(["-TERM", &control.worker_pid.to_string()]).status();
        for _ in 0..20 {
            if !process_alive(control.worker_pid) { break; }
            thread::sleep(Duration::from_millis(100));
        }
        if process_alive(control.worker_pid) {
            let _ = Command::new("kill").args(["-KILL", &control.worker_pid.to_string()]).status();
        }
    }
    let loader = helper_path("FLUXVM_AFXDP_LOADER", "/usr/libexec/fluxvm/fluxvm-afxdp-loader");
    unload(&loader, Path::new(&control.pin_root), &control.plan)?;
    let _ = fs::remove_file(&path);
    Ok(())
}

fn unload(loader: &str, pin_root: &Path, plan: &AfxdpPlan) -> Result<()> {
    let out = Command::new(loader)
        .arg("unload").arg(pin_root).arg(&plan.side_a.interface).arg(&plan.side_b.interface)
        .output()?;
    if !out.status.success() { bail!("AF_XDP unload failed: {}", String::from_utf8_lossy(&out.stderr).trim()); }
    Ok(())
}

pub fn status(id: Uuid, state_root: &Path) -> Result<AfxdpStatus> {
    let path = control_path(state_root, id);
    let control: Option<AfxdpControl> = if path.exists() { Some(serde_json::from_slice(&fs::read(&path)?)?) } else { None };
    let mut findings = Vec::new();
    let (running, worker_pid, loader, runtime, xdp) = if let Some(c) = &control {
        let running = process_alive(c.worker_pid);
        if !running { findings.push("worker is not alive; XSK removal makes the BPF redirect path fall back to XDP_PASS".into()); }
        let helper = helper_path("FLUXVM_AFXDP_LOADER", "/usr/libexec/fluxvm/fluxvm-afxdp-loader");
        let out = Command::new(helper).arg("status").arg(&c.pin_root).arg(&c.plan.side_a.interface).arg(&c.plan.side_b.interface).output();
        let loader = out.ok().and_then(|o| serde_json::from_slice::<Value>(&o.stdout).ok());
        let root = Path::new(&c.pin_root);
        (running, Some(c.worker_pid), loader, read_runtime(root).unwrap_or_default(), read_xdp_stats(root).unwrap_or_default())
    } else { (false, None, None, Vec::new(), Vec::new()) };
    for r in &runtime {
        if r.tx_ring_full > 0 { findings.push(format!("slot {} queue {} observed {} TX-ring-full drops", r.slot, r.queue, r.tx_ring_full)); }
        if r.multibuf_drops > 0 { findings.push(format!("slot {} queue {} dropped {} multi-buffer descriptors; reduce MTU or use the kernel datapath", r.slot, r.queue, r.multibuf_drops)); }
        if !r.zero_copy { findings.push(format!("slot {} queue {} is running AF_XDP copy mode", r.slot, r.queue)); }
    }
    Ok(AfxdpStatus { schema_version: AFXDP_SCHEMA_VERSION, vm_id: id, running, worker_pid, loader, runtime, xdp, findings })
}

pub fn list_statuses(state_root: &Path) -> Result<Vec<AfxdpStatus>> {
    if !state_root.exists() { return Ok(Vec::new()); }
    let mut ids = Vec::new();
    for e in fs::read_dir(state_root)? {
        let e=e?; let name=e.file_name().to_string_lossy().to_string();
        if let Some(stem)=name.strip_suffix(".control.json") { if let Ok(id)=stem.parse::<Uuid>() { ids.push(id); } }
    }
    ids.sort(); ids.into_iter().map(|id| status(id,state_root)).collect()
}

pub fn prometheus(s: &AfxdpStatus) -> String {
    let id=s.vm_id; let mut out=String::new();
    out.push_str(&format!("fluxvm_afxdp_running{{vm_id=\"{id}\"}} {}\n", if s.running {1}else{0}));
    for r in &s.runtime {
        let l=format!("vm_id=\"{id}\",slot=\"{}\",queue=\"{}\"",r.slot,r.queue);
        out.push_str(&format!("fluxvm_afxdp_rx_packets{{{l}}} {}\n",r.rx_packets));
        out.push_str(&format!("fluxvm_afxdp_tx_packets{{{l}}} {}\n",r.tx_packets));
        out.push_str(&format!("fluxvm_afxdp_dropped_packets{{{l}}} {}\n",r.dropped_packets));
        out.push_str(&format!("fluxvm_afxdp_zero_copy{{{l}}} {}\n",if r.zero_copy {1}else{0}));
    }
    for x in &s.xdp {
        let l=format!("vm_id=\"{id}\",slot=\"{}\",queue=\"{}\"",x.slot,x.queue);
        out.push_str(&format!("fluxvm_afxdp_xdp_seen_packets{{{l}}} {}\n",x.seen_packets));
        out.push_str(&format!("fluxvm_afxdp_xdp_redirect_attempts{{{l}}} {}\n",x.redirect_attempts));
    }
    out
}

pub fn stream_events(id: Uuid, seconds: u64, limit: usize, state_root: &Path) -> Result<()> {
    let control: AfxdpControl = serde_json::from_slice(&fs::read(control_path(state_root, id))?)?;
    let helper = helper_path("FLUXVM_AFXDP_EVENTS", "/usr/libexec/fluxvm/fluxvm-afxdp-events");
    let status = Command::new(helper)
        .arg(&control.pin_root).arg(seconds.to_string()).arg(limit.to_string()).status()?;
    if !status.success() { bail!("AF_XDP event reader failed with {status}"); }
    Ok(())
}

fn inspect_queue(iface: &str, queue: u32) -> Result<InterfaceQueue> {
    validate_iface_name(iface)?;
    let root=PathBuf::from("/sys/class/net").join(iface);
    if !root.exists() { bail!("interface {iface} not found"); }
    let q=root.join(format!("queues/rx-{queue}"));
    if !q.exists() { bail!("interface {iface} has no RX queue {queue}"); }
    let ifindex=read_u32(root.join("ifindex"))?; let mtu=read_u32(root.join("mtu"))?;
    let master=fs::read_link(root.join("master")).ok().and_then(|p| p.file_name().map(|v|v.to_string_lossy().to_string()));
    Ok(InterfaceQueue{interface:iface.into(),ifindex,queue,mtu,master})
}

fn validate_plan_live(plan:&AfxdpPlan)->Result<()> {
    if plan.schema_version!=AFXDP_SCHEMA_VERSION { bail!("unsupported AF_XDP plan schema {}",plan.schema_version); }
    if !plan.dedicated_interfaces_confirmed { bail!("plan lacks dedicated-interface confirmation"); }
    let a=inspect_queue(&plan.side_a.interface,plan.side_a.queue)?; let b=inspect_queue(&plan.side_b.interface,plan.side_b.queue)?;
    if a.ifindex!=plan.side_a.ifindex || b.ifindex!=plan.side_b.ifindex { bail!("interface identity drift since plan generation; regenerate plan"); }
    if a.mtu!=plan.side_a.mtu || b.mtu!=plan.side_b.mtu { bail!("interface MTU drift since plan generation; regenerate plan"); }
    Ok(())
}

fn read_runtime(pin_root:&Path)->Result<Vec<QueueRuntime>> {
    let rows=dump_map(&pin_root.join("maps/afxdp_runtime"))?; let mut out=Vec::new();
    for row in rows {
        let Some(k)=bytes(row.get("key")) else{continue}; let Some(v)=bytes(row.get("value")) else{continue};
        if k.len()<4 || v.len()<88 {continue;} let key=u32::from_ne_bytes(k[0..4].try_into().unwrap());
        let u64at=|o:usize|u64::from_ne_bytes(v[o..o+8].try_into().unwrap()); let u32at=|o:usize|u32::from_ne_bytes(v[o..o+4].try_into().unwrap());
        let worker=u32at(84); if worker==0 {continue;}
        out.push(QueueRuntime{slot:key/64,queue:key%64,rx_packets:u64at(0),rx_bytes:u64at(8),tx_packets:u64at(16),tx_bytes:u64at(24),dropped_packets:u64at(32),tx_ring_full:u64at(40),fill_deferred:u64at(48),poll_wakeups:u64at(56),multibuf_drops:u64at(64),last_update_ns:u64at(72),zero_copy:u32at(80)!=0,worker_pid:worker});
    }
    out.sort_by_key(|r|(r.slot,r.queue)); Ok(out)
}

fn read_xdp_stats(pin_root:&Path)->Result<Vec<XdpQueueStat>> {
    let rows=dump_map(&pin_root.join("maps/afxdp_xdp_stats"))?; let mut out=Vec::new();
    for row in rows {
        let Some(k)=bytes(row.get("key")) else{continue}; if k.len()<4{continue;} let key=u32::from_ne_bytes(k[0..4].try_into().unwrap());
        let mut sums=[0u64;5];
        if let Some(vals)=row.get("values").and_then(Value::as_array) {
            for cpu in vals { if let Some(v)=bytes(cpu.get("value")) { if v.len()>=40 { for (i,o) in [0usize,8,16,24,32].iter().enumerate(){sums[i]=sums[i].saturating_add(u64::from_ne_bytes(v[*o..*o+8].try_into().unwrap()));} } } }
        } else if let Some(v)=bytes(row.get("value")) { if v.len()>=40 { for (i,o) in [0usize,8,16,24,32].iter().enumerate(){sums[i]=u64::from_ne_bytes(v[*o..*o+8].try_into().unwrap());} } }
        if sums.iter().all(|v|*v==0){continue;}
        out.push(XdpQueueStat{slot:key/64,queue:key%64,seen_packets:sums[0],seen_bytes:sums[1],redirect_attempts:sums[2],pass_inactive:sums[3],pass_queue_disabled:sums[4]});
    }
    out.sort_by_key(|r|(r.slot,r.queue)); Ok(out)
}

fn dump_map(path:&Path)->Result<Vec<Value>> {
    if !path.exists(){return Ok(Vec::new());}
    let out=Command::new("bpftool").args(["-j","map","dump","pinned",path.to_string_lossy().as_ref()]).output()?;
    if !out.status.success(){bail!("bpftool dump {} failed: {}",path.display(),String::from_utf8_lossy(&out.stderr).trim());}
    Ok(serde_json::from_slice(&out.stdout)?)
}

fn bytes(v:Option<&Value>)->Option<Vec<u8>> {
    let a=v?.as_array()?; let mut out=Vec::with_capacity(a.len());
    for x in a { if let Some(n)=x.as_u64(){out.push(n as u8);} else if let Some(s)=x.as_str(){out.push(u8::from_str_radix(s.trim_start_matches("0x"),16).ok()?);} else{return None;} }
    Some(out)
}

fn validate_iface_name(name:&str)->Result<()> {
    if name.is_empty() || name.len()>15 || name.contains('/') || name.contains('\0') { bail!("invalid interface name {name:?}"); }
    Ok(())
}
fn read_u32(path:PathBuf)->Result<u32>{Ok(fs::read_to_string(&path).with_context(||format!("reading {}",path.display()))?.trim().parse()?)}
fn command_exists(cmd:&str)->bool{if cmd.contains('/'){Path::new(cmd).exists()}else{Command::new("sh").args(["-c",&format!("command -v -- {} >/dev/null 2>&1",shell_word(cmd))]).status().map(|s|s.success()).unwrap_or(false)}}
fn shell_word(s:&str)->String{s.chars().filter(|c|c.is_ascii_alphanumeric()||"._-/".contains(*c)).collect()}
fn helper_path(env_name:&str,default:&str)->String{env::var(env_name).unwrap_or_else(|_|default.into())}
fn control_path(root:&Path,id:Uuid)->PathBuf{root.join(format!("{id}.control.json"))}
fn process_alive(pid:u32)->bool{Path::new(&format!("/proc/{pid}")).exists()}
fn write_json_atomic<T:Serialize>(path:&Path,value:&T)->Result<()> { let tmp=path.with_extension("tmp");fs::write(&tmp,serde_json::to_vec_pretty(value)?)?;fs::rename(tmp,path)?;Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn modes(){assert_eq!(AfxdpMode::parse("zerocopy").unwrap(),AfxdpMode::Zerocopy);assert!(AfxdpMode::parse("magic").is_err());}
    #[test] fn metrics_are_labeled(){let s=AfxdpStatus{schema_version:1,vm_id:Uuid::nil(),running:false,worker_pid:None,loader:None,runtime:vec![],xdp:vec![],findings:vec![]};assert!(prometheus(&s).contains("fluxvm_afxdp_running"));}
    #[test] fn key_math(){let key=1*64+63;assert_eq!(key/64,1);assert_eq!(key%64,63);}
}
