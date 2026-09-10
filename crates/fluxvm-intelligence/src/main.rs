// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use axum::{Json, Router, extract::{Path, State}, http::StatusCode, response::{IntoResponse, Response}, routing::get};
use fluxvm_core::model::{VmRecord, VmStatus};
use fluxvm_intelligence::{DEFAULT_PIN_ROOT, FeatureProbe, NetworkVmStats, VmDiagnosis, VmRuntimeSnapshot, diagnose_vm_with_reasons, probe, register_raw, snapshot_raw, snapshot_record, unregister_raw, unregister_exact, unregister_stale_tids};
use fluxvm_network::{dataplane::{PodNetworkPolicy, VmNetworkPolicy}, ebpf::{DropReasonRecord, FlowRecord}};
use serde::Serialize;
use serde_json::json;
use std::{collections::{BTreeMap, BTreeSet}, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct Config {
    api_url: String,
    api_token: Option<String>,
    listen: SocketAddr,
    pin_root: PathBuf,
    sync_every: Duration,
}
impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            api_url: env::var("FLUXVM_API_URL").unwrap_or_else(|_| "http://127.0.0.1:7788".into()).trim_end_matches('/').into(),
            api_token: env::var("FLUXVM_API_TOKEN").ok().filter(|s| !s.is_empty()),
            listen: env::var("FLUXVM_INTEL_LISTEN").unwrap_or_else(|_| "127.0.0.1:7790".into()).parse().context("FLUXVM_INTEL_LISTEN")?,
            pin_root: env::var("FLUXVM_INTEL_PIN_ROOT").map(PathBuf::from).unwrap_or_else(|_| DEFAULT_PIN_ROOT.into()),
            sync_every: Duration::from_millis(env::var("FLUXVM_INTEL_SYNC_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(2000)),
        })
    }
}

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    snapshots: Arc<RwLock<BTreeMap<Uuid, VmRuntimeSnapshot>>>,
    registrations: Arc<RwLock<BTreeMap<Uuid, (u32, Vec<u32>)>>>,
    probe: Arc<RwLock<FeatureProbe>>,
}

#[derive(Serialize)]
struct Status { ok: bool, probe: FeatureProbe, vm_count: usize }

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args: Vec<String> = env::args().collect();
    let cfg = Config::from_env()?;
    match args.get(1).map(String::as_str).unwrap_or("daemon") {
        "probe" => { println!("{}", serde_json::to_string_pretty(&probe(&cfg.pin_root))?); Ok(()) }
        "register" => { let (id,pid)=parse_id_pid(&args)?; let tids=register_raw(id,pid,&cfg.pin_root)?; println!("{}", json!({"vm_id":id,"pid":pid,"tracked_tids":tids})); Ok(()) }
        "unregister" => { let id=args.get(2).context("usage: fluxvm-intelligence unregister <uuid> [pid]")?.parse()?; let pid=args.get(3).and_then(|s|s.parse().ok()); unregister_raw(id,pid,&cfg.pin_root)?; Ok(()) }
        "snapshot" => { let (id,pid)=parse_id_pid(&args)?; println!("{}",serde_json::to_string_pretty(&snapshot_raw(id,pid,&cfg.pin_root)?)?); Ok(()) }
        "diagnose" => diagnose_cli(&args).await,
        "daemon" => daemon(cfg).await,
        other => bail!("unknown command {other}; use daemon|probe|register|unregister|snapshot|diagnose"),
    }
}

fn parse_id_pid(args: &[String]) -> Result<(Uuid,u32)> {
    let id=args.get(2).context("expected <uuid> <pid>")?.parse()?;
    let pid=args.get(3).context("expected <uuid> <pid>")?.parse()?;
    Ok((id,pid))
}

async fn daemon(cfg: Config) -> Result<()> {
    let state = AppState {
        cfg: Arc::new(cfg.clone()),
        snapshots: Arc::new(RwLock::new(BTreeMap::new())),
        registrations: Arc::new(RwLock::new(BTreeMap::new())),
        probe: Arc::new(RwLock::new(probe(&cfg.pin_root))),
    };
    let bg_state=state.clone(); let bg_cfg=cfg.clone();
    tokio::spawn(async move { loop { if let Err(e)=sync_once(&bg_cfg,&bg_state).await { warn!(error=%e,"runtime intelligence sync failed"); } tokio::time::sleep(bg_cfg.sync_every).await; } });
    let app=Router::new()
        .route("/healthz",get(health))
        .route("/v1/intelligence/status",get(status))
        .route("/v1/intelligence/vms",get(list_vms))
        .route("/v1/intelligence/vms/{id}",get(get_vm))
        .route("/v1/intelligence/vms/{id}/diagnose",get(diagnose))
        .route("/metrics",get(metrics))
        .with_state(state);
    let listener=tokio::net::TcpListener::bind(cfg.listen).await?;
    info!(listen=%cfg.listen,"FluxVM runtime intelligence listening");
    axum::serve(listener,app).await?; Ok(())
}

async fn sync_once(cfg:&Config,state:&AppState)->Result<()> {
    let client=reqwest::Client::new(); let mut req=client.get(format!("{}/v1/vms",cfg.api_url));
    if let Some(token)=&cfg.api_token { req=req.bearer_auth(token); }
    let vms:Vec<VmRecord>=req.send().await?.error_for_status()?.json().await?;
    let old_regs=state.registrations.read().await.clone();
    let mut next=BTreeMap::new();
    let mut next_regs=BTreeMap::new();
    for vm in &vms {
        if !matches!(vm.status,VmStatus::Running|VmStatus::Paused) || vm.pid.is_none() { continue; }
        match snapshot_record(vm,&cfg.pin_root) {
            Ok(mut s)=>{
                s.network=fetch_network_stats(cfg,vm.id).await.ok();
                let pid=s.pid;
                let tids=s.tracked_tids.clone();
                if let Some((old_pid,old_tids))=old_regs.get(&vm.id) {
                    if *old_pid != pid {
                        let _=unregister_exact(vm.id,*old_pid,old_tids,&cfg.pin_root);
                        let _=register_raw(vm.id,pid,&cfg.pin_root);
                    } else {
                        let now:BTreeSet<u32>=tids.iter().copied().collect();
                        let stale:Vec<u32>=old_tids.iter().copied().filter(|t|!now.contains(t)).collect();
                        let _=unregister_stale_tids(&stale,&cfg.pin_root);
                    }
                }
                next_regs.insert(vm.id,(pid,tids)); next.insert(vm.id,s);
            },
            Err(e)=>warn!(vm=%vm.id,error=%e,"snapshot failed")
        }
    }
    for (id,(pid,tids)) in &old_regs {
        if !next_regs.contains_key(id) { let _=unregister_exact(*id,*pid,tids,&cfg.pin_root); }
    }
    *state.snapshots.write().await=next;
    *state.registrations.write().await=next_regs;
    *state.probe.write().await=probe(&cfg.pin_root);
    Ok(())
}



async fn diagnose_cli(args: &[String]) -> Result<()> {
    let id: Uuid = args
        .get(2)
        .context("usage: fluxvm-intelligence diagnose <uuid>")?
        .parse()?;
    let base = env::var("FLUXVM_INTEL_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:7790".into())
        .trim_end_matches('/')
        .to_string();
    let response = reqwest::Client::new()
        .get(format!("{base}/v1/intelligence/vms/{id}/diagnose"))
        .send()
        .await?
        .error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn diagnose(Path(id): Path<Uuid>, State(state): State<AppState>) -> Response {
    let Some(snapshot) = state.snapshots.read().await.get(&id).cloned() else {
        return (StatusCode::NOT_FOUND, Json(json!({"error":"VM intelligence snapshot not found"}))).into_response();
    };
    let policy = match fetch_network_policy(&state.cfg, id).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({"error":format!("network policy: {e:#}")}))).into_response(),
    };
    let pod_policy = match fetch_pod_policy(&state.cfg, id).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({"error":format!("pod policy: {e:#}")}))).into_response(),
    };
    let flows = match fetch_network_flows(&state.cfg, id, 256).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(json!({"error":format!("network flows: {e:#}")}))).into_response(),
    };
    // Rolling-upgrade safe: an older control plane has no schema-v6 reason
    // endpoint, in which case Set-2 inference remains the fallback.
    let reasons = fetch_drop_reasons(&state.cfg, id, 256).await.unwrap_or_default();
    let report: VmDiagnosis = diagnose_vm_with_reasons(
        &snapshot,
        &policy,
        pod_policy.as_ref(),
        &flows,
        &reasons,
    );
    Json(report).into_response()
}

fn authed_get(cfg: &Config, url: String) -> reqwest::RequestBuilder {
    let request = reqwest::Client::new().get(url);
    if let Some(token) = &cfg.api_token { request.bearer_auth(token) } else { request }
}

async fn fetch_network_policy(cfg: &Config, id: Uuid) -> Result<VmNetworkPolicy> {
    let response = authed_get(cfg, format!("{}/v1/vms/{}/network/effective", cfg.api_url, id))
        .send().await?.error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    let effective = value.get("effective").cloned().unwrap_or(value);
    serde_json::from_value(effective).context("decoding effective VM network policy")
}

async fn fetch_pod_policy(cfg: &Config, id: Uuid) -> Result<Option<PodNetworkPolicy>> {
    let response = authed_get(cfg, format!("{}/v1/vms/{}/network/pod-policy", cfg.api_url, id)).send().await?;
    if response.status().as_u16() == 404 { return Ok(None); }
    let response = response.error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    if value.is_null() { return Ok(None); }
    if let Some(policy) = value.get("policy") {
        if policy.is_null() { return Ok(None); }
        return Ok(Some(serde_json::from_value(policy.clone())?));
    }
    Ok(Some(serde_json::from_value(value)?))
}

async fn fetch_network_flows(cfg: &Config, id: Uuid, limit: usize) -> Result<Vec<FlowRecord>> {
    let response = authed_get(cfg, format!("{}/v1/vms/{}/network/flows?limit={}", cfg.api_url, id, limit.clamp(1,4096)))
        .send().await?.error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    let items = value.get("items").cloned().unwrap_or(value);
    Ok(serde_json::from_value(items)?)
}

async fn fetch_drop_reasons(cfg: &Config, id: Uuid, limit: usize) -> Result<Vec<DropReasonRecord>> {
    let response = authed_get(
        cfg,
        format!("{}/v1/vms/{}/network/drop-reasons?limit={}", cfg.api_url, id, limit.clamp(1,4096)),
    )
    .send()
    .await?;
    if response.status().as_u16() == 404 {
        return Ok(Vec::new());
    }
    let response = response.error_for_status()?;
    let value: serde_json::Value = response.json().await?;
    let items = value.get("items").cloned().unwrap_or(value);
    Ok(serde_json::from_value(items)?)
}

async fn fetch_network_stats(cfg:&Config,id:Uuid)->Result<NetworkVmStats>{
    let client=reqwest::Client::new();
    let mut req=client.get(format!("{}/v1/vms/{}/network/stats",cfg.api_url,id));
    if let Some(token)=&cfg.api_token { req=req.bearer_auth(token); }
    Ok(req.send().await?.error_for_status()?.json().await?)
}

async fn health()->Json<serde_json::Value>{Json(json!({"ok":true}))}
async fn status(State(s):State<AppState>)->Json<Status>{let p=s.probe.read().await.clone();let n=s.snapshots.read().await.len();Json(Status{ok:p.ready_for_scheduler(),probe:p,vm_count:n})}
async fn list_vms(State(s):State<AppState>)->Json<Vec<VmRuntimeSnapshot>>{Json(s.snapshots.read().await.values().cloned().collect())}
async fn get_vm(Path(id):Path<Uuid>,State(s):State<AppState>)->Response{match s.snapshots.read().await.get(&id).cloned(){Some(v)=>Json(v).into_response(),None=>(StatusCode::NOT_FOUND,Json(json!({"error":"VM intelligence snapshot not found"}))).into_response()}}
async fn metrics(State(s):State<AppState>)->Response{let rows=s.snapshots.read().await;let mut out=String::new();out.push_str("# HELP fluxvm_intel_kvm_exits_total KVM exits attributed to a FluxVM VM.\n# TYPE fluxvm_intel_kvm_exits_total counter\n");for v in rows.values(){let labels=format!("vm=\"{}\",name=\"{}\",backend=\"{}\"",v.vm_id,escape(&v.name),escape(&v.backend));out.push_str(&format!("fluxvm_intel_kvm_exits_total{{{labels}}} {}\n",v.kernel.kvm_exits));out.push_str(&format!("fluxvm_intel_guest_run_seconds_total{{{labels}}} {:.9}\n",v.kernel.guest_run_ns as f64/1e9));out.push_str(&format!("fluxvm_intel_sched_wakeups_total{{{labels}}} {}\n",v.kernel.sched_wakeups));out.push_str(&format!("fluxvm_intel_runnable_delay_seconds_total{{{labels}}} {:.9}\n",v.kernel.runnable_delay_ns as f64/1e9));out.push_str(&format!("fluxvm_intel_runnable_delay_max_seconds{{{labels}}} {:.9}\n",v.kernel.runnable_delay_max_ns as f64/1e9));out.push_str(&format!("fluxvm_intel_thread_migrations_total{{{labels}}} {}\n",v.kernel.migrations));out.push_str(&format!("fluxvm_intel_vmm_read_bytes{{{labels}}} {}\n",v.process.read_bytes));out.push_str(&format!("fluxvm_intel_vmm_write_bytes{{{labels}}} {}\n",v.process.write_bytes));if let Some(n)=&v.network{out.push_str(&format!("fluxvm_intel_network_allowed_packets_total{{{labels}}} {}\n",n.allowed_packets));out.push_str(&format!("fluxvm_intel_network_dropped_packets_total{{{labels}}} {}\n",n.dropped_packets));out.push_str(&format!("fluxvm_intel_network_dropped_bytes_total{{{labels}}} {}\n",n.dropped_bytes));}} (StatusCode::OK,[("content-type","text/plain; version=0.0.4; charset=utf-8")],out).into_response()}
fn escape(s:&str)->String{s.replace('\\',"\\\\").replace('"',"\\\"").replace('\n',"\\n")}
