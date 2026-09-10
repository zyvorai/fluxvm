// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, env, fs, net::IpAddr, path::{Path, PathBuf}, process::Command, time::{SystemTime, UNIX_EPOCH}};
use uuid::Uuid;

pub const QUICLB_SCHEMA_VERSION:u32=1;
pub const DEFAULT_QUICLB_PIN_ROOT:&str="/sys/fs/bpf/fluxvm/quiclb";
pub const DEFAULT_QUICLB_STATE_ROOT:&str="/run/fluxvm/quiclb";
const ALLOWED_MAGLEV:&[u32]=&[251,509,1021,2039,4093,8191,16381];
const MAX_CID:u8=20;
const MAX_BACKENDS:usize=128;

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="lowercase")]
pub enum QuicLbMode{Native,Generic,Offload}
impl QuicLbMode{pub fn parse(s:&str)->Result<Self>{match s{"native"=>Ok(Self::Native),"generic"=>Ok(Self::Generic),"offload"|"hw"=>Ok(Self::Offload),_=>bail!("mode must be native|generic|offload")}} pub fn as_str(&self)->&'static str{match self{Self::Native=>"native",Self::Generic=>"generic",Self::Offload=>"offload"}}}

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,Default)]
#[serde(rename_all="lowercase")]
pub enum QuicBackendState{#[default]Ready,Draining,Unhealthy}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicBackend{pub id:u32,pub interface:String,pub mac:String,#[serde(default="one")]pub weight:u16,#[serde(default)]pub state:QuicBackendState,#[serde(default)]pub address:Option<IpAddr>}
fn one()->u16{1}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicService{pub name:String,pub vip:IpAddr,pub port:u16,#[serde(default)]pub short_dcid_len:u8,#[serde(default="yes")]pub quic_only:bool,#[serde(default)]pub sample_rate:u32,#[serde(default)]pub maglev_table_size:Option<u32>,pub backends:Vec<QuicBackend>}
fn yes()->bool{true}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicLbSpec{pub instance_id:Uuid,pub interface:String,pub mode:QuicLbMode,pub services:Vec<QuicService>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct CompiledBackend{pub id:u32,pub interface:String,pub ifindex:u32,pub mac:String,pub weight:u16,pub state:QuicBackendState,pub address:Option<IpAddr>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct CompiledService{pub name:String,pub service_id:u32,pub vip:IpAddr,pub port:u16,pub short_dcid_len:u8,pub quic_only:bool,pub sample_rate:u32,pub maglev_table_size:u32,pub backends:Vec<CompiledBackend>,pub maglev:Vec<u32>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicLbPlan{pub schema_version:u32,pub instance_id:Uuid,pub interface:String,pub ifindex:u32,pub mode:QuicLbMode,pub generation:u32,pub services:Vec<CompiledService>,pub warnings:Vec<String>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicLbControl{pub schema_version:u32,pub instance_id:Uuid,pub pin_root:String,pub interface:String,pub mode:QuicLbMode,pub generation:u32,pub created_unix_seconds:u64,pub plan:QuicLbPlan}
#[derive(Debug,Clone,Default,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicServiceStats{pub service_id:u32,pub packets:u64,pub bytes:u64,pub quic_long:u64,pub quic_short:u64,pub affinity_hits:u64,pub affinity_misses:u64,pub tuple_fallbacks:u64,pub backend_misses:u64,pub redirects:u64,pub non_quic_pass:u64,pub parse_errors:u64,pub reselections:u64,pub affinity_store_failures:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct QuicLbStatus{pub schema_version:u32,pub instance_id:Uuid,pub attached:bool,pub generation:u32,pub interface:String,pub mode:QuicLbMode,pub services:Vec<CompiledService>,pub stats:Vec<QuicServiceStats>,pub affinity_entries:usize,pub loader:Option<Value>,pub findings:Vec<String>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct AffinityEntry{pub service_id:u32,pub cid_hex:String,pub backend_id:u32,pub source_last_seen_ns:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct AffinitySnapshot{pub schema_version:u32,pub instance_id:Uuid,pub generation:u32,pub entries:Vec<AffinityEntry>}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct SmartNicProbe{pub schema_version:u32,pub interface:String,pub ifindex:u32,pub driver:Option<String>,pub bus_info:Option<String>,pub pci_device:Option<String>,pub phys_port_name:Option<String>,pub bpftool_device_probe:bool,pub existing_xdp:Option<String>,pub eligible_hint:bool,pub blockers:Vec<String>,pub warnings:Vec<String>,pub raw_bpftool:Option<String>}

pub fn build_plan(spec:&QuicLbSpec)->Result<QuicLbPlan>{
    if spec.services.is_empty(){bail!("at least one QUIC service is required")}
    let primary_ifindex=ifindex(&spec.interface)?;let mut names=HashSet::new();let mut ids=HashSet::new();let mut listeners=HashSet::new();let mut out=Vec::new();let mut warnings=Vec::new();
    for s in &spec.services{
        if !names.insert(s.name.clone()){bail!("duplicate service name {}",s.name)}
        if s.port==0{bail!("{}: port 0 is invalid",s.name)}
        if !listeners.insert((s.vip,s.port)){bail!("duplicate QUIC listener {}:{}",s.vip,s.port)}
        if s.short_dcid_len>MAX_CID{bail!("{}: short_dcid_len must be 0..={MAX_CID}",s.name)}
        if s.backends.is_empty()||s.backends.len()>MAX_BACKENDS{bail!("{}: backend count must be 1..={MAX_BACKENDS}",s.name)}
        let sid=service_id(&s.name,s.vip,s.port);if !ids.insert(sid){bail!("service-id collision involving {} (id {sid})",s.name)}
        let size=s.maglev_table_size.unwrap_or(4093);if !ALLOWED_MAGLEV.contains(&size){bail!("{}: maglev table size must be one of {:?}",s.name,ALLOWED_MAGLEV)}
        let mut bids=HashSet::new();let mut compiled=Vec::new();
        for b in &s.backends{
            if b.id==0||!bids.insert(b.id){bail!("{}: backend ids must be unique and non-zero",s.name)}
            if b.weight==0||b.weight>32{bail!("{} backend {}: weight must be 1..=32",s.name,b.id)}
            let bi=ifindex(&b.interface)?;parse_mac(&b.mac)?;
            compiled.push(CompiledBackend{id:b.id,interface:b.interface.clone(),ifindex:bi,mac:b.mac.to_lowercase(),weight:b.weight,state:b.state.clone(),address:b.address});
        }
        let ready:Vec<&CompiledBackend>=compiled.iter().filter(|b|matches!(b.state,QuicBackendState::Ready)).collect();
        if ready.is_empty(){bail!("{} has no ready backend",s.name)}
        if s.short_dcid_len==0{warnings.push(format!("{}: QUIC short headers fall back to the 5-tuple because short_dcid_len=0; connection migration affinity is strongest with an explicit DCID length",s.name));}
        let maglev=maglev_table(sid,size,&ready)?;
        out.push(CompiledService{name:s.name.clone(),service_id:sid,vip:s.vip,port:s.port,short_dcid_len:s.short_dcid_len,quic_only:s.quic_only,sample_rate:s.sample_rate,maglev_table_size:size,backends:compiled,maglev});
    }
    warnings.push("DSR mode preserves the VIP destination IP; every backend must own the VIP locally and return traffic directly without relying on this node for reverse NAT".into());
    if matches!(spec.mode,QuicLbMode::Offload){warnings.push("hardware offload is device/verifier specific; SmartNIC probe is advisory and the loader's actual offload BPF load is authoritative".into());}
    Ok(QuicLbPlan{schema_version:QUICLB_SCHEMA_VERSION,instance_id:spec.instance_id,interface:spec.interface.clone(),ifindex:primary_ifindex,mode:spec.mode.clone(),generation:0,services:out,warnings})
}

pub fn smartnic_probe(iface:&str)->Result<SmartNicProbe>{
    let idx=ifindex(iface)?;let mut blockers=Vec::new();let mut warnings=Vec::new();let device=Path::new("/sys/class/net").join(iface).join("device");
    if !device.exists(){blockers.push("interface has no PCI/device sysfs node; hardware XDP offload is unlikely".into());}
    let (driver,bus)=ethtool_driver(iface);let pci_device=fs::canonicalize(&device).ok().and_then(|p|p.file_name().map(|x|x.to_string_lossy().into_owned()));
    let phys=fs::read_to_string(Path::new("/sys/class/net").join(iface).join("phys_port_name")).ok().map(|s|s.trim().to_string()).filter(|s|!s.is_empty());
    let existing=existing_xdp(iface);if existing.is_some(){blockers.push("an XDP owner is already attached; FluxVM will not replace it".into());}
    let output=Command::new("bpftool").args(["feature","probe","dev",iface]).output();
    let (ok,raw)=match output{Ok(o)=>(o.status.success(),Some(String::from_utf8_lossy(if o.status.success(){&o.stdout}else{&o.stderr}).to_string())),Err(_)=>(false,None)};
    if !ok{blockers.push("bpftool device feature probe failed; no hardware-offload capability has been demonstrated".into());}
    warnings.push("offload profile replaces the LRU affinity map with a bounded HASH map and disables ring-buffer events, but map/program support remains NIC-driver specific".into());
    warnings.push("eligible_hint is preflight only; successful BPF_PROG_LOAD with ifindex and XDP HW attach is the final proof".into());
    Ok(SmartNicProbe{schema_version:QUICLB_SCHEMA_VERSION,interface:iface.into(),ifindex:idx,driver,bus_info:bus,pci_device,phys_port_name:phys,bpftool_device_probe:ok,existing_xdp:existing,eligible_hint:blockers.is_empty(),blockers,warnings,raw_bpftool:raw})
}

pub fn apply(plan:&QuicLbPlan,pin_base:&Path,state_root:&Path,ack_hw:bool)->Result<QuicLbControl>{
    if plan.schema_version!=QUICLB_SCHEMA_VERSION{bail!("unsupported plan schema {}",plan.schema_version)}
    if matches!(plan.mode,QuicLbMode::Offload)&&!ack_hw{bail!("hardware offload requires explicit --ack-hardware-offload")}
    if ifindex(&plan.interface)?!=plan.ifindex{bail!("interface ifindex drift for {}",plan.interface)}
    fs::create_dir_all(state_root)?;
    let cp=control_path(state_root,plan.instance_id);
    let old=if cp.exists(){Some(serde_json::from_slice::<QuicLbControl>(&fs::read(&cp)?).with_context(||format!("parsing {}",cp.display()))?)}else{None};
    if let Some(o)=&old{
        if o.interface!=plan.interface||o.mode!=plan.mode{bail!("existing instance uses interface={} mode={}; remove it before changing attachment ownership",o.interface,o.mode.as_str())}
    }
    let generation=match old.as_ref(){Some(x)=>x.generation.checked_add(1).ok_or_else(||anyhow::anyhow!("generation space exhausted; remove and recreate the QUIC LB instance"))?,None=>1};
    let pin_root=pin_base.join(plan.instance_id.to_string());
    let loader=helper("FLUXVM_QUICLB_LOADER","/usr/libexec/fluxvm/fluxvm-quiclb-loader");
    let attached_new=old.is_none();
    if attached_new{
        let obj=match plan.mode{QuicLbMode::Offload=>env::var("FLUXVM_QUICLB_HW_OBJECT").unwrap_or_else(|_|"/usr/lib/fluxvm/bpf/fluxvm_quiclb_hw.bpf.o".into()),_=>env::var("FLUXVM_QUICLB_OBJECT").unwrap_or_else(|_|"/usr/lib/fluxvm/bpf/fluxvm_quiclb.bpf.o".into())};
        let root_s=pin_root.display().to_string();
        let o=Command::new(&loader).args(["load",&obj,&root_s,&plan.interface,plan.mode.as_str()]).output().with_context(||format!("running {loader}"))?;
        if !o.status.success(){let _=fs::remove_dir_all(&pin_root);bail!("QUIC LB attach failed: {}",String::from_utf8_lossy(&o.stderr).trim())}
    }
    let mut live=plan.clone();live.generation=generation;
    if let Err(e)=populate_generation(&pin_root,&live){cleanup_failed_generation(&loader,&pin_root,&live,old.as_ref(),attached_new);return Err(e)}
    if let Err(e)=publish_generation(&pin_root,generation){cleanup_failed_generation(&loader,&pin_root,&live,old.as_ref(),attached_new);return Err(e)}
    let control=QuicLbControl{schema_version:QUICLB_SCHEMA_VERSION,instance_id:plan.instance_id,pin_root:pin_root.display().to_string(),interface:plan.interface.clone(),mode:plan.mode,generation,created_unix_seconds:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),plan:live.clone()};
    if let Err(e)=write_json_atomic(&cp,&control){
        let rollback=old.as_ref().map(|x|x.generation).unwrap_or(0);
        let _=publish_generation(&pin_root,rollback);
        cleanup_failed_generation(&loader,&pin_root,&live,old.as_ref(),attached_new);
        return Err(e);
    }
    if let Some(o)=old{let root_s=pin_root.display().to_string();let _=Command::new(&loader).args(["gc",&root_s,&o.generation.to_string()]).status();}
    Ok(control)
}

fn cleanup_failed_generation(loader:&str,pin_root:&Path,live:&QuicLbPlan,old:Option<&QuicLbControl>,attached_new:bool){
    let root_s=pin_root.display().to_string();
    let _=Command::new(loader).args(["gc",&root_s,&live.generation.to_string()]).status();
    if attached_new{
        let _=Command::new(loader).args(["detach",&root_s,&live.interface,live.mode.as_str()]).status();
        let _=fs::remove_dir_all(pin_root);
    }else if let Some(o)=old{
        let _=publish_generation(pin_root,o.generation);
    }
}

pub fn remove(id:Uuid,state_root:&Path)->Result<()>{
    let p=control_path(state_root,id);let c:QuicLbControl=serde_json::from_slice(&fs::read(&p).with_context(||format!("reading {}",p.display()))?)?;let loader=helper("FLUXVM_QUICLB_LOADER","/usr/libexec/fluxvm/fluxvm-quiclb-loader");
    let o=Command::new(loader).args(["detach",&c.pin_root,&c.interface,c.mode.as_str()]).output()?;if !o.status.success(){bail!("detach failed: {}",String::from_utf8_lossy(&o.stderr).trim())}
    let _=fs::remove_dir_all(&c.pin_root);let _=fs::remove_file(p);Ok(())
}

pub fn status(id:Uuid,state_root:&Path)->Result<QuicLbStatus>{
    let p=control_path(state_root,id);let c:QuicLbControl=serde_json::from_slice(&fs::read(&p).with_context(||format!("reading {}",p.display()))?)?;let loader=helper("FLUXVM_QUICLB_LOADER","/usr/libexec/fluxvm/fluxvm-quiclb-loader");
    let o=Command::new(loader).args(["status",&c.pin_root,&c.interface,c.mode.as_str()]).output();let lv=o.ok().and_then(|x|serde_json::from_slice::<Value>(&x.stdout).ok());let attached=lv.as_ref().and_then(|v|v.get("attached")).and_then(Value::as_bool).unwrap_or(false);
    let stats=read_stats(Path::new(&c.pin_root)).unwrap_or_default();let affinity_entries=dump_map(Path::new(&c.pin_root).join("maps/fluxvm_quic_affinity")).map(|v|v.len()).unwrap_or(0);let mut findings=Vec::new();if !attached{findings.push("pinned QUIC LB control exists but the expected XDP program is not live".into())}if matches!(c.mode,QuicLbMode::Offload){findings.push("hardware-offload profile intentionally omits live ring-buffer events and uses bounded HASH affinity state".into())}
    Ok(QuicLbStatus{schema_version:QUICLB_SCHEMA_VERSION,instance_id:id,attached,generation:c.generation,interface:c.interface,mode:c.mode,services:c.plan.services,stats,affinity_entries,loader:lv,findings})
}
pub fn list_statuses(state_root:&Path)->Result<Vec<QuicLbStatus>>{let mut out=Vec::new();if !state_root.exists(){return Ok(out)}for e in fs::read_dir(state_root)?{let p=e?.path();if p.extension().and_then(|x|x.to_str())!=Some("json"){continue}if let Some(stem)=p.file_stem().and_then(|x|x.to_str()){if let Ok(id)=stem.parse(){if let Ok(s)=status(id,state_root){out.push(s)}}}}Ok(out)}
pub fn prometheus(s:&QuicLbStatus)->String{let mut o=String::new();o.push_str(&format!("fluxvm_quiclb_attached{{instance_id=\"{}\",interface=\"{}\",mode=\"{}\"}} {}\n",s.instance_id,s.interface,s.mode.as_str(),if s.attached{1}else{0}));o.push_str(&format!("fluxvm_quiclb_affinity_entries{{instance_id=\"{}\"}} {}\n",s.instance_id,s.affinity_entries));for x in &s.stats{let l=format!("instance_id=\"{}\",service_id=\"{}\"",s.instance_id,x.service_id);o.push_str(&format!("fluxvm_quiclb_packets{{{l}}} {}\nfluxvm_quiclb_redirects{{{l}}} {}\nfluxvm_quiclb_affinity_hits{{{l}}} {}\nfluxvm_quiclb_affinity_misses{{{l}}} {}\nfluxvm_quiclb_backend_misses{{{l}}} {}\nfluxvm_quiclb_parse_errors{{{l}}} {}\nfluxvm_quiclb_affinity_store_failures{{{l}}} {}\n",x.packets,x.redirects,x.affinity_hits,x.affinity_misses,x.backend_misses,x.parse_errors,x.affinity_store_failures));}o}
pub fn stream_events(id:Uuid,seconds:u32,limit:u32,state_root:&Path)->Result<()>{let c:QuicLbControl=serde_json::from_slice(&fs::read(control_path(state_root,id))?)?;if matches!(c.mode,QuicLbMode::Offload){bail!("event ring is intentionally unavailable in hardware-offload profile")}let h=helper("FLUXVM_QUICLB_EVENTS","/usr/libexec/fluxvm/fluxvm-quiclb-events");let st=Command::new(h).args([&c.pin_root,&seconds.to_string(),&limit.to_string()]).status()?;if !st.success(){bail!("event reader failed: {st}")}Ok(())}

pub fn export_affinity(id:Uuid,state_root:&Path)->Result<AffinitySnapshot>{
    let c:QuicLbControl=serde_json::from_slice(&fs::read(control_path(state_root,id))?)?;
    let rows=dump_map(Path::new(&c.pin_root).join("maps/fluxvm_quic_affinity"))?;let mut entries=Vec::new();
    for r in rows{let k=hex_bytes(r.get("key"));let v=hex_bytes(r.get("value"));if k.len()<28||v.len()<16{continue}let sid=u32::from_ne_bytes(k[0..4].try_into().unwrap());let cid_len=k[4] as usize;if cid_len==0||cid_len>MAX_CID as usize{continue}let cid_hex=k[5..5+cid_len].iter().map(|b|format!("{b:02x}")).collect::<String>();let backend_id=u32::from_ne_bytes(v[0..4].try_into().unwrap());let last=u64::from_ne_bytes(v[8..16].try_into().unwrap());entries.push(AffinityEntry{service_id:sid,cid_hex,backend_id,source_last_seen_ns:last});}
    Ok(AffinitySnapshot{schema_version:QUICLB_SCHEMA_VERSION,instance_id:id,generation:c.generation,entries})
}
pub fn import_affinity(id:Uuid,snap:&AffinitySnapshot,state_root:&Path)->Result<usize>{
    if snap.schema_version!=QUICLB_SCHEMA_VERSION||snap.instance_id!=id{bail!("affinity snapshot does not match target instance")}
    let c:QuicLbControl=serde_json::from_slice(&fs::read(control_path(state_root,id))?)?;let mut allowed=HashSet::new();for s in &c.plan.services{for b in &s.backends{if matches!(b.state,QuicBackendState::Ready|QuicBackendState::Draining){allowed.insert((s.service_id,b.id));}}}
    let map=Path::new(&c.pin_root).join("maps/fluxvm_quic_affinity");let mut n=0;for e in &snap.entries{if !allowed.contains(&(e.service_id,e.backend_id)){continue}let cid=decode_hex(&e.cid_hex)?;if cid.is_empty()||cid.len()>MAX_CID as usize{continue}let mut key=Vec::with_capacity(28);key.extend(e.service_id.to_ne_bytes());key.push(cid.len() as u8);key.extend(&cid);key.resize(28,0);let mut val=Vec::with_capacity(16);val.extend(e.backend_id.to_ne_bytes());val.extend(0u32.to_ne_bytes());val.extend(0u64.to_ne_bytes());map_update(&map,&key,&val)?;n+=1}Ok(n)
}
fn decode_hex(s:&str)->Result<Vec<u8>>{if s.len()%2!=0{bail!("odd-length hex CID")}let mut out=Vec::with_capacity(s.len()/2);for i in (0..s.len()).step_by(2){out.push(u8::from_str_radix(&s[i..i+2],16).context("invalid CID hex")?)}Ok(out)}

fn populate_generation(root:&Path,plan:&QuicLbPlan)->Result<()>{for s in &plan.services{map_update(&root.join("maps/fluxvm_quic_services"),&service_key(plan.generation,s),&service_value(s))?;for b in &s.backends{map_update(&root.join("maps/fluxvm_quic_backends"),&backend_key(plan.generation,s.service_id,b.id),&backend_value(b))?;}for (slot,bid) in s.maglev.iter().enumerate(){map_update(&root.join("maps/fluxvm_quic_maglev"),&maglev_key(plan.generation,s.service_id,slot as u32),&bid.to_ne_bytes())?;}}Ok(())}
fn publish_generation(root:&Path,g:u32)->Result<()>{map_update(&root.join("maps/fluxvm_quic_gen"),&0u32.to_ne_bytes(),&g.to_ne_bytes())}
fn service_key(g:u32,s:&CompiledService)->Vec<u8>{let mut v=Vec::with_capacity(24);v.extend(g.to_ne_bytes());v.push(if s.vip.is_ipv4(){4}else{6});v.push(17);v.extend(s.port.to_ne_bytes());match s.vip{IpAddr::V4(a)=>{v.extend(a.octets());v.extend([0u8;12])},IpAddr::V6(a)=>v.extend(a.octets())};v}
fn service_value(s:&CompiledService)->Vec<u8>{let mut v=Vec::with_capacity(20);v.extend(s.service_id.to_ne_bytes());v.extend(s.maglev_table_size.to_ne_bytes());v.extend((if s.quic_only{1u32}else{0}).to_ne_bytes());v.extend((s.short_dcid_len as u32).to_ne_bytes());v.extend(s.sample_rate.to_ne_bytes());v}
fn backend_key(g:u32,sid:u32,id:u32)->Vec<u8>{[g.to_ne_bytes(),sid.to_ne_bytes(),id.to_ne_bytes()].concat()}
fn backend_value(b:&CompiledBackend)->Vec<u8>{let mut v=Vec::with_capacity(16);v.extend(b.ifindex.to_ne_bytes());let f=match b.state{QuicBackendState::Ready=>1u32,QuicBackendState::Draining=>2,QuicBackendState::Unhealthy=>4};v.extend(f.to_ne_bytes());v.extend(parse_mac(&b.mac).unwrap_or([0;6]));v.extend([0u8;2]);v}
fn maglev_key(g:u32,sid:u32,slot:u32)->Vec<u8>{[g.to_ne_bytes(),sid.to_ne_bytes(),slot.to_ne_bytes()].concat()}
fn map_update(map:&Path,key:&[u8],value:&[u8])->Result<()>{let mut c=Command::new("bpftool");let ms=map.display().to_string();c.args(["map","update","pinned",&ms,"key","hex"]);for b in key{c.arg(format!("{b:02x}"));}c.arg("value").arg("hex");for b in value{c.arg(format!("{b:02x}"));}c.arg("any");let o=c.output().with_context(||format!("updating {}",map.display()))?;if !o.status.success(){bail!("bpftool update {} failed: {}",map.display(),String::from_utf8_lossy(&o.stderr).trim())}Ok(())}
fn dump_map(map:PathBuf)->Result<Vec<Value>>{let ms=map.display().to_string();let o=Command::new("bpftool").args(["-j","map","dump","pinned",&ms]).output()?;if !o.status.success(){bail!("bpftool dump failed")};Ok(serde_json::from_slice(&o.stdout)?)}
fn read_stats(root:&Path)->Result<Vec<QuicServiceStats>>{let rows=dump_map(root.join("maps/fluxvm_quic_stats"))?;let mut out=Vec::new();for r in rows{let kb=hex_bytes(r.get("key"));let vb=hex_bytes(r.get("value"));if kb.len()<4||vb.len()<104{continue}let sid=u32::from_ne_bytes(kb[0..4].try_into().unwrap());let mut x=QuicServiceStats{service_id:sid,..Default::default()};let vals:Vec<u64>=(0..13).map(|i|u64::from_ne_bytes(vb[i*8..i*8+8].try_into().unwrap())).collect();x.packets=vals[0];x.bytes=vals[1];x.quic_long=vals[2];x.quic_short=vals[3];x.affinity_hits=vals[4];x.affinity_misses=vals[5];x.tuple_fallbacks=vals[6];x.backend_misses=vals[7];x.redirects=vals[8];x.non_quic_pass=vals[9];x.parse_errors=vals[10];x.reselections=vals[11];x.affinity_store_failures=vals[12];out.push(x)}out.sort_by_key(|x|x.service_id);Ok(out)}
fn hex_bytes(v:Option<&Value>)->Vec<u8>{match v{Some(Value::Array(a))=>a.iter().filter_map(|x|x.as_str().and_then(|s|u8::from_str_radix(s.trim_start_matches("0x"),16).ok())).collect(),Some(Value::String(s))=>s.split_whitespace().filter_map(|x|u8::from_str_radix(x.trim_start_matches("0x"),16).ok()).collect(),_=>vec![]}}
fn service_id(name:&str,vip:IpAddr,port:u16)->u32{let mut h=2166136261u32;for b in name.as_bytes().iter().copied().chain(vip.to_string().bytes()).chain(port.to_be_bytes()){h^=b as u32;h=h.wrapping_mul(16777619)}if h==0{1}else{h}}
fn hash64(mut h:u64,data:&[u8])->u64{for b in data{h^=*b as u64;h=h.wrapping_mul(1099511628211)}h}
fn maglev_table(sid:u32,m:u32,ready:&[&CompiledBackend])->Result<Vec<u32>>{if ready.is_empty(){bail!("no ready backends")};let mut virtuals=Vec::new();for b in ready{for r in 0..b.weight{virtuals.push((b.id,r));}}let n=virtuals.len();let mut offset=Vec::with_capacity(n);let mut skip=Vec::with_capacity(n);for (id,r) in &virtuals{let mut seed=Vec::new();seed.extend(sid.to_ne_bytes());seed.extend(id.to_ne_bytes());seed.extend(r.to_ne_bytes());let h1=hash64(0xcbf29ce484222325,&seed);let h2=hash64(0x84222325cbf29ce4,&seed);offset.push((h1%(m as u64))as u32);skip.push(((h2%((m-1)as u64))+1)as u32);}let mut next=vec![0u32;n];let mut entry=vec![u32::MAX;m as usize];let mut filled=0usize;while filled<m as usize{for i in 0..n{let mut c=(offset[i]+next[i]*skip[i])%m;while entry[c as usize]!=u32::MAX{next[i]+=1;c=(offset[i]+next[i]*skip[i])%m;}entry[c as usize]=virtuals[i].0;next[i]+=1;filled+=1;if filled==m as usize{break}}}Ok(entry)}
fn parse_mac(s:&str)->Result<[u8;6]>{let p:Vec<&str>=s.split(':').collect();if p.len()!=6{bail!("invalid MAC {s}")}let mut a=[0u8;6];for(i,x)in p.iter().enumerate(){a[i]=u8::from_str_radix(x,16).with_context(||format!("invalid MAC {s}"))?}if a[0]&1!=0{bail!("backend MAC must be unicast: {s}")}Ok(a)}
fn ifindex(name:&str)->Result<u32>{let s=fs::read_to_string(Path::new("/sys/class/net").join(name).join("ifindex")).with_context(||format!("reading ifindex for {name}"))?;Ok(s.trim().parse()?)}
fn helper(var:&str,default:&str)->String{env::var(var).unwrap_or_else(|_|default.into())}
fn control_path(root:&Path,id:Uuid)->PathBuf{root.join(format!("{id}.json"))}
fn write_json_atomic(path:&Path,v:&impl Serialize)->Result<()>{let tmp=path.with_extension(format!("json.tmp.{}",std::process::id()));fs::write(&tmp,serde_json::to_vec_pretty(v)?)?;fs::rename(tmp,path)?;Ok(())}
fn ethtool_driver(iface:&str)->(Option<String>,Option<String>){let o=Command::new("ethtool").args(["-i",iface]).output();if let Ok(o)=o{let s=String::from_utf8_lossy(&o.stdout);let mut d=None;let mut b=None;for l in s.lines(){if let Some(v)=l.strip_prefix("driver: "){d=Some(v.trim().into())}if let Some(v)=l.strip_prefix("bus-info: "){b=Some(v.trim().into())}}(d,b)}else{(None,None)}}
fn existing_xdp(iface:&str)->Option<String>{let o=Command::new("ip").args(["-details","link","show","dev",iface]).output().ok()?;let s=String::from_utf8_lossy(&o.stdout);if s.contains("prog/xdp")||s.contains("xdp id "){Some(s.lines().find(|l|l.contains("xdp")).unwrap_or("xdp owner present").trim().to_string())}else{None}}

#[cfg(test)]mod tests{use super::*;#[test]fn mac_validation(){assert!(parse_mac("02:00:00:00:00:01").is_ok());assert!(parse_mac("01:00:00:00:00:01").is_err())}#[test]fn maglev_is_deterministic(){let b=CompiledBackend{id:7,interface:"x".into(),ifindex:1,mac:"02:00:00:00:00:01".into(),weight:1,state:QuicBackendState::Ready,address:None};let a=maglev_table(1,251,&[&b]).unwrap();assert!(a.iter().all(|x|*x==7));assert_eq!(a,maglev_table(1,251,&[&b]).unwrap())}#[test]fn service_key_is_abi_sized(){let s=CompiledService{name:"x".into(),service_id:1,vip:"192.0.2.1".parse().unwrap(),port:443,short_dcid_len:8,quic_only:true,sample_rate:1,maglev_table_size:251,backends:vec![],maglev:vec![]};assert_eq!(service_key(1,&s).len(),24);assert_eq!(service_value(&s).len(),20)}}
