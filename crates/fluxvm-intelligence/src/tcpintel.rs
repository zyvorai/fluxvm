// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, fs, net::{Ipv4Addr,Ipv6Addr}, path::{Path,PathBuf}, process::Command};
use uuid::Uuid;
use crate::vm_key;

pub const DEFAULT_TCP_PIN_ROOT:&str="/sys/fs/bpf/fluxvm/tcp-intel";
pub const DEFAULT_TCP_STATE_ROOT:&str="/var/lib/fluxvm/tcp-intel";
const DEFAULT_OBJECT:&str="/usr/lib/fluxvm/bpf/fluxvm_tcp_intel.bpf.o";

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct TcpAttachState{pub schema_version:u32,pub vm_id:Uuid,pub vm_key:u64,pub interface:String,pub attach_mode:String,pub sample_rate:u32}
#[derive(Debug,Clone,Default,Serialize,Deserialize,PartialEq,Eq)]
pub struct TcpCounters{pub syn:u64,pub established:u64,pub retransmits:u64,pub resets:u64,pub fins:u64,pub flow_alloc_misses:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct TcpLatencyBucket{pub kind:String,pub bucket:u32,pub le_ns:Option<u64>,pub count:u64,pub total_ns:u64,pub max_ns:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct TcpFlowRecord{pub family:u8,pub guest:String,pub remote:String,pub guest_port:u16,pub remote_port:u16,pub established:bool,pub handshake_ns:Option<u64>,pub retransmits:u32,pub syn_retransmits:u32,pub rtt_samples:u32,pub rtt_avg_ns:Option<u64>,pub rtt_min_ns:Option<u64>,pub rtt_max_ns:Option<u64>,pub resets:u32,pub fins:u32,pub last_seen_ns:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
pub struct TcpIntelSnapshot{pub schema_version:u32,pub vm_id:Uuid,pub interface:String,pub attach_mode:String,pub counters:TcpCounters,pub handshake_p50_ns:Option<u64>,pub handshake_p95_ns:Option<u64>,pub rtt_p50_ns:Option<u64>,pub rtt_p95_ns:Option<u64>,pub latency:Vec<TcpLatencyBucket>,pub flows:Vec<TcpFlowRecord>,pub notes:Vec<String>}

pub fn attach(id:Uuid,interface:&str,sample_rate:u32,pin_root:&Path,state_root:&Path)->Result<TcpAttachState>{
    if sample_rate>1_000_000{bail!("sample_rate must be <= 1000000");}let _=read_ifindex(interface)?;let pin=vm_pin_dir(pin_root,id);let state_path=state_path(state_root,id);
    if state_path.exists()||pin.join("maps/fluxvm_tcp_cfg").exists(){bail!("TCP Intelligence already exists for {id}; detach before re-attaching");}
    let helper=helper();let obj=object();let pin_s=pin.display().to_string();let key=vm_key(id).to_string();let sample=sample_rate.to_string();
    let out=Command::new(&helper).args(["attach",interface,&obj,&pin_s,&key,&sample]).output().with_context(||format!("running {helper}"))?;
    if !out.status.success(){bail!("TCP loader failed: {}",String::from_utf8_lossy(&out.stderr).trim());}let v:Value=serde_json::from_slice(&out.stdout)?;let mode=v.get("mode").and_then(Value::as_str).unwrap_or("unknown").to_string();
    let state=TcpAttachState{schema_version:1,vm_id:id,vm_key:vm_key(id),interface:interface.into(),attach_mode:mode,sample_rate};write_state(&state,state_root)?;Ok(state)
}

pub fn detach(id: Uuid, pin_root: &Path, state_root: &Path) -> Result<()> {
    let state = read_state(id, state_root)?;
    let helper = helper();
    let pin = vm_pin_dir(pin_root, id);
    let pin_s = pin.display().to_string();
    let vm_key_s = state.vm_key.to_string();
    let out = Command::new(&helper)
        .args(["detach", &state.interface, &pin_s, &vm_key_s])
        .output()?;
    if !out.status.success() {
        bail!("TCP detach failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    if pin.exists() {
        fs::remove_dir_all(&pin)?;
    }
    let p = state_path(state_root, id);
    if p.exists() {
        fs::remove_file(p)?;
    }
    Ok(())
}
pub fn read_state(id:Uuid,root:&Path)->Result<TcpAttachState>{let p=state_path(root,id);serde_json::from_slice(&fs::read(&p).with_context(||format!("reading {}",p.display()))?).context("decoding TCP intelligence state")}

pub fn snapshot(id:Uuid,pin_root:&Path,state_root:&Path,limit:usize)->Result<TcpIntelSnapshot>{let state=read_state(id,state_root)?;let maps=vm_pin_dir(pin_root,id).join("maps");let counters=read_counts(&maps.join("fluxvm_tcp_counts"))?;let mut latency=read_hist(&maps.join("fluxvm_tcp_hist"))?;latency.sort_by(|a,b|a.kind.cmp(&b.kind).then_with(||a.bucket.cmp(&b.bucket)));let mut flows=read_flows(&maps.join("fluxvm_tcp_flows"))?;flows.sort_by(|a,b|b.last_seen_ns.cmp(&a.last_seen_ns));flows.truncate(limit.clamp(1,4096));let hp50=quantile(&latency,"handshake",0.50);let hp95=quantile(&latency,"handshake",0.95);let rp50=quantile(&latency,"rtt-estimate",0.50);let rp95=quantile(&latency,"rtt-estimate",0.95);Ok(TcpIntelSnapshot{schema_version:1,vm_id:id,interface:state.interface,attach_mode:state.attach_mode,counters,handshake_p50_ns:hp50,handshake_p95_ns:hp95,rtt_p50_ns:rp50,rtt_p95_ns:rp95,latency,flows,notes:vec!["handshake response latency is measured from the observed initiating SYN to the opposite-direction SYN/ACK for either guest- or remote-initiated connections".into(),"RTT and retransmission values are passive packet-level estimates, not the guest kernel TCP srtt/retransmission counters".into()]})}

pub fn stream_events(id:Uuid,pin_root:&Path,seconds:u64,limit:usize)->Result<()> {let map=vm_pin_dir(pin_root,id).join("maps/fluxvm_tcp_events");if !map.exists(){bail!("TCP event map missing: {}",map.display());}let h=env::var("FLUXVM_TCP_EVENTS").unwrap_or_else(|_|"/usr/libexec/fluxvm/fluxvm-tcp-events".into());let s=Command::new(&h).arg(map).arg(seconds.clamp(1,3600).to_string()).arg(limit.clamp(1,10000).to_string()).status()?;if !s.success(){bail!("TCP event reader exited with {s}");}Ok(())}

pub fn prometheus(s:&TcpIntelSnapshot)->String{let id=s.vm_id;let mut out=String::new();for (name,v) in [("syn",s.counters.syn),("established",s.counters.established),("retransmit",s.counters.retransmits),("rst",s.counters.resets),("fin",s.counters.fins),("flow_alloc_miss",s.counters.flow_alloc_misses)]{out.push_str(&format!("fluxvm_tcp_events_total{{vm_id=\"{id}\",event=\"{name}\"}} {v}\n"));}for (name,v) in [("handshake_p50",s.handshake_p50_ns),("handshake_p95",s.handshake_p95_ns),("rtt_estimate_p50",s.rtt_p50_ns),("rtt_estimate_p95",s.rtt_p95_ns)]{if let Some(v)=v{out.push_str(&format!("fluxvm_tcp_latency_ns{{vm_id=\"{id}\",quantile=\"{name}\"}} {v}\n"));}}out}

fn read_counts(map:&Path)->Result<TcpCounters>{
    let mut c=TcpCounters::default();
    for row in rows(map)? {
        let kind=if let Some(Value::Object(k))=row.get("key") {
            ju(k.get("kind")).unwrap_or(0) as u32
        } else {
            let Some(k)=hex(row.get("key")) else { continue; };
            if k.len()<4 { continue; }
            u32::from_ne_bytes(k[0..4].try_into().unwrap())
        };
        let value=if let Some(v)=ju(row.get("value")) { v } else {
            let raw=hex(row.get("value")).unwrap_or_default();
            if raw.len()<8 { continue; }
            u64::from_ne_bytes(raw[0..8].try_into().unwrap())
        };
        match kind {1=>c.syn=value,2=>c.established=value,3=>c.retransmits=value,4=>c.resets=value,5=>c.fins=value,6=>c.flow_alloc_misses=value,_=>{}}
    }
    Ok(c)
}

fn read_hist(map:&Path)->Result<Vec<TcpLatencyBucket>>{
    let mut out=Vec::new();
    for row in rows(map)? {
        let (kind,bucket)=if let Some(Value::Object(k))=row.get("key") {
            (ju(k.get("kind")).unwrap_or(0) as u32,ju(k.get("bucket")).unwrap_or(0) as u32)
        } else {
            let Some(k)=hex(row.get("key")) else { continue; };
            if k.len()<8 { continue; }
            (u32::from_ne_bytes(k[0..4].try_into().unwrap()),u32::from_ne_bytes(k[4..8].try_into().unwrap()))
        };
        let (count,total,max)=if let Some(Value::Object(v))=row.get("value") {
            (ju(v.get("count")).unwrap_or(0),ju(v.get("total_ns")).unwrap_or(0),ju(v.get("max_ns")).unwrap_or(0))
        } else {
            let v=hex(row.get("value")).unwrap_or_default();
            if v.len()<24 { continue; }
            (u64::from_ne_bytes(v[0..8].try_into().unwrap()),u64::from_ne_bytes(v[8..16].try_into().unwrap()),u64::from_ne_bytes(v[16..24].try_into().unwrap()))
        };
        out.push(TcpLatencyBucket{kind:if kind==1{"handshake"}else{"rtt-estimate"}.into(),bucket,le_ns:bound(bucket),count,total_ns:total,max_ns:max});
    }
    Ok(out)
}

fn read_flows(map: &Path) -> Result<Vec<TcpFlowRecord>> {
    let mut out = Vec::new();
    for row in rows(map)? {
        if let (Some(Value::Object(key)), Some(Value::Object(value))) =
            (row.get("key"), row.get("value"))
        {
            let family = ju(key.get("family")).unwrap_or(0) as u8;
            let Some(guest_bytes) = byte_array(key.get("guest"), 16) else { continue; };
            let Some(remote_bytes) = byte_array(key.get("remote"), 16) else { continue; };
            if family != 4 && family != 6 {
                continue;
            }
            let samples = ju(value.get("rtt_samples")).unwrap_or(0) as u32;
            let total = ju(value.get("rtt_total_ns")).unwrap_or(0);
            let min = ju(value.get("rtt_min_ns")).unwrap_or(0);
            let max = ju(value.get("rtt_max_ns")).unwrap_or(0);
            let handshake = ju(value.get("handshake_ns")).unwrap_or(0);
            out.push(TcpFlowRecord {
                family,
                guest: ip(family, &guest_bytes),
                remote: ip(family, &remote_bytes),
                guest_port: ju(key.get("guest_port")).unwrap_or(0) as u16,
                remote_port: ju(key.get("remote_port")).unwrap_or(0) as u16,
                established: ju(value.get("established")).unwrap_or(0) != 0,
                handshake_ns: (handshake > 0).then_some(handshake),
                retransmits: ju(value.get("retransmits")).unwrap_or(0) as u32,
                syn_retransmits: ju(value.get("syn_retransmits")).unwrap_or(0) as u32,
                rtt_samples: samples,
                rtt_avg_ns: (samples > 0).then_some(total / samples as u64),
                rtt_min_ns: (samples > 0 && min != u64::MAX).then_some(min),
                rtt_max_ns: (samples > 0).then_some(max),
                resets: ju(value.get("rst_count")).unwrap_or(0) as u32,
                fins: ju(value.get("fin_count")).unwrap_or(0) as u32,
                last_seen_ns: ju(value.get("last_seen_ns")).unwrap_or(0),
            });
            continue;
        }

        let Some(key) = hex(row.get("key")) else { continue; };
        let Some(value) = hex(row.get("value")) else { continue; };
        if key.len() < 40 || value.len() < 120 {
            continue;
        }
        let family = key[0];
        if family != 4 && family != 6 {
            continue;
        }
        let guest = ip(family, &key[4..20]);
        let remote = ip(family, &key[20..36]);
        let guest_port = u16::from_ne_bytes(key[36..38].try_into().unwrap());
        let remote_port = u16::from_ne_bytes(key[38..40].try_into().unwrap());
        let u64at = |offset: usize| {
            u64::from_ne_bytes(value[offset..offset + 8].try_into().unwrap())
        };
        let u32at = |offset: usize| {
            u32::from_ne_bytes(value[offset..offset + 4].try_into().unwrap())
        };
        let handshake = u64at(8);
        let total = u64at(32);
        let max = u64at(40);
        let min = u64at(48);
        let samples = u32at(96);
        out.push(TcpFlowRecord {
            family,
            guest,
            remote,
            guest_port,
            remote_port,
            established: u32at(108) != 0,
            handshake_ns: (handshake > 0).then_some(handshake),
            retransmits: u32at(88),
            syn_retransmits: u32at(92),
            rtt_samples: samples,
            rtt_avg_ns: (samples > 0).then_some(total / samples as u64),
            rtt_min_ns: (samples > 0 && min != u64::MAX).then_some(min),
            rtt_max_ns: (samples > 0).then_some(max),
            resets: u32at(100),
            fins: u32at(104),
            last_seen_ns: u64at(56),
        });
    }
    Ok(out)
}

fn quantile(v:&[TcpLatencyBucket],kind:&str,q:f64)->Option<u64>{let rows:Vec<&TcpLatencyBucket>=v.iter().filter(|b|b.kind==kind).collect();let total:u64=rows.iter().map(|b|b.count).sum();if total==0{return None}let target=((total as f64*q).ceil() as u64).max(1);let mut seen=0;for b in rows{seen+=b.count;if seen>=target{return b.le_ns.or(Some(b.max_ns));}}None}
fn bound(bucket:u32)->Option<u64>{if bucket>=24{None}else{Some(1000u64.saturating_mul(1u64<<bucket))}}
fn ip(family:u8,b:&[u8])->String{if family==4{Ipv4Addr::new(b[0],b[1],b[2],b[3]).to_string()}else{let mut a=[0u8;16];a.copy_from_slice(&b[..16]);Ipv6Addr::from(a).to_string()}}
fn rows(map:&Path)->Result<Vec<Value>>{let out=Command::new("bpftool").args(["-j","map","dump","pinned"]).arg(map).output()?;if !out.status.success(){bail!("bpftool map dump {} failed: {}",map.display(),String::from_utf8_lossy(&out.stderr).trim());}serde_json::from_slice(&out.stdout).context("decoding bpftool JSON")}
fn hex(v:Option<&Value>)->Option<Vec<u8>>{match v?{Value::Array(a)=>a.iter().map(|x|match x{Value::Number(n)=>n.as_u64().filter(|n|*n<=255).map(|n|n as u8),Value::String(s)=>u8::from_str_radix(s.trim_start_matches("0x"),16).ok(),_=>None}).collect(),Value::Object(o)=>o.get("bytes").and_then(|x|hex(Some(x))),_=>None}}
fn byte_array(v: Option<&Value>, expected: usize) -> Option<Vec<u8>> {
    let bytes = hex(v)?;
    (bytes.len() >= expected).then(|| bytes[..expected].to_vec())
}
fn ju(v:Option<&Value>)->Option<u64>{match v?{Value::Number(n)=>n.as_u64(),Value::String(s)=>s.parse().ok().or_else(||u64::from_str_radix(s.trim_start_matches("0x"),16).ok()),Value::Object(o)=>o.values().find_map(|x|ju(Some(x))),_=>None}}
fn helper()->String{env::var("FLUXVM_TCP_LOADER").unwrap_or_else(|_|"/usr/libexec/fluxvm/fluxvm-tcp-loader".into())}fn object()->String{env::var("FLUXVM_TCP_OBJECT").unwrap_or_else(|_|DEFAULT_OBJECT.into())}fn vm_pin_dir(root:&Path,id:Uuid)->PathBuf{root.join(id.to_string())}fn state_path(root:&Path,id:Uuid)->PathBuf{root.join(format!("{id}.json"))}fn read_ifindex(iface:&str)->Result<u32>{fs::read_to_string(Path::new("/sys/class/net").join(iface).join("ifindex"))?.trim().parse().context("parsing ifindex")}
fn write_state(s:&TcpAttachState,root:&Path)->Result<()> {fs::create_dir_all(root)?;let p=state_path(root,s.vm_id);let tmp=root.join(format!(".{}.{}.tmp",s.vm_id,std::process::id()));fs::write(&tmp,serde_json::to_vec_pretty(s)?)?;fs::rename(tmp,p)?;Ok(())}

#[cfg(test)] mod tests{use super::*;#[test]fn histogram_boundaries(){assert_eq!(bound(0),Some(1000));assert_eq!(bound(10),Some(1_024_000));assert_eq!(bound(24),None);}#[test]fn vm_key_is_stable_for_state(){let id=Uuid::nil();assert_ne!(vm_key(id),0);}}
