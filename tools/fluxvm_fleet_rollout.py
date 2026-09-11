#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""FluxVM Sentinel Set 15E fleet rollout and canary controller.

Conservative multi-node wrapper around Set 14E's node-local upgrade manager.
No local shell execution, strict host-key checking by default, fsync'd journals, immutable
plan hash, bounded parallelism, canary gates, cohort compatibility, and
reverse-order rollback for the current wave.
"""
from __future__ import annotations
import argparse, base64, concurrent.futures, dataclasses, datetime as dt, fcntl, hashlib, json, os, pathlib, re, shlex, subprocess, sys, tempfile, time
from typing import Any, Optional

SCHEMA_VERSION=1
VERSION="15e.1"
DEFAULT_STATE_DIR="/var/lib/fluxvm/sentinel-fleet-rollouts"
NAME_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

class FleetError(RuntimeError): pass

@dataclasses.dataclass
class Result:
    rc:int; stdout:str; stderr:str

class Runner:
    def run(self, argv:list[str], *, check=True, timeout:Optional[float]=None, input_text:Optional[str]=None)->Result:
        if not argv or any((not isinstance(x,str) or '\x00' in x) for x in argv): raise FleetError("invalid argv")
        cp=subprocess.run(argv,input=input_text,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        r=Result(cp.returncode,cp.stdout,cp.stderr)
        if check and r.rc: raise FleetError(f"command failed rc={r.rc}: {argv!r}: {r.stderr.strip() or r.stdout.strip()}")
        return r
RUNNER=Runner()

def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
def canonical(o): return json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(o): return hashlib.sha256(canonical(o)).hexdigest()
def atomic_json(path:pathlib.Path,obj:Any,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"w") as f: json.dump(obj,f,indent=2,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path); d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def load(path):
    with open(path,encoding="utf-8") as f:return json.load(f)

def validate(plan):
    if not isinstance(plan,dict) or plan.get("schema_version")!=SCHEMA_VERSION: raise FleetError("unsupported schema_version")
    rid=str(plan.get("rollout_id",""));
    if not NAME_RE.fullmatch(rid): raise FleetError("invalid rollout_id")
    nodes=plan.get("nodes");
    if not isinstance(nodes,list) or not nodes: raise FleetError("nodes must be non-empty")
    seen=set()
    for n in nodes:
        if not isinstance(n,dict): raise FleetError("node must be object")
        name=str(n.get("name","")); host=str(n.get("host",""))
        if not NAME_RE.fullmatch(name) or not host or '\x00' in host: raise FleetError("invalid node")
        if name in seen: raise FleetError(f"duplicate node {name}")
        seen.add(name)
        if not isinstance(n.get("labels",{}),dict): raise FleetError("labels must be object")
    s=plan.get("strategy",{})
    if not isinstance(s,dict): raise FleetError("strategy must be object")
    for k,d in (("canary",1),("wave_size",2),("max_parallel",2),("max_failures",0)):
        v=int(s.get(k,d));
        if v < (0 if k=="max_failures" else 1): raise FleetError(f"invalid {k}")
    if not isinstance(plan.get("node_upgrade_plan"),str) or not plan["node_upgrade_plan"]: raise FleetError("node_upgrade_plan required")
    return plan

def ssh_base(node,plan):
    args=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=10"]
    if not plan.get("allow_insecure_host_key",False): args += ["-o","StrictHostKeyChecking=yes"]
    if node.get("port"): args += ["-p",str(int(node["port"]))]
    if node.get("identity_file"): args += ["-i",str(node["identity_file"])]
    target=(str(node.get("user"))+"@" if node.get("user") else "")+str(node["host"])
    return args+[target]

def remote(node,plan,argv,*,check=True,timeout=120,input_text=None):
    # argv is base64(JSON) in an env var set on the remote command line (not
    # SSH env forwarding, which needs server-side AcceptEnv and is commonly
    # disabled) -- this keeps stdin entirely free for `input_text` to reach
    # the actual remote process, e.g. push_upgrade_plan's file transfer.
    # Passing argv over stdin instead (as originally written) would work for
    # callers with no input_text, but silently discards any input_text a
    # caller does pass: the wrapper's own sys.stdin.read() drains the pipe
    # to EOF decoding argv, leaving nothing for subprocess.run(a)'s child to
    # read from the same (now-exhausted) stdin.
    payload=base64.b64encode(json.dumps(argv).encode()).decode()
    py="import base64,json,os,subprocess,sys; a=json.loads(base64.b64decode(os.environ['FLEET_ARGV'])); r=subprocess.run(a); sys.exit(r.returncode)"
    remote_cmd="FLEET_ARGV="+shlex.quote(payload)+" python3 -c "+shlex.quote(py)
    return RUNNER.run(ssh_base(node,plan)+[remote_cmd],check=check,timeout=timeout,input_text=input_text)

def inventory_node(node,plan):
    cmd=["python3","-c",
      "import json,platform,os,shutil; print(json.dumps({'kernel':platform.release(),'arch':platform.machine(),'bpftool':bool(shutil.which('bpftool')),'fluxvm_upgrade':bool(shutil.which('fluxvm-upgrade')),'sched_ext':os.path.exists('/sys/kernel/sched_ext'),'bpf':os.path.exists('/sys/fs/bpf')}))"]
    r=remote(node,plan,cmd,timeout=30)
    data=json.loads(r.stdout.strip() or "{}")
    data.update(name=node["name"],host=node["host"],labels=node.get("labels",{}))
    return data

def cohort_key(inv):
    # Kernel minor + arch + sched_ext are the compatibility boundaries that matter most for Sentinel artifacts.
    parts=inv.get("kernel","").split("."); km=".".join(parts[:2]) if len(parts)>=2 else inv.get("kernel","")
    return f"{inv.get('arch')}|{km}|scx={int(bool(inv.get('sched_ext')))}"

def txdir(plan,state_dir): return pathlib.Path(state_dir)/plan["rollout_id"]
def journal_path(plan,state_dir): return txdir(plan,state_dir)/"journal.json"
def lock_path(plan,state_dir): return txdir(plan,state_dir)/"lock"

def fresh_journal(plan):
    return {"schema_version":1,"rollout_id":plan["rollout_id"],"plan_sha256":sha(plan),"status":"new","created_at":now(),"updated_at":now(),"canary_approved":False,"inventory":{},"waves":[],"nodes":{n['name']:{"status":"pending","attempts":0} for n in plan['nodes']}}

def save(plan,state_dir,j): j["updated_at"]=now(); atomic_json(journal_path(plan,state_dir),j)
def read_journal(plan,state_dir):
    p=journal_path(plan,state_dir)
    if not p.exists(): return fresh_journal(plan)
    j=load(p)
    if j.get("plan_sha256")!=sha(plan): raise FleetError("plan hash changed after rollout began")
    return j

def inventory(plan,j,state_dir):
    maxp=int(plan.get("strategy",{}).get("max_parallel",2))
    def one(n): return n["name"],inventory_node(n,plan)
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxp) as ex:
        for name,data in ex.map(one,plan["nodes"]): j["inventory"][name]=data; save(plan,state_dir,j)
    missing=[x for x in j["inventory"].values() if not x.get("fluxvm_upgrade")]
    if missing: raise FleetError("Set 14E fluxvm-upgrade missing on: "+", ".join(x["name"] for x in missing))
    return j

def build_waves(plan,j):
    nodes=plan["nodes"][:]; strat=plan.get("strategy",{}); can=int(strat.get("canary",1)); size=int(strat.get("wave_size",2))
    # Keep compatibility cohorts together for predictable behavior, but canary selects across first available cohort.
    by={}
    for n in nodes: by.setdefault(cohort_key(j["inventory"][n["name"]]),[]).append(n)
    waves=[]
    first=True
    for k in sorted(by):
        cohort=by[k]
        if first and cohort:
            take=min(can,len(cohort)); waves.append([n["name"] for n in cohort[:take]]); cohort=cohort[take:]; first=False
        for i in range(0,len(cohort),size): waves.append([n["name"] for n in cohort[i:i+size]])
    j["waves"]=[{"index":i,"nodes":w,"cohort":cohort_key(j["inventory"][w[0]]) if w else None,"status":"pending"} for i,w in enumerate(waves)]
    return j

def node_by_name(plan,name): return next(n for n in plan["nodes"] if n["name"]==name)
def plan_remote_path(plan): return str(plan.get("remote_upgrade_plan","/var/lib/fluxvm/sentinel-upgrades/fleet-plan.json"))

def push_upgrade_plan(node,plan):
    data=pathlib.Path(plan["node_upgrade_plan"]).read_text(encoding="utf-8")
    dest=plan_remote_path(plan)
    script=["python3","-c","import os,sys; p=sys.argv[1]; os.makedirs(os.path.dirname(p),exist_ok=True); open(p,'w').write(sys.stdin.read()); os.chmod(p,0o600)",dest]
    return remote(node,plan,script,input_text=data,timeout=30)

def upgrade_node(node,plan):
    push_upgrade_plan(node,plan)
    binary=str(plan.get("upgrade_binary","fluxvm-upgrade")); cmd=[binary,"run",plan_remote_path(plan)]
    if plan.get("sudo",True): cmd=["sudo","-n"]+cmd
    r=remote(node,plan,cmd,check=False,timeout=float(plan.get("node_timeout_seconds",900)))
    return r

def rollback_node(node,plan):
    binary=str(plan.get("upgrade_binary","fluxvm-upgrade")); cmd=[binary,"rollback",plan_remote_path(plan)]
    if plan.get("sudo",True): cmd=["sudo","-n"]+cmd
    return remote(node,plan,cmd,check=False,timeout=float(plan.get("node_timeout_seconds",900)))

def postcheck_node(node,plan):
    checks=plan.get("post_checks",[])
    for c in checks:
        if not isinstance(c,list) or not c: raise FleetError("post_checks entries must be argv arrays")
        r=remote(node,plan,c,check=False,timeout=60)
        if r.rc: return False,f"post-check failed: {c!r}: {r.stderr.strip() or r.stdout.strip()}"
    return True,"ok"

def wave_run(plan,j,state_dir,wave):
    maxp=min(int(plan.get("strategy",{}).get("max_parallel",2)),len(wave["nodes"]) or 1)
    def one(name):
        n=node_by_name(plan,name); r=upgrade_node(n,plan)
        if r.rc:return name,False,(r.stderr or r.stdout)[-4000:]
        ok,msg=postcheck_node(n,plan); return name,ok,msg
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxp) as ex:
        futs={ex.submit(one,n):n for n in wave["nodes"]}
        for f in concurrent.futures.as_completed(futs):
            name,ok,msg=f.result(); results.append((name,ok,msg)); rec=j["nodes"][name]; rec["attempts"]+=1; rec["status"]="healthy" if ok else "failed"; rec["message"]=msg; save(plan,state_dir,j)
    return results

def rollback_wave(plan,j,state_dir,wave):
    ok=True
    for name in reversed(wave["nodes"]):
        if j["nodes"][name]["status"] not in ("healthy","failed"): continue
        r=rollback_node(node_by_name(plan,name),plan); j["nodes"][name]["rollback_rc"]=r.rc; j["nodes"][name]["status"]="rolled-back" if r.rc==0 else "manual-intervention"; ok = ok and (r.rc==0); save(plan,state_dir,j)
    return ok

def run_rollout(plan,state_dir):
    d=txdir(plan,state_dir); d.mkdir(parents=True,exist_ok=True)
    with open(lock_path(plan,state_dir),"a+") as lf:
        try:
            fcntl.flock(lf,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise FleetError("rollout is already locked") from e
        j=read_journal(plan,state_dir)
        try:
            if not j["inventory"]: j["status"]="inventory"; save(plan,state_dir,j); inventory(plan,j,state_dir)
            if not j["waves"]: build_waves(plan,j); save(plan,state_dir,j)
            maxfail=int(plan.get("strategy",{}).get("max_failures",0)); auto_rb=bool(plan.get("strategy",{}).get("rollback_failed_wave",True))
            for wave in j["waves"]:
                if wave["status"]=="complete": continue
                # Re-checked on every call (not just the one where the canary
                # wave finished): without this, `continue` on an
                # already-complete wave 0 would skip straight past this gate
                # on a later `run`/`resume` call, silently proceeding into
                # wave 1+ even when the operator never called `approve`.
                if wave["index"] > 0 and plan.get("strategy",{}).get("require_canary_approval",False) and not j.get("canary_approved",False):
                    j["status"]="awaiting-canary-approval"; save(plan,state_dir,j); write_evidence(plan,j,state_dir); return j
                wave["status"]="running"; j["status"]="running"; save(plan,state_dir,j)
                results=wave_run(plan,j,state_dir,wave); fails=sum(1 for _,ok,_ in results if not ok)
                if fails>maxfail:
                    wave["status"]="failed"; j["status"]="paused"; save(plan,state_dir,j)
                    if auto_rb:
                        rb_ok=rollback_wave(plan,j,state_dir,wave)
                        wave["status"]="rolled-back" if rb_ok else "manual-intervention"
                        j["status"]="paused" if rb_ok else "manual-intervention"
                        save(plan,state_dir,j)
                    raise FleetError(f"wave {wave['index']} exceeded failure budget: {fails}>{maxfail}")
                wave["status"]="complete"; save(plan,state_dir,j)
                dwell=float(plan.get("strategy",{}).get("dwell_seconds",0));
                if dwell>0: time.sleep(dwell)
            j["status"]="complete"; save(plan,state_dir,j); write_evidence(plan,j,state_dir); return j
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)

def write_evidence(plan,j,state_dir):
    d=txdir(plan,state_dir)/"evidence"; d.mkdir(parents=True,exist_ok=True)
    atomic_json(d/"rollout.json",j,0o640); atomic_json(d/"plan.json",plan,0o640)
    items=[]
    for p in sorted(d.glob("*.json")): items.append({"file":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()})
    atomic_json(d/"manifest.json",{"generated_at":now(),"files":items},0o640)

def cmd_probe(plan):
    rows=[]
    for n in plan["nodes"]:
        try: rows.append(inventory_node(n,plan))
        except Exception as e: rows.append({"name":n["name"],"host":n["host"],"error":str(e)})
    print(json.dumps(rows,indent=2,sort_keys=True))

def main():
    ap=argparse.ArgumentParser(prog="fluxvm-fleet",description="FluxVM Sentinel Set 15E fleet rollout controller")
    ap.add_argument("--state-dir",default=DEFAULT_STATE_DIR)
    sub=ap.add_subparsers(dest="cmd",required=True)
    for c in ("validate","probe","plan","run","resume","status","evidence","approve"): sub.add_parser(c).add_argument("plan")
    a=ap.parse_args(); pth=pathlib.Path(a.plan); plan=validate(load(pth))
    if a.cmd=="validate": print(json.dumps({"ok":True,"plan_sha256":sha(plan),"nodes":len(plan["nodes"])},indent=2)); return
    if a.cmd=="probe": cmd_probe(plan); return
    if a.cmd=="plan":
        j=fresh_journal(plan); inventory(plan,j,a.state_dir); build_waves(plan,j); print(json.dumps({"inventory":j["inventory"],"waves":j["waves"]},indent=2,sort_keys=True)); return
    if a.cmd in ("run","resume"): print(json.dumps(run_rollout(plan,a.state_dir),indent=2,sort_keys=True)); return
    j=read_journal(plan,a.state_dir)
    if a.cmd=="approve":
        if not j.get("waves") or j["waves"][0].get("status")!="complete": raise FleetError("canary wave is not complete")
        j["canary_approved"]=True; j["status"]="paused"; save(plan,a.state_dir,j); print(json.dumps({"approved":True,"rollout_id":plan["rollout_id"]},indent=2)); return
    if a.cmd=="status": print(json.dumps(j,indent=2,sort_keys=True)); return
    if a.cmd=="evidence": write_evidence(plan,j,a.state_dir); print(str(txdir(plan,a.state_dir)/"evidence")); return

if __name__=="__main__":
    try: main()
    except FleetError as e: print(f"fluxvm-fleet: {e}",file=sys.stderr); raise SystemExit(1)
