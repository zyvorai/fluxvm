#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""FluxVM Sentinel Set 16E continuous fleet drift and SLO guard.

Read-mostly by default. It inventories nodes over strict SSH, compares release/build/file/BPF
fingerprints, evaluates health and numeric SLO checks with hysteresis, and writes fsync'd,
tamper-evident evidence. Optional action commands are explicit argv arrays from the policy;
there is no synthesized shell command and no implicit quarantine/remediation.
"""
from __future__ import annotations
import argparse, concurrent.futures, dataclasses, datetime as dt, fcntl, hashlib, json, os, pathlib, re, shlex, shutil, subprocess, tempfile
from typing import Any, Optional

SCHEMA_VERSION=1
VERSION="16e.1"
DEFAULT_STATE_DIR="/var/lib/fluxvm/sentinel-fleet-guard"
NAME_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
OPS={"lt":lambda a,b:a<b,"le":lambda a,b:a<=b,"gt":lambda a,b:a>b,"ge":lambda a,b:a>=b,"eq":lambda a,b:a==b}

class GuardError(RuntimeError): pass
@dataclasses.dataclass
class Result: rc:int; stdout:str; stderr:str
class Runner:
    def run(self,argv:list[str],*,check=True,timeout:Optional[float]=None,input_text:Optional[str]=None)->Result:
        if not argv or any(not isinstance(x,str) or "\x00" in x for x in argv): raise GuardError("invalid argv")
        cp=subprocess.run(argv,input=input_text,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        r=Result(cp.returncode,cp.stdout,cp.stderr)
        if check and r.rc: raise GuardError(f"command failed rc={r.rc}: {argv!r}: {(r.stderr or r.stdout).strip()}")
        return r
RUNNER=Runner()

def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
def canonical(o): return json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(o): return hashlib.sha256(canonical(o)).hexdigest()
def load(p):
    with open(p,encoding="utf-8") as f:return json.load(f)
def atomic_json(path:pathlib.Path,obj:Any,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"w") as f: json.dump(obj,f,indent=2,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path); d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(d); os.close(d)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def validate(plan):
    if not isinstance(plan,dict) or plan.get("schema_version")!=SCHEMA_VERSION: raise GuardError("unsupported schema_version")
    gid=str(plan.get("guard_id",""));
    if not NAME_RE.fullmatch(gid): raise GuardError("invalid guard_id")
    desired=plan.get("desired",{})
    if not isinstance(desired,dict) or not str(desired.get("release_id","")): raise GuardError("desired.release_id required")
    nodes=plan.get("nodes")
    if not isinstance(nodes,list) or not nodes: raise GuardError("nodes must be non-empty")
    seen=set()
    for n in nodes:
        if not isinstance(n,dict): raise GuardError("node must be object")
        name=str(n.get("name","")); host=str(n.get("host",""))
        if not NAME_RE.fullmatch(name) or not host or "\x00" in host: raise GuardError("invalid node")
        if name in seen: raise GuardError(f"duplicate node {name}")
        seen.add(name)
        for k in ("health_checks","slo_checks"):
            if k in n and not isinstance(n[k],list): raise GuardError(f"{k} must be array")
    pol=plan.get("policy",{})
    if not isinstance(pol,dict): raise GuardError("policy must be object")
    mode=pol.get("mode","observe")
    if mode not in ("observe","quarantine","remediate","rollback"): raise GuardError("invalid policy.mode")
    if mode!="observe" and not pol.get("allow_actions",False): raise GuardError("mutating mode requires policy.allow_actions=true")
    for k,d,mn in (("consecutive_failures",3,1),("max_actions_per_run",1,0),("max_actions_per_cohort",1,0),("max_unhealthy_nodes",1,0),("max_unhealthy_per_cohort",1,0),("max_unhealthy_percent",25,0),("max_parallel",4,1)):
        if int(pol.get(k,d))<mn: raise GuardError(f"invalid policy.{k}")
    return plan

def ssh_base(node,plan):
    args=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=10"]
    if not plan.get("allow_insecure_host_key",False): args += ["-o","StrictHostKeyChecking=yes"]
    if node.get("port"): args += ["-p",str(int(node["port"]))]
    if node.get("identity_file"): args += ["-i",str(node["identity_file"])]
    target=(str(node.get("user"))+"@" if node.get("user") else "")+str(node["host"])
    return args+[target]

def remote(node,plan,argv,*,check=True,timeout=60,input_text=None):
    payload=json.dumps(argv)
    py="import json,subprocess,sys; a=json.loads(sys.stdin.read()); r=subprocess.run(a); sys.exit(r.returncode)"
    return RUNNER.run(ssh_base(node,plan)+["python3 -c "+shlex.quote(py)],check=check,timeout=timeout,input_text=payload)

def remote_capture(node,plan,argv,timeout=60):
    # stdout-preserving variant used by probes; argv still comes from JSON, not shell interpolation.
    payload=json.dumps(argv)
    py="import json,subprocess,sys; a=json.loads(sys.stdin.read()); r=subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); sys.stdout.write(r.stdout); sys.stderr.write(r.stderr); sys.exit(r.returncode)"
    return RUNNER.run(ssh_base(node,plan)+["python3 -c "+shlex.quote(py)],check=False,timeout=timeout,input_text=payload)

def state_dir(plan,root): return pathlib.Path(root)/plan["guard_id"]
def journal_path(plan,root): return state_dir(plan,root)/"journal.json"
def lock_path(plan,root): return state_dir(plan,root)/"lock"
def fresh_journal(plan):
    return {"schema_version":1,"guard_id":plan["guard_id"],"plan_sha256":sha(plan),"created_at":now(),"updated_at":now(),"runs":0,"status":"new","nodes":{n["name"]:{"failure_streak":0,"status":"unknown","last_action":None} for n in plan["nodes"]}}
def save(plan,root,j): j["updated_at"]=now(); atomic_json(journal_path(plan,root),j)
def read_journal(plan,root):
    p=journal_path(plan,root)
    if not p.exists(): return fresh_journal(plan)
    j=load(p)
    if j.get("plan_sha256")!=sha(plan): raise GuardError("plan hash changed; use a new guard_id for a new desired release/policy")
    return j

def parse_float(s):
    try:return float(str(s).strip().splitlines()[-1])
    except Exception as e: raise GuardError(f"metric output is not numeric: {s!r}") from e

def node_observation(node,plan):
    obs={"name":node["name"],"host":node["host"],"observed_at":now(),"drift":[],"health":[],"slos":[]}
    # Host/build inventory is one fixed remote Python program, avoiding shell parsing.
    inv_script=("import hashlib,json,os,platform,shutil; "
                "p='/var/lib/fluxvm/sentinel-release.json'; d={}; "
                "d=json.load(open(p)) if os.path.exists(p) else {}; "
                "print(json.dumps({'kernel':platform.release(),'arch':platform.machine(),'bpftool':bool(shutil.which('bpftool')),'release':d}))")
    r=remote_capture(node,plan,["python3","-c",inv_script],timeout=30)
    if r.rc:
        obs["drift"].append({"kind":"inventory-unreachable","severity":"critical","detail":(r.stderr or r.stdout)[-1000:]}); return obs
    try: inv=json.loads(r.stdout.strip() or "{}")
    except Exception:
        obs["drift"].append({"kind":"inventory-invalid","severity":"critical","detail":"remote inventory was not JSON"}); return obs
    obs["inventory"]=inv
    desired=plan["desired"]; rel=inv.get("release",{}) if isinstance(inv.get("release"),dict) else {}
    if rel.get("release_id")!=desired.get("release_id"):
        obs["drift"].append({"kind":"release-mismatch","severity":"critical","expected":desired.get("release_id"),"observed":rel.get("release_id")})
    if desired.get("artifact_sha256") and rel.get("artifact_sha256")!=desired.get("artifact_sha256"):
        obs["drift"].append({"kind":"artifact-mismatch","severity":"critical","expected":desired.get("artifact_sha256"),"observed":rel.get("artifact_sha256")})
    expected_abis=desired.get("state_abis",{})
    got_abis=rel.get("state_abis",{}) if isinstance(rel.get("state_abis"),dict) else {}
    for name,fp in expected_abis.items():
        if got_abis.get(name)!=fp: obs["drift"].append({"kind":"state-abi-mismatch","severity":"critical","component":name,"expected":fp,"observed":got_abis.get(name)})
    for spec in node.get("file_hashes",[]):
        path=str(spec.get("path","")); expected=str(spec.get("sha256",""))
        if not path.startswith("/") or not expected: continue
        rr=remote_capture(node,plan,["sha256sum",path],timeout=30)
        got=rr.stdout.split()[0] if rr.rc==0 and rr.stdout.split() else None
        if got!=expected: obs["drift"].append({"kind":"file-hash-mismatch","severity":"critical","path":path,"expected":expected,"observed":got})
    for chk in node.get("health_checks",[]):
        argv=chk.get("argv") if isinstance(chk,dict) else None
        if not isinstance(argv,list) or not argv: raise GuardError(f"invalid health check on {node['name']}")
        rr=remote_capture(node,plan,[str(x) for x in argv],timeout=float(chk.get("timeout_seconds",30)))
        good=rr.rc==int(chk.get("expected_rc",0)); rec={"name":chk.get("name","health"),"ok":good,"rc":rr.rc}; obs["health"].append(rec)
        if not good: obs["drift"].append({"kind":"health-check-failed","severity":"critical","check":rec["name"],"rc":rr.rc})
    for chk in node.get("slo_checks",[]):
        argv=chk.get("argv") if isinstance(chk,dict) else None; op=str(chk.get("op","le")); threshold=float(chk.get("threshold",0))
        if not isinstance(argv,list) or not argv or op not in OPS: raise GuardError(f"invalid SLO check on {node['name']}")
        rr=remote_capture(node,plan,[str(x) for x in argv],timeout=float(chk.get("timeout_seconds",30)))
        try: value=parse_float(rr.stdout) if rr.rc==0 else None; good=value is not None and OPS[op](value,threshold)
        except GuardError: value=None; good=False
        rec={"name":chk.get("name","slo"),"ok":good,"value":value,"op":op,"threshold":threshold}; obs["slos"].append(rec)
        if not good: obs["drift"].append({"kind":"slo-violation","severity":"warning" if chk.get("severity")=="warning" else "critical","check":rec["name"],"value":value,"op":op,"threshold":threshold})
    return obs

def node_cohort(node):
    c=str(node.get("cohort","default"))
    return c if NAME_RE.fullmatch(c) else "default"

def action_for(node,plan,obs):
    mode=plan.get("policy",{}).get("mode","observe")
    if mode=="observe": return None
    key={"quarantine":"quarantine_argv","remediate":"remediate_argv","rollback":"rollback_argv"}[mode]
    argv=node.get(key)
    if not isinstance(argv,list) or not argv: return None
    return [str(x) for x in argv]

def execute_action(node,plan,argv):
    # Never invent a mutating command. The exact approved argv is part of the immutable plan hash.
    cmd=argv
    if plan.get("policy",{}).get("sudo_actions",True): cmd=["sudo","-n"]+cmd
    return remote_capture(node,plan,cmd,timeout=float(plan.get("policy",{}).get("action_timeout_seconds",900)))

def write_evidence(plan,j,root,run_record):
    d=state_dir(plan,root)/"evidence"/f"run-{j['runs']:06d}"; d.mkdir(parents=True,exist_ok=True)
    atomic_json(d/"plan.json",plan,0o640); atomic_json(d/"run.json",run_record,0o640); atomic_json(d/"journal.json",j,0o640)
    files=[]
    for p in sorted(d.glob("*.json")): files.append({"file":p.name,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()})
    manifest={"schema_version":1,"generated_at":now(),"files":files}; atomic_json(d/"manifest.json",manifest,0o640)
    key=plan.get("evidence_signing_key")
    if key:
        if not pathlib.Path(key).is_file(): raise GuardError("evidence signing key missing")
        sig=d/"manifest.json.sig"
        r=RUNNER.run(["ssh-keygen","-Y","sign","-f",str(key),"-n","fluxvm-sentinel",str(d/"manifest.json")],check=False,timeout=30)
        produced=pathlib.Path(str(d/"manifest.json")+".sig")
        if r.rc or not produced.exists(): raise GuardError("evidence signing failed")
        os.replace(produced,sig)
    return d

def evaluate_budget(plan,observations):
    unhealthy=[o for o in observations if any(d.get("severity")=="critical" for d in o.get("drift",[]))]
    pol=plan.get("policy",{}); n=len(observations); pct=(100.0*len(unhealthy)/n) if n else 100.0
    global_ok=len(unhealthy)<=int(pol.get("max_unhealthy_nodes",1)) and pct<=float(pol.get("max_unhealthy_percent",25))
    node_map={n["name"]:n for n in plan["nodes"]}; by={}
    for o in unhealthy:
        c=node_cohort(node_map[o["name"]]); by[c]=by.get(c,0)+1
    cohort_ok=all(v<=int(pol.get("max_unhealthy_per_cohort",1)) for v in by.values())
    return unhealthy, global_ok and cohort_ok

def run_once(plan,root):
    d=state_dir(plan,root); d.mkdir(parents=True,exist_ok=True)
    with open(lock_path(plan,root),"a+") as lf:
        try: fcntl.flock(lf,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e: raise GuardError("guard is already running") from e
        j=read_journal(plan,root); pol=plan.get("policy",{}); maxp=int(pol.get("max_parallel",4))
        key=plan.get("evidence_signing_key")
        if key and (not pathlib.Path(key).is_file() or not shutil.which("ssh-keygen")):
            raise GuardError("evidence signing preflight failed")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=maxp) as ex:
                observations=list(ex.map(lambda n:node_observation(n,plan),plan["nodes"]))
            j["runs"]+=1; obs_by={o["name"]:o for o in observations}
            threshold=int(pol.get("consecutive_failures",3))
            for n in plan["nodes"]:
                rec=j["nodes"][n["name"]]; bad=any(x.get("severity")=="critical" for x in obs_by[n["name"]].get("drift",[]))
                rec["failure_streak"]=rec.get("failure_streak",0)+1 if bad else 0; rec["status"]="drift" if bad else "compliant"; rec["last_observed_at"]=now()
            unhealthy,budget_ok=evaluate_budget(plan,observations); actions=[]
            action_budget=int(pol.get("max_actions_per_run",1)); cohort_action_budget=int(pol.get("max_actions_per_cohort",1)); cohort_actions={}
            # Fleet/cohort budgets are mutation circuit breakers: if already over budget, observe and stop changing nodes.
            if budget_ok and pol.get("allow_actions",False):
                for n in plan["nodes"]:
                    if len(actions)>=action_budget: break
                    cohort=node_cohort(n)
                    if cohort_actions.get(cohort,0)>=cohort_action_budget: continue
                    rec=j["nodes"][n["name"]]
                    if rec["failure_streak"]<threshold: continue
                    argv=action_for(n,plan,obs_by[n["name"]])
                    if not argv: continue
                    rr=execute_action(n,plan,argv); a={"node":n["name"],"cohort":cohort,"argv":argv,"rc":rr.rc,"at":now()}; actions.append(a); cohort_actions[cohort]=cohort_actions.get(cohort,0)+1; rec["last_action"]=a; rec["status"]="action-succeeded" if rr.rc==0 else "manual-intervention"
                    if rr.rc!=0: j["status"]="manual-intervention"; save(plan,root,j); break
            if j.get("status")!="manual-intervention": j["status"]="healthy" if not unhealthy else ("degraded" if budget_ok else "paused-budget")
            cohort_summary={}
            for n in plan["nodes"]:
                c=node_cohort(n); cohort_summary.setdefault(c,{"nodes":[],"unhealthy":[]}); cohort_summary[c]["nodes"].append(n["name"]);
                if n["name"] in {o["name"] for o in unhealthy}: cohort_summary[c]["unhealthy"].append(n["name"])
            run_record={"schema_version":1,"run":j["runs"],"started_at":now(),"desired_release":plan["desired"]["release_id"],"observations":observations,"unhealthy_nodes":[o["name"] for o in unhealthy],"cohorts":cohort_summary,"budget_ok":budget_ok,"actions":actions,"status":j["status"]}
            save(plan,root,j); ev=write_evidence(plan,j,root,run_record); run_record["evidence_dir"]=str(ev); return run_record
        finally: fcntl.flock(lf,fcntl.LOCK_UN)

def verify_evidence(path):
    d=pathlib.Path(path); manifest=load(d/"manifest.json")
    for x in manifest.get("files",[]):
        p=d/x["file"]
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=x["sha256"]: raise GuardError(f"evidence verification failed: {x['file']}")
    return True

def main():
    ap=argparse.ArgumentParser(prog="fluxvm-fleet-guard",description="FluxVM Sentinel Set 16E fleet drift and SLO guard")
    ap.add_argument("--state-dir",default=DEFAULT_STATE_DIR)
    sub=ap.add_subparsers(dest="cmd",required=True)
    for c in ("validate","check","status"): sub.add_parser(c).add_argument("plan")
    v=sub.add_parser("verify-evidence"); v.add_argument("directory")
    a=ap.parse_args()
    if a.cmd=="verify-evidence": verify_evidence(a.directory); print(json.dumps({"ok":True,"directory":a.directory},indent=2)); return
    plan=validate(load(a.plan))
    if a.cmd=="validate": print(json.dumps({"ok":True,"plan_sha256":sha(plan),"nodes":len(plan["nodes"]),"mode":plan.get("policy",{}).get("mode","observe")},indent=2)); return
    if a.cmd=="check": print(json.dumps(run_once(plan,a.state_dir),indent=2,sort_keys=True)); return
    if a.cmd=="status": print(json.dumps(read_journal(plan,a.state_dir),indent=2,sort_keys=True)); return
if __name__=="__main__":
    try: main()
    except GuardError as e: print(f"fluxvm-fleet-guard: {e}",file=os.sys.stderr); raise SystemExit(1)
