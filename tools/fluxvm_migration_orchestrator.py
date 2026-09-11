# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Crash-resumable FluxVM migration transaction orchestrator (Sentinel Set 13E)."""
from __future__ import annotations
import argparse, dataclasses, fcntl, hashlib, http.server, json, os, re, shlex, shutil
import socketserver, subprocess, sys, time, uuid
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 1
MIGRATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SENSITIVE_FLAGS = {"--token", "--password", "--secret", "--api-key", "--bearer"}

class MigrationError(RuntimeError): pass
class ManualIntervention(MigrationError): pass

@dataclasses.dataclass(frozen=True)
class Node:
    name: str
    host: str | None = None
    user: str | None = None
    port: int = 22
    sudo: bool = False
    strict_host_key: bool = True
    command_timeout_seconds: int = 60

    @staticmethod
    def from_obj(name: str, obj: dict[str, Any]) -> "Node":
        if not isinstance(obj, dict): raise MigrationError(f"{name}: node must be an object")
        allowed={"host","user","port","sudo","strict_host_key","command_timeout_seconds"}
        unknown=set(obj)-allowed
        if unknown: raise MigrationError(f"{name}: unknown node fields: {sorted(unknown)}")
        port=int(obj.get("port",22)); timeout=int(obj.get("command_timeout_seconds",60))
        if not 1<=port<=65535: raise MigrationError(f"{name}: invalid SSH port")
        if not 1<=timeout<=3600: raise MigrationError(f"{name}: command timeout must be 1..3600")
        host=obj.get("host") or None; user=obj.get("user") or None
        for value,label in [(host,"host"),(user,"user")]:
            if value is not None and ("\n" in value or "\x00" in value or any(c.isspace() for c in value) or value.startswith("-")):
                raise MigrationError(f"{name}: invalid {label}")
        if user is not None and not re.fullmatch(r"[A-Za-z0-9._-]+", user): raise MigrationError(f"{name}: invalid user")
        return Node(name,host,user,port,bool(obj.get("sudo",False)),bool(obj.get("strict_host_key",True)),timeout)

@dataclasses.dataclass
class Result:
    returncode: int; stdout: str; stderr: str; elapsed_ms: int

class Runner:
    def __init__(self,node:Node,dry_run:bool=False): self.node=node; self.dry_run=dry_run
    def _remote_target(self)->str:
        return f"{self.node.user}@{self.node.host}" if self.node.user else str(self.node.host)
    def _argv(self,argv:list[str])->list[str]:
        validate_argv(argv)
        if self.node.sudo: argv=["sudo","-n","--",*argv]
        if not self.node.host: return argv
        return ["ssh","-o","BatchMode=yes","-o",f"StrictHostKeyChecking={'yes' if self.node.strict_host_key else 'no'}","-p",str(self.node.port),self._remote_target(),"--",shlex.join(argv)]
    def run(self,argv:list[str],check:bool=True,timeout:int|None=None)->Result:
        actual=self._argv(list(argv)); timeout=timeout or self.node.command_timeout_seconds
        if self.dry_run: return Result(0,"",f"DRY-RUN {redact_argv(actual)}",0)
        started=time.monotonic_ns()
        try:
            p=subprocess.run(actual,text=True,capture_output=True,timeout=timeout,check=False)
        except FileNotFoundError as e:
            if not check: return Result(127,"",str(e),0)
            raise MigrationError(f"{self.node.name}: executable not found: {redact_argv(actual)}") from e
        except subprocess.TimeoutExpired as e:
            raise MigrationError(f"{self.node.name}: command timed out after {timeout}s: {redact_argv(actual)}") from e
        elapsed=(time.monotonic_ns()-started)//1_000_000
        r=Result(p.returncode,p.stdout,p.stderr,elapsed)
        if check and p.returncode:
            raise MigrationError(f"{self.node.name}: command failed rc={p.returncode}: {redact_argv(actual)}\n{p.stderr[-4000:]}")
        return r
    def has_binary(self,name:str)->bool:
        if not re.fullmatch(r"[A-Za-z0-9._+/-]+", name) or name.startswith("-"): return False
        if self.dry_run: return True
        if not self.node.host: return shutil.which(name) is not None
        target=self._remote_target()
        cmd=["ssh","-o","BatchMode=yes","-o",f"StrictHostKeyChecking={'yes' if self.node.strict_host_key else 'no'}","-p",str(self.node.port),target,"--",f"command -v {shlex.quote(name)} >/dev/null 2>&1"]
        try: return subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=self.node.command_timeout_seconds,check=False).returncode==0
        except (FileNotFoundError,subprocess.TimeoutExpired): return False
    def put(self,local:Path,remote:str)->None:
        validate_remote_path(remote)
        if self.dry_run: return
        if not self.node.host:
            dest=Path(remote); dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(local,dest); os.chmod(dest,0o600); return
        cmd=["scp","-q","-P",str(self.node.port),"-o",f"StrictHostKeyChecking={'yes' if self.node.strict_host_key else 'no'}",str(local),f"{self._remote_target()}:{remote}"]
        p=subprocess.run(cmd,text=True,capture_output=True,timeout=self.node.command_timeout_seconds,check=False)
        if p.returncode: raise MigrationError(f"scp put failed to {self.node.name}: {p.stderr[-4000:]}")
        # The restore may run under sudo, but the copied snapshot remains readable only by the SSH user/root.
        chmod=["ssh","-o","BatchMode=yes","-o",f"StrictHostKeyChecking={'yes' if self.node.strict_host_key else 'no'}","-p",str(self.node.port),self._remote_target(),"--",shlex.join(["chmod","0600",remote])]
        p=subprocess.run(chmod,text=True,capture_output=True,timeout=self.node.command_timeout_seconds,check=False)
        if p.returncode: raise MigrationError(f"chmod of transferred snapshot failed on {self.node.name}: {p.stderr[-4000:]}")
    def get(self,remote:str,local:Path)->None:
        validate_remote_path(remote); local.parent.mkdir(parents=True,exist_ok=True)
        if self.dry_run:
            local.write_text("{}\n"); os.chmod(local,0o600); return
        # sudo exports can be root-owned; read them through cat rather than assuming scp has permission.
        cat_argv=["cat",remote]
        if self.node.sudo: cat_argv=["sudo","-n","--",*cat_argv]
        if not self.node.host:
            try: p=subprocess.run(cat_argv,capture_output=True,timeout=self.node.command_timeout_seconds,check=False)
            except FileNotFoundError as e: raise MigrationError(f"cannot read exported snapshot: {e}") from e
        else:
            cmd=["ssh","-o","BatchMode=yes","-o",f"StrictHostKeyChecking={'yes' if self.node.strict_host_key else 'no'}","-p",str(self.node.port),self._remote_target(),"--",shlex.join(cat_argv)]
            p=subprocess.run(cmd,capture_output=True,timeout=self.node.command_timeout_seconds,check=False)
        if p.returncode: raise MigrationError(f"snapshot read failed from {self.node.name}: {p.stderr.decode(errors='replace')[-4000:]}")
        fd=os.open(local,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        try: os.write(fd,p.stdout); os.fsync(fd)
        finally: os.close(fd)

class Journal:
    def __init__(self,state_root:Path,migration_id:str):
        validate_migration_id(migration_id); self.root=state_root/migration_id; self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chmod(self.root,0o700); self.path=self.root/'journal.json'; self.lock_path=self.root/'lock'; self._fd=None
    def lock(self):
        self._fd=open(self.lock_path,'a+')
        try: fcntl.flock(self._fd.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except Exception:
            self._fd.close(); self._fd=None; raise
        return self
    def close(self):
        if self._fd: fcntl.flock(self._fd.fileno(),fcntl.LOCK_UN); self._fd.close(); self._fd=None
    def load(self)->dict[str,Any]:
        if not self.path.exists(): return {"schema_version":SCHEMA_VERSION,"completed_steps":[],"events":[],"status":"new"}
        o=json.loads(self.path.read_text())
        if o.get("schema_version")!=SCHEMA_VERSION: raise MigrationError("unsupported journal schema")
        return o
    def save(self,o:dict[str,Any]):
        o["updated_unix_ns"]=time.time_ns(); tmp=self.path.with_suffix('.tmp')
        data=(json.dumps(o,indent=2,sort_keys=True)+"\n").encode(); fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        try: os.write(fd,data); os.fsync(fd)
        finally: os.close(fd)
        os.replace(tmp,self.path); dfd=os.open(self.root,os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
    def artifact(self,name:str,data:bytes)->Path:
        if '/' in name or name in {'.','..'}: raise MigrationError("invalid artifact name")
        p=self.root/name; fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        try: os.write(fd,data); os.fsync(fd)
        finally: os.close(fd)
        return p

class Orchestrator:
    def __init__(self,plan:dict[str,Any],state_root:Path,dry_run:bool=False):
        validate_plan(plan); self.plan=plan; self.id=plan['migration_id']; self.vm=plan['vm_id']; self.j=Journal(state_root,self.id)
        self.src=Runner(Node.from_obj('source',plan['source']),dry_run); self.dst=Runner(Node.from_obj('destination',plan['destination']),dry_run); self.dry_run=dry_run
    def _record_event(self,state:dict[str,Any],kind:str,**kw):
        state.setdefault('events',[]).append({"time_unix_ns":time.time_ns(),"kind":kind,**kw}); state['events']=state['events'][-512:]
    def _step(self,state:dict[str,Any],name:str,fn:Callable[[],Any]):
        if name in state.get('completed_steps',[]): return
        self._record_event(state,'step-start',step=name); self.j.save(state)
        started=time.monotonic_ns(); out=fn(); elapsed=(time.monotonic_ns()-started)//1_000_000
        state.setdefault('completed_steps',[]).append(name); state['phase']=name; self._record_event(state,'step-complete',step=name,elapsed_ms=elapsed)
        if out is not None: state.setdefault('results',{})[name]=out
        self.j.save(state)
    def _cmd(self,runner:Runner,argv:list[str],check=True)->dict[str,Any]:
        r=runner.run(argv,check=check); return {"returncode":r.returncode,"stdout":r.stdout[-8192:],"stderr":r.stderr[-8192:],"elapsed_ms":r.elapsed_ms,"argv":redact_list(argv)}
    def preflight(self):
        checks=[]
        req=[(self.src,'source','fluxvm',True),(self.dst,'destination','fluxvm',True)]
        q=self.plan.get('quiclb') or {}
        if q.get('instance_id'):
            required=not q.get('optional',True); req += [(self.src,'source','fluxvm-quiclb',required),(self.dst,'destination','fluxvm-quiclb',required)]
        for comp,binary in [('afxdp','fluxvm-afxdp'),('topology','fluxvm-topology'),('scx','fluxvm-scx')]:
            c=self.plan.get(comp) or {}
            if c.get('enabled'):
                required=not c.get('optional',False); req += [(self.src,'source',binary,required),(self.dst,'destination',binary,required)]
        vbin=self.plan['vmm']['migrate_argv'][0]; req.append((self.src,'source',vbin,True))
        seen=set()
        for runner,label,binary,required in req:
            key=(label,binary)
            if key in seen: continue
            seen.add(key); available=runner.has_binary(binary); checks.append({"node":label,"binary":binary,"available":available,"required":required})
            if required and not available: raise MigrationError(f"preflight: {binary} missing on {label}")
        return {"checks":checks,"plan_sha256":sha256_bytes(canonical_json(self.plan))}
    def export_network(self):
        remote=f"/tmp/fluxvm-migrate-{self.id}-network.json"; local=self.j.root/'network-state.json'
        self.src.run(['fluxvm','dataplane','migration-export',self.vm,'--output',remote]); self.src.get(remote,local)
        return {"path":str(local),"sha256":sha256_file(local)}
    def export_quic(self):
        q=self.plan.get('quiclb') or {}; iid=q.get('instance_id')
        if not iid: return {"skipped":True}
        remote=f"/tmp/fluxvm-migrate-{self.id}-quic.json"; local=self.j.root/'quic-affinity.json'
        r=self.src.run(['fluxvm-quiclb','affinity-export',iid,remote],check=not q.get('optional',True))
        if r.returncode and q.get('optional',True): return {"skipped":True,"reason":"quiclb unavailable"}
        self.src.get(remote,local); return {"path":str(local),"sha256":sha256_file(local)}
    def stop_aux(self):
        out={}; a=self.plan.get('afxdp') or {}; t=self.plan.get('topology') or {}; s=self.plan.get('scx') or {}
        if a.get('enabled'): out['afxdp']=self._cmd(self.src,['fluxvm-afxdp','stop',self.vm],check=not a.get('optional',False))
        if t.get('enabled'): out['topology']=self._cmd(self.src,['fluxvm-topology','rollback',self.vm],check=not t.get('optional',False))
        if s.get('enabled'): out['scx']=self._cmd(self.src,['fluxvm-scx','rollback',self.vm],check=not s.get('optional',False))
        return out
    def migrate_vmm(self): return self._cmd(self.src,expand_argv(self.plan['vmm']['migrate_argv'],self))
    def restore_destination(self):
        local=self.j.root/'network-state.json'; remote=f"/tmp/fluxvm-migrate-{self.id}-network.json"; self.dst.put(local,remote)
        out={'network':self._cmd(self.dst,['fluxvm','dataplane','migration-restore',self.vm,'--input',remote])}
        q=self.plan.get('quiclb') or {}; iid=q.get('instance_id'); qlocal=self.j.root/'quic-affinity.json'
        if iid and qlocal.exists():
            qremote=f"/tmp/fluxvm-migrate-{self.id}-quic.json"; self.dst.put(qlocal,qremote)
            out['quiclb']=self._cmd(self.dst,['fluxvm-quiclb','affinity-import',iid,qremote],check=not q.get('optional',True))
        return out
    def start_aux_destination(self):
        out={}; a=self.plan.get('afxdp') or {}; t=self.plan.get('topology') or {}; s=self.plan.get('scx') or {}
        if a.get('enabled') and a.get('destination_plan'): out['afxdp']=self._cmd(self.dst,['fluxvm-afxdp','start',a['destination_plan']],check=not a.get('optional',False))
        if t.get('enabled') and t.get('destination_plan'): out['topology']=self._cmd(self.dst,['fluxvm-topology','apply',t['destination_plan']],check=not t.get('optional',False))
        if s.get('enabled') and s.get('destination_plan'): out['scx']=self._cmd(self.dst,['fluxvm-scx','apply',s['destination_plan']],check=not s.get('optional',False))
        return out
    def run(self)->dict[str,Any]:
        self.j.lock(); state=self.j.load()
        try:
            expected=sha256_bytes(canonical_json(self.plan)); existing=state.get('plan_sha256')
            if existing and existing!=expected: raise MigrationError("plan changed after transaction began; use a new migration_id")
            if state.get('status')=='complete':
                if not (self.j.root/'EVIDENCE.sha256').exists():
                    state['evidence_sha256']=self.seal_evidence(state); self.j.save(state)
                return state
            if state.get('status')=='manual-intervention': raise ManualIntervention("journal requires manual intervention")
            state.update({"migration_id":self.id,"vm_id":self.vm,"status":"running","plan_sha256":expected}); self.j.save(state)
            self._step(state,'preflight',self.preflight)
            self._step(state,'source-quiesced',lambda:self._cmd(self.src,['fluxvm','dataplane','migration-quiesce',self.vm]))
            self._step(state,'state-exported',lambda:{"network":self.export_network(),"quic":self.export_quic()})
            self._step(state,'aux-quiesced',self.stop_aux)
            self._step(state,'vmm-migrated',self.migrate_vmm)
            self._step(state,'destination-restored',self.restore_destination)
            self._step(state,'aux-restored',self.start_aux_destination)
            self._step(state,'destination-resumed',lambda:self._cmd(self.dst,['fluxvm','dataplane','migration-resume',self.vm]))
            self._step(state,'temp-cleanup',self.cleanup_remote_temps)
            self._step(state,'complete',lambda:{"transaction":"committed"})
            state['status']='complete'; self.j.save(state)
            state['evidence_sha256']=self.seal_evidence(state); self.j.save(state); return state
        except Exception as e:
            state['status']='failed'; state['error']=str(e); self._record_event(state,'failure',error=str(e)); self.j.save(state)
            if self.plan.get('automatic_rollback',True):
                try: self.rollback_locked(state)
                except Exception as rb:
                    state['status']='manual-intervention'; state['rollback_error']=str(rb); self._record_event(state,'rollback-failure',error=str(rb)); self.j.save(state)
            raise
        finally: self.j.close()
    def rollback_locked(self,state):
        done=set(state.get('completed_steps',[])); actions=[]
        if 'vmm-migrated' in done:
            rb=self.plan.get('vmm',{}).get('rollback_argv')
            if not rb: raise ManualIntervention("VMM already migrated and no vmm.rollback_argv is configured")
            actions.append(('vmm-rollback',lambda:self._cmd(self.dst,expand_argv(rb,self))))
        a=self.plan.get('afxdp') or {}; t=self.plan.get('topology') or {}; s=self.plan.get('scx') or {}
        if 'aux-quiesced' in done:
            if t.get('enabled') and t.get('source_plan'): actions.append(('topology-source-reapply',lambda:self._cmd(self.src,['fluxvm-topology','apply',t['source_plan']],check=not t.get('optional',False))))
            if s.get('enabled') and s.get('source_plan'): actions.append(('scx-source-reapply',lambda:self._cmd(self.src,['fluxvm-scx','apply',s['source_plan']],check=not s.get('optional',False))))
            if a.get('enabled') and a.get('source_plan'): actions.append(('afxdp-source-restart',lambda:self._cmd(self.src,['fluxvm-afxdp','start',a['source_plan']],check=not a.get('optional',False))))
        if 'source-quiesced' in done: actions.append(('source-network-resume',lambda:self._cmd(self.src,['fluxvm','dataplane','migration-resume',self.vm])))
        for name,fn in actions:
            if name in state.get('rollback_steps',[]): continue
            out=fn(); state.setdefault('rollback_steps',[]).append(name); state.setdefault('rollback_results',{})[name]=out; self.j.save(state)
        state['status']='rolled-back'; self._record_event(state,'rollback-complete'); self.j.save(state); return state
    def rollback(self):
        self.j.lock(); state=self.j.load()
        try: return self.rollback_locked(state)
        finally: self.j.close()
    def cleanup_remote_temps(self):
        names=[f"/tmp/fluxvm-migrate-{self.id}-network.json",f"/tmp/fluxvm-migrate-{self.id}-quic.json"]
        out=[]
        for runner in (self.src,self.dst):
            r=runner.run(['rm','-f','--',*names],check=False); out.append({"node":runner.node.name,"returncode":r.returncode})
        return out
    def seal_evidence(self,state)->str:
        # journal.final.json is the immutable transaction snapshot covered by the manifest.
        final=(json.dumps(state,indent=2,sort_keys=True)+"\n").encode(); self.j.artifact('journal.final.json',final)
        rows=[]
        for p in sorted(self.j.root.iterdir()):
            if p.is_file() and p.name not in {'lock','journal.json','EVIDENCE.sha256'}: rows.append(f"{sha256_file(p)}  {p.name}")
        data=("\n".join(rows)+"\n").encode(); self.j.artifact('EVIDENCE.sha256',data); return sha256_bytes(data)

def validate_migration_id(s:str):
    if not MIGRATION_ID_RE.fullmatch(s): raise MigrationError("migration_id must be 1..96 safe filename characters")
def validate_remote_path(s:str):
    if not s.startswith('/tmp/fluxvm-migrate-') or '\n' in s or '\x00' in s or '..' in Path(s).parts: raise MigrationError("unsafe remote transfer path")
def validate_argv(argv:list[str]):
    if not argv or not all(isinstance(x,str) and x and '\n' not in x and '\x00' not in x for x in argv): raise MigrationError("invalid argv")
def redact_list(argv:list[str])->list[str]:
    out=[]; hide=False
    for x in argv:
        if hide: out.append('<redacted>'); hide=False; continue
        low=x.lower()
        if any(low.startswith(flag+'=') for flag in SENSITIVE_FLAGS):
            out.append(x.split('=',1)[0]+'=<redacted>'); hide=False; continue
        out.append(x); hide=low in SENSITIVE_FLAGS
    return out
def redact_argv(argv:list[str])->str: return shlex.join(redact_list(argv))
def canonical_json(o:Any)->bytes: return json.dumps(o,sort_keys=True,separators=(',',':')).encode()
def sha256_bytes(b:bytes)->str: return hashlib.sha256(b).hexdigest()
def sha256_file(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()
def expand_argv(argv:list[str],o:Orchestrator)->list[str]:
    if not isinstance(argv,list): raise MigrationError("argv must be an array")
    mapping={'{vm_id}':o.vm,'{migration_id}':o.id}; result=[]
    for a in argv:
        if not isinstance(a,str): raise MigrationError("argv entries must be strings")
        for k,v in mapping.items(): a=a.replace(k,v)
        result.append(a)
    validate_argv(result); return result

def validate_plan(p:dict[str,Any]):
    required={'schema_version','migration_id','vm_id','source','destination','vmm'}; missing=required-set(p)
    if missing: raise MigrationError(f"missing plan fields: {sorted(missing)}")
    if p['schema_version']!=SCHEMA_VERSION: raise MigrationError("unsupported plan schema_version")
    validate_migration_id(str(p['migration_id']))
    try: uuid.UUID(str(p['vm_id']))
    except Exception as e: raise MigrationError("vm_id must be UUID") from e
    Node.from_obj('source',p['source']); Node.from_obj('destination',p['destination']); v=p['vmm']
    if not isinstance(v,dict) or not isinstance(v.get('migrate_argv'),list): raise MigrationError("vmm.migrate_argv array is required")
    validate_argv(v['migrate_argv'])
    if 'rollback_argv' in v: validate_argv(v['rollback_argv'])
    for comp in ('afxdp','topology','scx'):
        c=p.get(comp)
        if c is not None and not isinstance(c,dict): raise MigrationError(f"{comp} must be an object")
    q=p.get('quiclb')
    if q and q.get('instance_id'):
        try: uuid.UUID(str(q['instance_id']))
        except Exception as e: raise MigrationError("quiclb.instance_id must be UUID") from e

def load_plan(path:Path)->dict[str,Any]:
    o=json.loads(path.read_text()); validate_plan(o); return o

def list_journals(root:Path)->list[dict[str,Any]]:
    rows=[]
    if not root.exists(): return rows
    for d in sorted(root.iterdir()):
        p=d/'journal.json'
        if p.exists():
            try: rows.append(json.loads(p.read_text()))
            except Exception: rows.append({'migration_id':d.name,'status':'corrupt'})
    return rows

class Handler(http.server.BaseHTTPRequestHandler):
    state_root=Path('/var/lib/fluxvm/migrations')
    def log_message(self,fmt,*args): pass
    def _send(self,code,body,ctype='application/json'):
        b=body if isinstance(body,bytes) else body.encode(); self.send_response(code); self.send_header('content-type',ctype); self.send_header('content-length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        rows=list_journals(self.state_root)
        if self.path=='/healthz': return self._send(200,'{"ok":true}\n')
        if self.path=='/v1/migrations': return self._send(200,json.dumps(rows,sort_keys=True)+'\n')
        if self.path=='/metrics':
            counts={k:0 for k in ('complete','running','failed','rolled-back','manual-intervention','corrupt')}
            for r in rows: counts[r.get('status','running')]=counts.get(r.get('status','running'),0)+1
            lines=['# HELP fluxvm_migration_journals Number of migration journals by state.','# TYPE fluxvm_migration_journals gauge']
            for k,v in sorted(counts.items()): lines.append(f'fluxvm_migration_journals{{status="{k}"}} {v}')
            return self._send(200,'\n'.join(lines)+'\n','text/plain; version=0.0.4')
        m=re.fullmatch(r'/v1/migrations/([A-Za-z0-9._-]+)',self.path)
        if m:
            p=self.state_root/m.group(1)/'journal.json'
            if p.exists(): return self._send(200,p.read_text())
            return self._send(404,'{"error":"not found"}\n')
        return self._send(404,'{"error":"not found"}\n')

def main(argv=None)->int:
    ap=argparse.ArgumentParser(prog='fluxvm-migrate',description='FluxVM Sentinel Set 13E migration transaction orchestrator')
    ap.add_argument('--state-root',default=os.getenv('FLUXVM_MIGRATION_STATE_ROOT','/var/lib/fluxvm/migrations'))
    sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('validate'); p.add_argument('plan')
    p=sub.add_parser('run'); p.add_argument('plan'); p.add_argument('--dry-run',action='store_true')
    p=sub.add_parser('resume'); p.add_argument('plan'); p.add_argument('--dry-run',action='store_true')
    p=sub.add_parser('rollback'); p.add_argument('plan'); p.add_argument('--dry-run',action='store_true')
    p=sub.add_parser('status'); p.add_argument('migration_id')
    p=sub.add_parser('reconcile'); p.add_argument('--stale-minutes',type=int,default=15)
    p=sub.add_parser('serve'); p.add_argument('--listen',default='127.0.0.1:7797')
    a=ap.parse_args(argv); root=Path(a.state_root)
    try:
        if a.cmd=='validate': print(json.dumps({'ok':True,'plan':load_plan(Path(a.plan))},indent=2)); return 0
        if a.cmd in {'run','resume','rollback'}:
            o=Orchestrator(load_plan(Path(a.plan)),root,a.dry_run); state=o.rollback() if a.cmd=='rollback' else o.run(); print(json.dumps(state,indent=2,sort_keys=True)); return 0
        if a.cmd=='status':
            validate_migration_id(a.migration_id); p=root/a.migration_id/'journal.json'
            if not p.exists(): raise MigrationError('journal not found')
            print(p.read_text(),end=''); return 0
        if a.cmd=='reconcile':
            now=time.time_ns(); stale=[]
            for r in list_journals(root):
                age=(now-int(r.get('updated_unix_ns',now)))/60e9
                if r.get('status') not in {'complete','rolled-back'} and age>=a.stale_minutes: stale.append({'migration_id':r.get('migration_id'),'status':r.get('status'),'age_minutes':round(age,1)})
            print(json.dumps({'stale':stale,'count':len(stale)},indent=2)); return 2 if stale else 0
        if a.cmd=='serve':
            host,port=a.listen.rsplit(':',1); Handler.state_root=root
            with socketserver.ThreadingTCPServer((host,int(port)),Handler) as srv: srv.serve_forever()
    except BlockingIOError: print('migration journal is locked by another process',file=sys.stderr); return 73
    except ManualIntervention as e: print(f'MANUAL INTERVENTION: {e}',file=sys.stderr); return 4
    except (MigrationError,OSError,json.JSONDecodeError,subprocess.SubprocessError) as e: print(f'ERROR: {e}',file=sys.stderr); return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
