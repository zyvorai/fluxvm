import importlib.util, json, pathlib, tempfile, unittest, sys
P=pathlib.Path(__file__).parents[1]/"fluxvm_fleet_rollout.py"
s=importlib.util.spec_from_file_location("fleet",P); m=importlib.util.module_from_spec(s); sys.modules["fleet"]=m; s.loader.exec_module(m)

def plan(tmp):
 p={"schema_version":1,"rollout_id":"r1","node_upgrade_plan":str(tmp/"node.json"),"nodes":[{"name":"n1","host":"h1"},{"name":"n2","host":"h2"},{"name":"n3","host":"h3"}],"strategy":{"canary":1,"wave_size":2,"max_parallel":2,"max_failures":0,"rollback_failed_wave":True}}
 (tmp/"node.json").write_text("{}")
 return p

class T(unittest.TestCase):
 def test_validate_duplicate(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(pathlib.Path(d)); p["nodes"][1]["name"]="n1"
   with self.assertRaises(m.FleetError):m.validate(p)
 def test_hash_stable(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(pathlib.Path(d)); self.assertEqual(m.sha(p),m.sha(json.loads(json.dumps(p))))
 def test_waves(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(pathlib.Path(d)); j=m.fresh_journal(p)
   for n in p["nodes"]: j["inventory"][n["name"]]={"arch":"x86_64","kernel":"6.12.1","sched_ext":True}
   m.build_waves(p,j); self.assertEqual([len(x["nodes"]) for x in j["waves"]],[1,2])
 def test_plan_drift_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); p=plan(root); j=m.fresh_journal(p); m.save(p,root,j); p["strategy"]["canary"]=2
   with self.assertRaises(m.FleetError):m.read_journal(p,root)
 def test_failure_budget_rolls_wave(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); p=plan(root); j=m.fresh_journal(p)
   for n in p["nodes"]: j["inventory"][n["name"]]={"arch":"x86_64","kernel":"6.12.1","sched_ext":True,"fluxvm_upgrade":True}
   m.build_waves(p,j); m.save(p,root,j)
   old_u,old_r=m.upgrade_node,m.rollback_node
   class R: pass
   try:
    def u(n,p): x=R(); x.rc=1 if n["name"]=="n1" else 0; x.stdout=""; x.stderr="boom"; return x
    def r(n,p): x=R(); x.rc=0; x.stdout=x.stderr=""; return x
    m.upgrade_node=u; m.rollback_node=r; m.postcheck_node=lambda n,p:(True,"ok")
    with self.assertRaises(m.FleetError): m.run_rollout(p,root)
    jj=m.read_journal(p,root); self.assertEqual(jj["status"],"paused"); self.assertEqual(jj["nodes"]["n1"]["status"],"rolled-back")
   finally:m.upgrade_node,m.rollback_node=old_u,old_r
 def test_cohorts_not_mixed(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(pathlib.Path(d)); p["nodes"].append({"name":"n4","host":"h4"}); j=m.fresh_journal(p)
   vals=[("n1","x86_64","6.12.1",True),("n2","x86_64","6.12.1",True),("n3","aarch64","6.12.1",False),("n4","aarch64","6.12.1",False)]
   for name,arch,k,scx in vals:j["inventory"][name]={"arch":arch,"kernel":k,"sched_ext":scx}
   m.build_waves(p,j)
   for w in j["waves"]:
    keys={m.cohort_key(j["inventory"][n]) for n in w["nodes"]}; self.assertEqual(len(keys),1)
 def test_rollback_failure_requires_manual_intervention(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); p=plan(root); j=m.fresh_journal(p)
   for n in p["nodes"]: j["inventory"][n["name"]]={"arch":"x86_64","kernel":"6.12.1","sched_ext":True,"fluxvm_upgrade":True}
   m.build_waves(p,j); m.save(p,root,j)
   old_u,old_r=m.upgrade_node,m.rollback_node
   class R: pass
   try:
    def u(n,p): x=R(); x.rc=1; x.stdout=""; x.stderr="boom"; return x
    def r(n,p): x=R(); x.rc=1; x.stdout=""; x.stderr="rollback boom"; return x
    m.upgrade_node=u; m.rollback_node=r
    with self.assertRaises(m.FleetError):m.run_rollout(p,root)
    jj=m.read_journal(p,root); self.assertEqual(jj["status"],"manual-intervention")
   finally:m.upgrade_node,m.rollback_node=old_u,old_r
 def test_canary_approval_pause(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); p=plan(root); p["strategy"]["require_canary_approval"]=True; old_i,old_u=m.inventory_node,m.upgrade_node
   class R: rc=0; stdout=""; stderr=""
   try:
    m.inventory_node=lambda n,p:{"name":n["name"],"host":n["host"],"arch":"x86_64","kernel":"6.12.1","sched_ext":True,"fluxvm_upgrade":True,"bpf":True,"bpftool":True,"labels":{}}
    m.upgrade_node=lambda n,p:R(); m.postcheck_node=lambda n,p:(True,"ok")
    j=m.run_rollout(p,root); self.assertEqual(j["status"],"awaiting-canary-approval"); self.assertEqual(j["waves"][0]["status"],"complete")
   finally:m.inventory_node,m.upgrade_node=old_i,old_u
 def test_resume_without_approval_does_not_bypass_canary_gate(self):
  # A crash-resumable `run_rollout` must not let a second call (simulating
  # a resume/retry after the pause) slip past an unapproved canary gate --
  # wave 0 is already "complete" and skipped by `continue`, so the gate
  # check must be re-evaluated on every call, not only the one where the
  # canary wave just finished.
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); p=plan(root); p["strategy"]["require_canary_approval"]=True; old_i,old_u=m.inventory_node,m.upgrade_node
   wave1_ran=[]
   class R: rc=0; stdout=""; stderr=""
   try:
    m.inventory_node=lambda n,p:{"name":n["name"],"host":n["host"],"arch":"x86_64","kernel":"6.12.1","sched_ext":True,"fluxvm_upgrade":True,"bpf":True,"bpftool":True,"labels":{}}
    def u(n,p): wave1_ran.append(n["name"]); return R()
    m.upgrade_node=u; m.postcheck_node=lambda n,p:(True,"ok")
    j=m.run_rollout(p,root); self.assertEqual(j["status"],"awaiting-canary-approval")
    wave1_ran.clear()
    j2=m.run_rollout(p,root)
    self.assertEqual(j2["status"],"awaiting-canary-approval")
    self.assertEqual(wave1_ran,[],"wave 1 must not run before canary approval, even on resume")
    j["canary_approved"]=True; j["status"]="paused"; m.save(p,root,j)
    j3=m.run_rollout(p,root)
    self.assertEqual(j3["status"],"complete")
    self.assertTrue(wave1_ran,"wave 1 should run once canary is approved")
   finally:m.inventory_node,m.upgrade_node=old_i,old_u
 def test_success(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); p=plan(root); old_i,old_u=m.inventory_node,m.upgrade_node
   class R: rc=0; stdout=""; stderr=""
   try:
    m.inventory_node=lambda n,p:{"name":n["name"],"host":n["host"],"arch":"x86_64","kernel":"6.12.1","sched_ext":True,"fluxvm_upgrade":True,"bpf":True,"bpftool":True,"labels":{}}
    m.upgrade_node=lambda n,p:R(); m.postcheck_node=lambda n,p:(True,"ok")
    j=m.run_rollout(p,root); self.assertEqual(j["status"],"complete"); self.assertTrue((root/"r1/evidence/manifest.json").exists())
   finally:m.inventory_node,m.upgrade_node=old_i,old_u
if __name__=="__main__": unittest.main()
