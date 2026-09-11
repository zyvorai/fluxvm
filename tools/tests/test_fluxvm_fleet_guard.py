import importlib.util,json,pathlib,sys,tempfile,unittest
P=pathlib.Path(__file__).parents[1]/"fluxvm_fleet_guard.py"
s=importlib.util.spec_from_file_location("guard",P); m=importlib.util.module_from_spec(s); sys.modules["guard"]=m; s.loader.exec_module(m)

def plan():
 return {"schema_version":1,"guard_id":"g1","desired":{"release_id":"r2","artifact_sha256":"aa","state_abis":{"net":"v8"}},"nodes":[{"name":"n1","host":"h1"},{"name":"n2","host":"h2"}],"policy":{"mode":"observe","consecutive_failures":2,"max_actions_per_run":1,"max_unhealthy_nodes":2,"max_unhealthy_percent":100,"max_parallel":2}}
class T(unittest.TestCase):
 def test_validate_mutating_requires_optin(self):
  p=plan(); p["policy"]["mode"]="rollback"
  with self.assertRaises(m.GuardError):m.validate(p)
 def test_hash_stable(self):
  p=plan(); self.assertEqual(m.sha(p),m.sha(json.loads(json.dumps(p))))
 def test_budget(self):
  p=plan(); obs=[{"name":"n1","drift":[{"severity":"critical"}]},{"name":"n2","drift":[]}]
  u,ok=m.evaluate_budget(p,obs); self.assertEqual(len(u),1); self.assertTrue(ok)
 def test_plan_drift_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); j=m.fresh_journal(p); m.save(p,d,j); p["desired"]["release_id"]="r3"
   with self.assertRaises(m.GuardError):m.read_journal(p,d)
 def test_hysteresis_observe(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); old=m.node_observation
   try:
    m.node_observation=lambda n,p:{"name":n["name"],"drift":[{"severity":"critical","kind":"x"}]}
    r=m.run_once(p,d); self.assertEqual(r["actions"],[]); self.assertEqual(m.read_journal(p,d)["nodes"]["n1"]["failure_streak"],1)
   finally:m.node_observation=old
 def test_action_after_threshold(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); p["policy"].update(mode="quarantine",allow_actions=True,consecutive_failures=2); p["nodes"][0]["quarantine_argv"]=["true"]
   old_o,old_e=m.node_observation,m.execute_action
   class R:rc=0;stdout="";stderr=""
   try:
    m.node_observation=lambda n,p:{"name":n["name"],"drift":[{"severity":"critical","kind":"x"}]} if n["name"]=="n1" else {"name":n["name"],"drift":[]}
    m.execute_action=lambda n,p,a:R()
    self.assertEqual(m.run_once(p,d)["actions"],[])
    rr=m.run_once(p,d); self.assertEqual(len(rr["actions"]),1); self.assertEqual(rr["actions"][0]["node"],"n1")
   finally:m.node_observation,m.execute_action=old_o,old_e
 def test_over_budget_blocks_actions(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); p["policy"].update(mode="quarantine",allow_actions=True,consecutive_failures=1,max_unhealthy_nodes=0); p["nodes"][0]["quarantine_argv"]=["true"]
   old=m.node_observation
   try:
    m.node_observation=lambda n,p:{"name":n["name"],"drift":[{"severity":"critical"}]} if n["name"]=="n1" else {"name":n["name"],"drift":[]}
    r=m.run_once(p,d); self.assertFalse(r["budget_ok"]); self.assertEqual(r["actions"],[]); self.assertEqual(r["status"],"paused-budget")
   finally:m.node_observation=old
 def test_action_failure_manual(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); p["policy"].update(mode="rollback",allow_actions=True,consecutive_failures=1); p["nodes"][0]["rollback_argv"]=["false"]
   old_o,old_e=m.node_observation,m.execute_action
   class R:rc=1;stdout="";stderr="bad"
   try:
    m.node_observation=lambda n,p:{"name":n["name"],"drift":[{"severity":"critical"}]} if n["name"]=="n1" else {"name":n["name"],"drift":[]}
    m.execute_action=lambda n,p,a:R(); r=m.run_once(p,d); self.assertEqual(r["status"],"manual-intervention")
   finally:m.node_observation,m.execute_action=old_o,old_e
 def test_evidence_tamper(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); j=m.fresh_journal(p); j["runs"]=1; ev=m.write_evidence(p,j,d,{"ok":1}); self.assertTrue(m.verify_evidence(ev)); (ev/"run.json").write_text("{}")
   with self.assertRaises(m.GuardError):m.verify_evidence(ev)

 def test_cohort_budget_blocks(self):
  p=plan(); p["policy"]["max_unhealthy_per_cohort"]=1; p["nodes"][0]["cohort"]="c1"; p["nodes"][1]["cohort"]="c1"
  obs=[{"name":"n1","drift":[{"severity":"critical"}]},{"name":"n2","drift":[{"severity":"critical"}]}]
  _,ok=m.evaluate_budget(p,obs); self.assertFalse(ok)
 def test_signing_preflight_before_probe(self):
  with tempfile.TemporaryDirectory() as d:
   p=plan(); p["evidence_signing_key"]="/definitely/missing/key"; called=[]; old=m.node_observation
   try:
    m.node_observation=lambda n,p:(called.append(n["name"]) or {"name":n["name"],"drift":[]})
    with self.assertRaises(m.GuardError):m.run_once(p,d)
    self.assertEqual(called,[])
   finally:m.node_observation=old
 def test_parse_float(self): self.assertEqual(m.parse_float("1.25\n"),1.25)
if __name__=="__main__":unittest.main()
