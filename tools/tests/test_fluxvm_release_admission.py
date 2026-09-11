#!/usr/bin/env python3
import hashlib, importlib.util, json, pathlib, sys, tempfile, unittest

HERE=pathlib.Path(__file__).resolve()
MOD_PATH=HERE.parents[1]/"fluxvm_release_admission.py"
spec=importlib.util.spec_from_file_location("fluxvm_release_admission", MOD_PATH)
m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)


def hfile(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def base_plan(td):
    art=pathlib.Path(td)/"sentinel.tar.zst"; art.write_bytes(b"candidate-v17")
    ev=pathlib.Path(td)/"cert.json"; ev.write_text(json.dumps({"status":"pass","metrics":{"p99_us":90},"profile":"strict"}))
    return {
      "schema_version":1,"admission_id":"release-a","candidate":{"release_id":"sentinel-17.0","artifact_path":str(art),"artifact_sha256":hfile(art),"state_abis":{"network":"v8","scheduler":"scx-v1"}},
      "evidence":[{"name":"ga-cert","kind":"json","path":str(ev),"sha256":hfile(ev),"assertions":[{"pointer":"/status","op":"eq","value":"pass"},{"pointer":"/metrics/p99_us","op":"le","value":100}]}],
      "nodes":[{"name":"n1","host":"node1","cohort":"x86","required_capabilities":["kernel_btf"]},{"name":"n2","host":"node2","cohort":"x86","required_capabilities":["kernel_btf"]}],
      "compatibility":{"allowed_from_state_abis":{"network":["v7"],"scheduler":["legacy"]}},
      "policy":{"required_capabilities":["bpftool"],"min_reachable_percent":100,"min_compatible_percent":100,"max_unreachable_nodes":0,"min_nodes_per_cohort":1,"max_parallel":2,"admission_ttl_seconds":3600}
    }

class AdmissionTests(unittest.TestCase):
    def test_validate_duplicate_node(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); p["nodes"].append(dict(p["nodes"][0]))
            with self.assertRaises(m.AdmissionError): m.validate(p)

    def test_candidate_integrity(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); self.assertTrue(m.verify_candidate(p)["ok"])
            pathlib.Path(p["candidate"]["artifact_path"]).write_bytes(b"tampered")
            self.assertFalse(m.verify_candidate(p)["ok"])

    def test_json_evidence_assertions(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); r=m.verify_evidence_entry(p["evidence"][0]); self.assertTrue(r["ok"])
            p["evidence"][0]["assertions"][1]["value"]=50
            self.assertFalse(m.verify_evidence_entry(p["evidence"][0])["ok"])

    def test_manifest_directory_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            d=pathlib.Path(td)/"e"; d.mkdir(); run=d/"run.json"; run.write_text('{"status":"pass"}\n')
            manifest={"schema_version":1,"files":[{"file":"run.json","sha256":hfile(run)}]}; (d/"manifest.json").write_text(json.dumps(manifest))
            e={"name":"strict","kind":"evidence-dir","path":str(d),"document":"run.json","assertions":[{"pointer":"/status","op":"eq","value":"pass"}]}
            self.assertTrue(m.verify_evidence_entry(e)["ok"]); run.write_text('{"status":"fail"}\n')
            with self.assertRaises(m.AdmissionError): m.verify_evidence_entry(e)

    def test_node_abi_compatibility(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td)
            old=m.remote_capture
            inv={"kernel":"6.12.0","arch":"x86_64","capabilities":{"kernel_btf":True,"bpftool":True},"release":{"state_abis":{"network":"v7","scheduler":"legacy"}}}
            m.remote_capture=lambda *a,**k:m.Result(0,json.dumps(inv),"")
            try:
                r=m.node_probe(p["nodes"][0],p); self.assertTrue(r["compatible"])
                inv["release"]["state_abis"]["network"]="v3"
                r=m.node_probe(p["nodes"][0],p); self.assertFalse(r["compatible"]); self.assertEqual(r["reasons"][0]["kind"],"incompatible-state-abi")
            finally: m.remote_capture=old

    def test_evaluate_cohort_budget(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); c={"ok":True}; e=[{"name":"x","ok":True}]
            obs=[{"name":"n1","cohort":"x86","reachable":True,"compatible":True},{"name":"n2","cohort":"x86","reachable":False,"compatible":False}]
            self.assertFalse(m.evaluate(p,obs,c,e)["ok"])
            p["policy"].update({"min_reachable_percent":50,"min_compatible_percent":50,"max_unreachable_nodes":1})
            self.assertTrue(m.evaluate(p,obs,c,e)["ok"])

    def test_local_failure_skips_network(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); pathlib.Path(p["candidate"]["artifact_path"]).write_bytes(b"bad")
            old=m.node_probe; m.node_probe=lambda *_: (_ for _ in ()).throw(AssertionError("network called"))
            try:
                got=m.collect(p); self.assertFalse(got["decision"]["ok"]); self.assertEqual(got["observations"][0]["reasons"][0]["kind"],"probe-skipped-local-gate")
            finally: m.node_probe=old

    def test_admit_and_verify_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); old=m.node_probe
            m.node_probe=lambda n,pl:{"name":n["name"],"host":n["host"],"cohort":n.get("cohort","default"),"reachable":True,"compatible":True,"reasons":[],"inventory":{"kernel":"6.12","arch":"x86_64","capabilities":{"kernel_btf":True,"bpftool":True},"release":{"state_abis":{"network":"v7","scheduler":"legacy"}}}}
            try:
                out=m.do_evaluate(p,td,True); self.assertTrue(out["admitted"])
                v=m.verify_bundle(pathlib.Path(td)/p["admission_id"],require_admitted=True); self.assertTrue(v["ok"]); self.assertTrue(v["admitted"])
            finally: m.node_probe=old

    def test_denied_never_admitted(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); old=m.node_probe
            m.node_probe=lambda n,pl:{"name":n["name"],"host":n["host"],"cohort":"x86","reachable":True,"compatible":False,"reasons":[{"kind":"missing-capability"}],"inventory":{}}
            try:
                with self.assertRaises(m.AdmissionError): m.do_evaluate(p,td,True)
                with open(pathlib.Path(td)/p["admission_id"]/"admission.json", encoding="utf-8") as f: rec=json.load(f)
                self.assertFalse(rec["admitted"])
            finally: m.node_probe=old

    def test_bundle_tamper_detection(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); collected={"candidate":m.verify_candidate(p),"evidence":[m.verify_evidence_entry(p["evidence"][0])],"observations":[{"name":"n1","cohort":"x86","reachable":True,"compatible":True},{"name":"n2","cohort":"x86","reachable":True,"compatible":True}],"decision":{"ok":True}}
            d=m.write_bundle(p,td,collected,True); (d/"evaluation.json").write_text("{}\n")
            with self.assertRaises(m.AdmissionError): m.verify_bundle(d)

    def test_signing_preflight_before_network(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); p["evidence_signing_key"]=str(pathlib.Path(td)/"missing")
            old=m.node_probe; m.node_probe=lambda *_: (_ for _ in ()).throw(AssertionError("probe called"))
            try:
                with self.assertRaises(m.AdmissionError): m.do_evaluate(p,td,False)
            finally: m.node_probe=old


    def test_signed_record_requires_signature(self):
        with tempfile.TemporaryDirectory() as td:
            p=base_plan(td); collected={"candidate":m.verify_candidate(p),"evidence":[m.verify_evidence_entry(p["evidence"][0])],"observations":[{"name":"n1","cohort":"x86","reachable":True,"compatible":True},{"name":"n2","cohort":"x86","reachable":True,"compatible":True}],"decision":{"ok":True}}
            # Build unsigned first, then mark signature required and refresh the manifest hashes.
            d=m.write_bundle(p,td,collected,True)
            with open(d/"admission.json", encoding="utf-8") as f: rec=json.load(f)
            rec["signature_required"]=True; m.atomic_json(d/"admission.json",rec,0o640)
            with open(d/"manifest.json", encoding="utf-8") as f: manifest=json.load(f)
            for ent in manifest["files"]:
                if ent["file"]=="admission.json": ent["sha256"]=m.sha_file(d/"admission.json")
            m.atomic_json(d/"manifest.json",manifest,0o640)
            with self.assertRaises(m.AdmissionError): m.verify_bundle(d,require_admitted=True)

    def test_json_pointer_escape(self):
        self.assertEqual(m.json_pointer({"a/b":{"~x":7}},"/a~1b/~0x"),7)

if __name__ == "__main__": unittest.main()
