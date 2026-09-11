# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
import importlib.util, json, os, sys, tempfile, unittest, uuid
from pathlib import Path
P=Path(__file__).parents[1]/'fluxvm_migration_orchestrator.py'
spec=importlib.util.spec_from_file_location('m',P); m=importlib.util.module_from_spec(spec); sys.modules['m']=m; spec.loader.exec_module(m)
class T(unittest.TestCase):
    def plan(self,root,fail_migrate=False):
        fake=root/'fake'; fake.mkdir(exist_ok=True); log=root/'calls.log'
        def cmd(name,body):
            p=fake/name; p.write_text('#!/bin/sh\nset -eu\necho "'+name+' $*" >> "'+str(log)+'"\n'+body+'\n'); p.chmod(0o755)
        cmd('fluxvm',"""case \"$*\" in \"dataplane migration-export \"*) while [ \"$#\" -gt 0 ]; do if [ \"$1\" = \"--output\" ]; then shift; printf '{\"network\":1}\\n' > \"$1\"; break; fi; shift; done;; *) :;; esac""")
        cmd('fluxvm-quiclb',"""case \"$1\" in affinity-export) printf '{\"affinity\":1}\\n' > \"$3\";; esac"""); cmd('fluxvm-afxdp',':'); cmd('fluxvm-topology',':'); cmd('fluxvm-scx',':')
        mig=fake/'vmm-migrate'; mig.write_text('#!/bin/sh\necho vmm-migrate >> "'+str(log)+'"\n'+('exit 9' if fail_migrate else 'exit 0')+'\n'); mig.chmod(0o755)
        rb=fake/'vmm-rollback'; rb.write_text('#!/bin/sh\necho vmm-rollback >> "'+str(log)+'"\nexit 0\n'); rb.chmod(0o755)
        old=os.environ.get('PATH',''); os.environ['PATH']=str(fake)+os.pathsep+old; self.addCleanup(lambda:os.environ.__setitem__('PATH',old))
        vm=str(uuid.uuid4()); qi=str(uuid.uuid4())
        return {'schema_version':1,'migration_id':'test-mig','vm_id':vm,'source':{},'destination':{},'automatic_rollback':True,'vmm':{'migrate_argv':[str(mig),'{vm_id}'],'rollback_argv':[str(rb),'{vm_id}']},'quiclb':{'instance_id':qi,'optional':False},'afxdp':{'enabled':True,'source_plan':str(root/'src-afxdp.json'),'destination_plan':str(root/'dst-afxdp.json'),'optional':False},'topology':{'enabled':True,'source_plan':str(root/'src-topo.json'),'destination_plan':str(root/'dst-topo.json'),'optional':False},'scx':{'enabled':True,'source_plan':str(root/'src-scx.json'),'destination_plan':str(root/'dst-scx.json'),'optional':False}},log
    def test_validate_rejects_bad_uuid(self):
        p={'schema_version':1,'migration_id':'x','vm_id':'bad','source':{},'destination':{},'vmm':{'migrate_argv':['true']}}
        with self.assertRaises(m.MigrationError): m.validate_plan(p)
    def test_redaction(self): self.assertEqual(m.redact_list(['x','--token','abc','z']),['x','--token','<redacted>','z'])
    def test_redaction_equals(self): self.assertEqual(m.redact_list(['x','--token=abc']),['x','--token=<redacted>'])
    def test_plan_drift_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p,log=self.plan(root); m.Orchestrator(p,root/'state').run(); p2=dict(p); p2['automatic_rollback']=False
            with self.assertRaises(m.MigrationError): m.Orchestrator(p2,root/'state').run()
    def test_success_is_resumable(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p,log=self.plan(root); s=m.Orchestrator(p,root/'state').run(); self.assertEqual(s['status'],'complete'); before=log.read_text(); s2=m.Orchestrator(p,root/'state').run(); self.assertEqual(s2['status'],'complete'); self.assertEqual(before,log.read_text()); self.assertTrue((root/'state/test-mig/EVIDENCE.sha256').exists())
    def test_failure_before_vmm_rolls_back_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p,log=self.plan(root,True)
            with self.assertRaises(m.MigrationError): m.Orchestrator(p,root/'state').run()
            j=json.loads((root/'state/test-mig/journal.json').read_text()); self.assertEqual(j['status'],'rolled-back'); calls=log.read_text(); self.assertIn('fluxvm dataplane migration-resume',calls); self.assertNotIn('vmm-rollback',calls)
    def test_post_migrate_failure_without_rollback_requires_manual_intervention(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); p,log=self.plan(root); p['vmm'].pop('rollback_argv')
            o=m.Orchestrator(p,root/'state'); o.restore_destination=lambda: (_ for _ in ()).throw(m.MigrationError('restore failed'))
            with self.assertRaises(m.MigrationError): o.run()
            j=json.loads((root/'state/test-mig/journal.json').read_text()); self.assertEqual(j['status'],'manual-intervention')
    def test_lock_exclusion(self):
        with tempfile.TemporaryDirectory() as td:
            j1=m.Journal(Path(td),'x').lock()
            try:
                with self.assertRaises(BlockingIOError): m.Journal(Path(td),'x').lock()
            finally: j1.close()
    def test_remote_path_guard(self):
        with self.assertRaises(m.MigrationError): m.validate_remote_path('/tmp/../etc/passwd')
if __name__=='__main__': unittest.main()
