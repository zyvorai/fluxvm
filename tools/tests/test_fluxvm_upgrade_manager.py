#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import pathlib
import tempfile
import unittest

MOD_PATH = pathlib.Path(__file__).resolve().parents[1] / "fluxvm_upgrade_manager.py"
spec = importlib.util.spec_from_file_location("fluxvm_upgrade_manager", MOD_PATH)
m = importlib.util.module_from_spec(spec)
assert spec.loader
import sys
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.fail = set()
        self.maps = {}

    def add_map(self, pin, entries=None, map_type="hash", key_size=4, value_size=8, max_entries=32):
        self.maps[str(pin)] = {
            # Field names match real `bpftool -j map show pinned <path>`
            # output (confirmed against bpftool v7.4.0): bytes_key/
            # bytes_value, not key/value -- using the wrong names here let a
            # real ABI-validation bug (comparing against None on both sides)
            # slip past every test in this suite.
            "meta": {"type": map_type, "bytes_key": key_size, "bytes_value": value_size, "max_entries": max_entries},
            "entries": entries or [],
        }

    def run(self, argv, *, check=True, timeout=None, input_text=None):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key in self.fail:
            out = m.CmdResult(1, "", "forced failure")
            if check:
                raise m.CommandError(list(argv), 1, "", "forced failure")
            return out
        if argv[:3] == ["bpftool", "-j", "map"]:
            op = argv[3]
            pin = argv[-1]
            if op == "show":
                return m.CmdResult(0, json.dumps([self.maps[pin]["meta"]]), "")
            if op == "dump":
                return m.CmdResult(0, json.dumps(self.maps[pin]["entries"]), "")
        if argv[:3] == ["bpftool", "map", "delete"]:
            pin = argv[4]
            h = argv.index("hex")
            key_bytes = [int(x, 16) for x in argv[h + 1:]]
            self.maps[pin]["entries"] = [e for e in self.maps[pin]["entries"] if e.get("key") != key_bytes]
            return m.CmdResult(0, "", "")
        if argv[:3] == ["bpftool", "map", "update"]:
            pin = argv[4]
            kh = argv.index("hex")
            vh = argv.index("value") + 2
            key_bytes = [int(x, 16) for x in argv[kh + 1:argv.index("value")]]
            value_bytes = [int(x, 16) for x in argv[vh:-1]]
            entries = [e for e in self.maps[pin]["entries"] if e.get("key") != key_bytes]
            entries.append({"key": key_bytes, "value": value_bytes})
            self.maps[pin]["entries"] = entries
            return m.CmdResult(0, "", "")
        return m.CmdResult(0, "ok\n", "")


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.old_runner = m.RUNNER
        self.fake = FakeRunner()
        m.RUNNER = self.fake
        self.td = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.td.name)
        self.bpffs = self.root / "bpffs"
        self.repo = self.root / "repo"
        self.state = self.root / "state"
        self.bpffs.mkdir(); self.repo.mkdir()

    def tearDown(self):
        m.RUNNER = self.old_runner
        self.td.cleanup()

    def plan(self, comps=None):
        return m.validate_plan({
            "schema_version": 1,
            "transaction_id": "tx-001",
            "bpffs_root": str(self.bpffs),
            "repo_root": str(self.repo),
            "components": comps or [{
                "name": "intel",
                "preflight": ["preflight-ok"],
                "apply": ["apply-ok"],
                "health": ["health-ok"],
                "rollback": ["rollback-ok"],
            }],
        })

    def test_validate_rejects_path_escape_and_duplicate(self):
        with self.assertRaises(m.UpgradeError):
            m.validate_plan({"schema_version": 1, "transaction_id": "tx", "components": [{"name": "a", "files": ["../x"]}]})
        with self.assertRaises(m.UpgradeError):
            m.validate_plan({"schema_version": 1, "transaction_id": "tx", "components": [{"name": "a"}, {"name": "a"}]})

    def test_logical_state_abi_gate(self):
        ok = {
            "schema_version": 1, "transaction_id": "tx",
            "components": [{"name": "a", "state_abi": {"current": 2, "target": 3, "target_compatible_from": [2]}}],
        }
        self.assertEqual(3, m.validate_plan(ok)["components"][0]["state_abi"]["target"])
        bad = {
            "schema_version": 1, "transaction_id": "tx",
            "components": [{"name": "a", "state_abi": {"current": 1, "target": 3, "target_compatible_from": [2]}}],
        }
        with self.assertRaises(m.UpgradeError):
            m.validate_plan(bad)

    def test_success_restores_declared_map_state_before_health(self):
        pin = self.bpffs / "intel" / "vm_stats"
        pin.parent.mkdir(parents=True); pin.touch()
        original = [{"key": [1,0,0,0], "value": [9,0,0,0,0,0,0,0]}]
        self.fake.add_map(pin, original.copy())
        p = self.plan([{
            "name": "intel", "apply": ["apply-ok"], "health": ["health-ok"], "rollback": ["rollback-ok"],
            "maps": [{"pin":"intel/vm_stats","state":"merge","abi":{"type":"hash","key_size":4,"value_size":8}}],
        }])
        j = m.run_upgrade(p, state_dir=str(self.state))
        self.assertTrue(j["components"]["intel"]["state_restored"])
        update_i = next(i for i,c in enumerate(self.fake.calls) if c[:3] == ["bpftool","map","update"])
        health_i = self.fake.calls.index(["health-ok"])
        self.assertLess(update_i, health_i)

    def test_plan_hash_canonical(self):
        p1 = self.plan()
        p2 = dict(reversed(list(p1.items())))
        self.assertEqual(m.plan_hash(p1), m.plan_hash(p2))

    def test_success_is_idempotent(self):
        p = self.plan()
        j1 = m.run_upgrade(p, state_dir=str(self.state))
        self.assertEqual(j1["status"], "committed")
        before = len(self.fake.calls)
        j2 = m.run_upgrade(p, state_dir=str(self.state), resume=True)
        self.assertEqual(j2["status"], "committed")
        self.assertEqual(before, len(self.fake.calls))
        self.assertTrue((self.state / "tx-001" / "EVIDENCE.sha256").is_file())
        self.assertEqual([], m.verify_hash_manifest(self.state / "tx-001"))

    def test_plan_drift_rejected(self):
        p = self.plan()
        m.run_upgrade(p, state_dir=str(self.state))
        q = self.plan()
        q["components"][0]["health"] = ["different"]
        with self.assertRaises(m.UpgradeError):
            m.load_or_create_journal(self.state / "tx-001", q)

    def test_map_snapshot_restore_replace(self):
        pin = self.bpffs / "intel" / "vm_stats"
        pin.parent.mkdir(parents=True); pin.touch()
        original = [{"key": [1,0,0,0], "value": [9,0,0,0,0,0,0,0]}]
        self.fake.add_map(pin, original.copy())
        p = self.plan([{
            "name": "intel",
            "apply": ["apply-ok"], "health": ["health-ok"], "rollback": ["rollback-ok"],
            "maps": [{"pin": "intel/vm_stats", "state": "replace", "abi": {"type": "hash", "key_size": 4, "value_size": 8}}],
        }])
        d = m.tx_dir(p, str(self.state)); d.mkdir(parents=True)
        m.atomic_json(d / "plan.json", p)
        j = m.initial_journal(p); m.save_journal(d, j)
        m.component_snapshot(p, p["components"][0], d)
        self.fake.maps[str(pin)]["entries"] = [{"key": [2,0,0,0], "value": [7,0,0,0,0,0,0,0]}]
        out = m.component_restore(p, p["components"][0], d)
        self.assertIn("restored-1", out[0])
        self.assertEqual(original, self.fake.maps[str(pin)]["entries"])

    def test_map_abi_mismatch_rejected(self):
        pin = self.bpffs / "x"; pin.touch()
        self.fake.add_map(pin, [], key_size=8)
        spec = {"pin": "x", "state": "metadata-only", "abi": {"key_size": 4}}
        with self.assertRaises(m.UpgradeError):
            m.snapshot_map(self.bpffs, spec, self.root / "out")

    def test_byte_seq_accepts_real_bpftool_hex_string_list(self):
        # Real `bpftool -j map dump pinned <path>` (confirmed against
        # bpftool v7.4.0) encodes each byte as a hex *string* token, e.g.
        # ["0x01","0x00","0x00","0x00"] -- not a list of small integers and
        # not a single delimited string, which were the only two encodings
        # this function previously accepted.
        self.assertEqual(m.byte_seq(["0x01", "0x00", "0xaa", "0xff"], field="key"), [1, 0, 170, 255])

    def test_flatten_percpu_value_accepts_real_bpftool_hex_string_list(self):
        self.assertEqual(m.flatten_percpu_value(["0x11", "0x22", "0x33", "0x44"]), [17, 34, 51, 68])
        # A genuine per-cpu value (list of per-cpu objects) must still be
        # refused rather than misread as a flat byte array.
        self.assertIsNone(m.flatten_percpu_value([{"cpu": 0, "value": ["0x01"]}]))

    def test_failure_rolls_back_reverse_order(self):
        comps = [
            {"name": "a", "apply": ["apply-a"], "health": ["health-a"], "rollback": ["rollback-a"]},
            {"name": "b", "apply": ["apply-b"], "health": ["health-b"], "rollback": ["rollback-b"]},
        ]
        p = self.plan(comps)
        self.fake.fail.add(("health-b",))
        with self.assertRaises(m.CommandError):
            m.run_upgrade(p, state_dir=str(self.state))
        j = m.load_json(self.state / "tx-001" / "journal.json")
        self.assertEqual("rolled-back", j["status"])
        cmds = [c[0] for c in self.fake.calls if len(c) == 1]
        self.assertLess(cmds.index("rollback-b"), cmds.index("rollback-a"))

    def test_rollback_failure_marks_manual(self):
        p = self.plan([{"name": "a", "apply": ["apply-a"], "health": ["health-a"], "rollback": ["rollback-a"]}])
        self.fake.fail.add(("health-a",)); self.fake.fail.add(("rollback-a",))
        with self.assertRaises(m.UpgradeError):
            m.run_upgrade(p, state_dir=str(self.state))
        j = m.load_json(self.state / "tx-001" / "journal.json")
        self.assertEqual("manual-intervention", j["status"])

    def test_file_snapshot_restore(self):
        f = self.repo / "etc" / "config"; f.parent.mkdir(); f.write_text("old", encoding="utf-8")
        p = self.plan([{"name": "a", "files": ["etc/config"]}])
        d = m.tx_dir(p, str(self.state)); d.mkdir(parents=True)
        m.component_snapshot(p, p["components"][0], d)
        f.write_text("new", encoding="utf-8")
        m.component_restore(p, p["components"][0], d)
        self.assertEqual("old", f.read_text(encoding="utf-8"))

    def test_evidence_tamper_detected(self):
        p = self.plan(); j = m.run_upgrade(p, state_dir=str(self.state))
        d = self.state / "tx-001"
        (d / "journal.final.json").write_text("tamper", encoding="utf-8")
        self.assertTrue(m.verify_hash_manifest(d))

    def test_reconcile_rolls_back_stale(self):
        p = self.plan()
        d = m.tx_dir(p, str(self.state)); d.mkdir(parents=True)
        m.atomic_json(d / "plan.json", p)
        j = m.initial_journal(p)
        j["components"]["intel"]["applied"] = True
        j["components"]["intel"]["snapshotted"] = False
        j["updated_at"] = "2020-01-01T00:00:00+00:00"
        m.save_journal(d, j)
        out = m.reconcile(self.state, 1)
        self.assertEqual("rolled-back", out[0]["action"])

    def test_probe_reports_permission_denied_instead_of_crashing(self):
        # pathlib.Path.exists() only swallows ENOENT-style errors and
        # re-raises PermissionError -- a real FluxVM bpffs pin root is 0700
        # root-owned by design, so `probe` (meant to be runnable
        # unprivileged, to check host readiness before a privileged `run`)
        # must not crash just because the caller lacks root.
        class DeniedPath(pathlib.Path):
            def exists(self, *, follow_symlinks=True):
                raise PermissionError(13, "Permission denied", str(self))

        self.assertEqual(m.path_status(DeniedPath("/sys/fs/bpf/fluxvm")), "permission-denied")
        self.assertIn(m.path_status(pathlib.Path(self.bpffs)), (True, False))


if __name__ == "__main__":
    unittest.main()
