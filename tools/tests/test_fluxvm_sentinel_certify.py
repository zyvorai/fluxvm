#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
import pathlib
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve()
MOD_PATH = HERE.parents[1] / "fluxvm-sentinel-certify.py"
spec = importlib.util.spec_from_file_location("cert", MOD_PATH)
cert = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(cert)


class CertificationTests(unittest.TestCase):
    def test_tcx_detection_is_kernel_version_based_not_bpftool_blob(self):
        # `bpftool feature probe kernel [full] -j` does not report TCX at
        # all, at any privilege level -- confirmed empirically against a
        # real kernel that does support TCX. A regression back to
        # substring-searching the bpftool JSON for "tcx" would silently
        # report `False` unconditionally on every host, including ones
        # that genuinely support it (as this one does).
        probe = cert.probe_capabilities()
        kernel = cert._kernel_version_tuple()
        self.assertEqual(probe["capabilities"]["tcx"], kernel >= (6, 6, 0))

    def test_budget_max_and_min(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            budgets = d / "b.json"
            measures = d / "m.json"
            budgets.write_text(json.dumps({"schema_version": 1, "profiles": {"x": {"required_capabilities": [], "optional_capabilities": [], "budgets": {"lat": {"max": 2}, "bw": {"min": 5}}}}}))
            measures.write_text(json.dumps({"schema_version": 1, "metrics": {"lat": 1.5, "bw": 6}}))
            out = cert.evaluate("x", budgets, measures, True)
            self.assertTrue(out["pass"])

    def test_missing_metric_is_failure_when_required(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            budgets = d / "b.json"
            budgets.write_text(json.dumps({"schema_version": 1, "profiles": {"x": {"required_capabilities": [], "optional_capabilities": [], "budgets": {"lat": {"max": 2}}}}}))
            out = cert.evaluate("x", budgets, None, True)
            self.assertFalse(out["pass"])
            self.assertEqual(out["metrics"][0]["status"], "missing")

    def test_reconcile_requires_magic_and_dead_pid(self):
        # Manifests live in a tree mirroring target_root, never inside it --
        # a real bpffs target_root has no create() for plain files (only
        # `mkdir` and BPF-object pins), confirmed against a real kernel.
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "target"
            manifests = pathlib.Path(td) / "manifests"
            (root / "dead").mkdir(parents=True)
            (manifests / "dead").mkdir(parents=True)
            (manifests / "dead" / ".fluxvm-owner.json").write_text(json.dumps({"owner_magic": cert.OWNER_MAGIC, "owner_pid": 99999999, "component": "test", "created_unix": time.time() - 3600}))
            (root / "foreign").mkdir(parents=True)
            (manifests / "foreign").mkdir(parents=True)
            (manifests / "foreign" / ".fluxvm-owner.json").write_text(json.dumps({"owner_magic": "foreign", "owner_pid": 99999999, "created_unix": time.time() - 3600}))
            out = cert.reconcile(root, manifest_root=manifests, min_age_seconds=1, dry_run=True)
            actions = {pathlib.Path(x["manifest"]).parent.name: x["action"] for x in out["actions"]}
            self.assertEqual(actions["dead"], "would-remove")
            self.assertEqual(actions["foreign"], "skip")

    def test_reconcile_apply_removes_only_owned_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "target"
            manifests = pathlib.Path(td) / "manifests"
            owned = root / "dead"
            owned.mkdir(parents=True)
            (owned / "pin").write_text("x")
            manifest_dir = manifests / "dead"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / ".fluxvm-owner.json").write_text(json.dumps({"owner_magic": cert.OWNER_MAGIC, "owner_pid": 99999999, "component": "test", "created_unix": time.time() - 3600}))
            out = cert.reconcile(root, manifest_root=manifests, min_age_seconds=1, dry_run=False)
            self.assertEqual(out["errors"], 0)
            self.assertFalse(owned.exists())
            self.assertFalse((manifest_dir / ".fluxvm-owner.json").exists())

    def test_write_owner_manifest_mirrors_target_not_colocated(self):
        # write_owner_manifest must never write into `target` itself.
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "target"
            manifests = pathlib.Path(td) / "manifests"
            target = root / "vms" / "abc"
            target.mkdir(parents=True)
            path = cert.write_owner_manifest(target, os.getpid(), "test", target_root=root, manifest_root=manifests)
            self.assertEqual(path, manifests / "vms" / "abc" / ".fluxvm-owner.json")
            self.assertTrue(path.exists())
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
