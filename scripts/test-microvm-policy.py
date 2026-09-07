#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Offline gates that do not need rustc / a cluster."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PolicySource(unittest.TestCase):
    def test_driven_by_skip_in_node_agent(self):
        src = (ROOT / "crates/fluxvm-microvm/src/node_agent.rs").read_text()
        self.assertIn("node_agent_should_drive", src)

    def test_converted_annotations_set(self):
        src = (ROOT / "crates/fluxvm-microvm/src/convert.rs").read_text()
        self.assertIn("converted_annotations", src)

    def test_shadow_uses_tiny_budget(self):
        src = (ROOT / "crates/fluxvm-microvm/src/shadow.rs").read_text()
        self.assertIn("SHADOW_CPU", src)
        self.assertIn("SHADOW_MEMORY", src)
        self.assertNotIn('Quantity(vm.spec.vcpus.to_string())', src)

    def test_policy_constants(self):
        src = (ROOT / "crates/fluxvm-microvm/src/policy.rs").read_text()
        self.assertIn('DRIVEN_BY_FLUXVM_KUBE: &str = "fluxvm-kube"', src)
        self.assertIn('SHADOW_CPU: &str = "10m"', src)
        self.assertIn('SHADOW_MEMORY: &str = "32Mi"', src)
        self.assertIn("microvm.fluxvm.zyvor.io/driven-by", src)

    def test_guest_image_modules(self):
        self.assertTrue((ROOT / "crates/fluxvm-microvm/src/images.rs").is_file())
        self.assertTrue((ROOT / "crates/fluxvm-microvm/src/guest_images.rs").is_file())
        main = (ROOT / "crates/fluxvm-microvm/src/main.rs").read_text()
        self.assertIn("guest_images::run", main)
        agent = (ROOT / "crates/fluxvm-microvm/src/node_agent.rs").read_text()
        self.assertIn("resolve_image", agent)
        self.assertIn("looks_like_direct_image", agent)


class Manifests(unittest.TestCase):
    def test_controller_convert_off(self):
        src = (ROOT / "deploy/k8s/microvm/controller.yaml").read_text()
        self.assertIn('command: ["fluxvm-microvm", "controller"]', src)
        self.assertNotIn("--convert", src.split("command:", 1)[-1])

    def test_crd_kinds(self):
        src = (ROOT / "deploy/k8s/microvm/crd.yaml").read_text()
        for kind in ("MicroVM", "MicroVMJob", "MicroVMPool", "GuestImage"):
            self.assertIn(f"kind: {kind}", src)

    def test_example_persist_false(self):
        src = (ROOT / "examples/microvm/microvm.yaml").read_text()
        self.assertIn("persist: false", src)
        self.assertIn("kind: MicroVM", src)

    def test_test_script_prints_crd(self):
        src = (ROOT / "scripts/test-microvm.sh").read_text()
        self.assertIn("cargo test -p fluxvm-microvm", src)
        self.assertIn("--print-crd", src)


if __name__ == "__main__":
    r = unittest.main(verbosity=2, exit=False)
    sys.exit(0 if r.result.wasSuccessful() else 1)
