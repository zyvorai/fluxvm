#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]


class FluxvmDevopsLayoutTests(unittest.TestCase):
    def test_contract_json(self):
        data = json.loads(
            (REPO / "docs/contracts/fabric-fluxvm-readyz.json").read_text(encoding="utf-8")
        )
        self.assertEqual(data["fluxvm"]["healthz"]["path"], "/healthz")
        self.assertEqual(data["fluxvm"]["readyz"]["path"], "/readyz")
        self.assertIn("/healthz", data["fluxvm"]["healthz"]["path"])

    def test_prod_spec_has_tenant(self):
        spec = json.loads((REPO / "examples/create-vm-prod.json").read_text(encoding="utf-8"))
        self.assertIn("tenant", spec)
        self.assertIn("backend", spec)
        self.assertIn("image", spec)

    def test_gitops_kustomize_exists(self):
        path = REPO / "deploy/k8s/gitops/kustomization.yaml"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        self.assertIn("../namespace.yaml", text)


if __name__ == "__main__":
    unittest.main()
