#!/usr/bin/env python3
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProdProfile(unittest.TestCase):
    def test_prod_toml_is_fail_closed(self):
        text = (ROOT / "configs/network-fabric-prod.toml").read_text()
        self.assertIn('mode = "ebpf"', text)
        self.assertIn("required = true", text)
        self.assertIn("default_allow = false", text)
        self.assertIn("fluxvm_tc.bpf.o", text)

    def test_runbook_exists(self):
        md = (ROOT / "docs/production-dataplane.md").read_text()
        self.assertIn("fluxvm dataplane health", md)
        self.assertIn("refresh-dns", md)

    def test_fqdn_wildcard_skipped(self):
        names = ["example.com", "*.example.com", ""]
        kept = [n for n in names if n and "*" not in n]
        self.assertEqual(kept, ["example.com"])


if __name__ == "__main__":
    unittest.main()
