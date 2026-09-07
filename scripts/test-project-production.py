#!/usr/bin/env python3
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProjectProduction(unittest.TestCase):
    def test_required_docs(self):
        for p in (
            "SECURITY.md",
            "CONTRIBUTING.md",
            "Makefile",
            "docs/PRODUCTION.md",
            "docs/production-dataplane.md",
            "SECURITY.md",
        ):
            self.assertTrue((ROOT / p).is_file(), p)

    def test_readyz_route_present(self):
        api = (ROOT / "crates/fluxvm-api/src/lib.rs").read_text()
        self.assertIn("/readyz", api)

    def test_tenant_field_present(self):
        model = (ROOT / "crates/fluxvm-core/src/model.rs").read_text()
        self.assertIn("pub tenant: Option<String>", model)

    def test_prod_checklist_covers_planes(self):
        text = (ROOT / "docs/PRODUCTION.md").read_text()
        for needle in ("auth.require", "network-fabric-prod", "Kubernetes", "Catalog", "/readyz"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
