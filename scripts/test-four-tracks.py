#!/usr/bin/env python3
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FourTracks(unittest.TestCase):
    def test_oidc_module(self):
        text = (ROOT / "crates/fluxvm-api/src/oidc.rs").read_text()
        self.assertIn("OidcValidator", text)
        self.assertIn("JWKS", text)

    def test_mtls_headers(self):
        api = (ROOT / "crates/fluxvm-api/src/lib.rs").read_text()
        self.assertIn("x-client-cert-cn", api)
        self.assertIn("mtls_enabled", api)

    def test_hubble_routes(self):
        api = (ROOT / "crates/fluxvm-api/src/lib.rs").read_text()
        self.assertIn("/v1/network/hubble/ui", api)
        self.assertIn("/v1/network/endpoints", api)

    def test_ch_qga_serial(self):
        ch = (ROOT / "crates/fluxvm-cloud-hypervisor/src/lib.rs").read_text()
        self.assertIn("qga.sock", ch)
        self.assertIn("socket=", ch)

    def test_kvm_lock(self):
        mem = (ROOT / "crates/fluxvm-hypervisor/src/memory.rs").read_text()
        self.assertIn("FLUXVM_KVM_LOCK_MEM", mem)
        self.assertIn("MAP_POPULATE", mem)


if __name__ == "__main__":
    unittest.main()
