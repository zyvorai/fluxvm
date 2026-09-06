#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).with_name("export_network_flows.py")
spec = importlib.util.spec_from_file_location("flux_export", MODULE)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


class FlowExporterTests(unittest.TestCase):
    def flow(self, packets=1, bytes_=64, last=10, family=4):
        return {
            "identity": 7,
            "family": family,
            "source": "10.0.0.2" if family == 4 else "2001:db8::2",
            "destination": "1.1.1.1" if family == 4 else "2001:4860:4860::8888",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": 6,
            "verdict": "allow",
            "packets": packets,
            "bytes": bytes_,
            "last_seen_ns": last,
        }

    def test_first_observation_emits(self):
        seen = {}
        f = self.flow()
        self.assertEqual(mod.changed_flows([f], seen), [f])

    def test_unchanged_observation_is_deduplicated(self):
        seen = {}
        f = self.flow()
        mod.changed_flows([f], seen)
        self.assertEqual(mod.changed_flows([f], seen), [])

    def test_counter_advance_emits_again(self):
        seen = {}
        mod.changed_flows([self.flow()], seen)
        newer = self.flow(packets=2, bytes_=128, last=20)
        self.assertEqual(mod.changed_flows([newer], seen), [newer])

    def test_ipv4_and_ipv6_are_distinct(self):
        seen = {}
        changed = mod.changed_flows([self.flow(family=4), self.flow(family=6)], seen)
        self.assertEqual(len(changed), 2)


if __name__ == "__main__":
    unittest.main()
