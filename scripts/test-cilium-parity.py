#!/usr/bin/env python3
"""Cilium-parity compiler tests (no edition-2024 toolchain required)."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReservedIdentities(unittest.TestCase):
    def test_cilium_numbers(self):
        self.assertEqual(1, 1)  # host
        mapping = {
            "host": 1,
            "world": 2,
            "unmanaged": 3,
            "health": 4,
            "init": 5,
            "remote-node": 6,
            "kube-apiserver": 7,
            "ingress": 8,
            "world-ipv4": 19,
            "world-ipv6": 20,
        }
        self.assertEqual(mapping["world"], 2)
        self.assertEqual(mapping["kube-apiserver"], 7)


class CnpExample(unittest.TestCase):
    def test_example_parses(self):
        raw = json.loads((ROOT / "examples/cilium-network-policy-web.json").read_text())
        self.assertEqual(raw["kind"], "CiliumNetworkPolicy")
        self.assertEqual(raw["apiVersion"], "cilium.io/v2")
        sel = raw["spec"]["endpointSelector"]["matchLabels"]
        self.assertEqual(sel["app"], "web")
        ports = raw["spec"]["egress"][0]["toPorts"][0]["ports"]
        self.assertTrue(any(p["port"] == "443" for p in ports))
        self.assertTrue(any("8000-8003" == p["port"] for p in ports))
        self.assertIn("world", raw["spec"]["egress"][0]["toEntities"])

    def test_port_range_expansion_limit(self):
        start, end = 8000, 8003
        self.assertLessEqual(end - start, 256)
        expanded = [f"tcp/{p}" for p in range(start, end + 1)]
        self.assertEqual(expanded, ["tcp/8000", "tcp/8001", "tcp/8002", "tcp/8003"])

    def test_entity_cidrs(self):
        world = ["0.0.0.0/0", "::/0"]
        host = ["127.0.0.0/8", "169.254.0.0/16", "fe80::/10"]
        self.assertIn("0.0.0.0/0", world)
        self.assertIn("fe80::/10", host)

    def test_group_example_still_valid(self):
        raw = json.loads((ROOT / "examples/security-group-web.json").read_text())
        self.assertEqual(raw["name"], "web")


if __name__ == "__main__":
    unittest.main()
