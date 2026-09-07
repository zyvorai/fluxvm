#!/usr/bin/env python3
"""Control-plane checks for security-group identity and merge rules.

Mirrors crates/fluxvm-network/src/groups.rs so the PR can be validated
without the workspace's Rust 1.85+/edition-2024 toolchain.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


GROUP_IDENTITY_BASE = 0x10000


def normalize_label(raw: str) -> str:
    s = raw.strip()
    if not s or len(s) > 128:
        raise ValueError("bad label")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=/. -_:".replace(" ", ""))
    # keep hyphen underscore colon slash dot equals alnum only
    for c in s:
        if not (c.isalnum() or c in "=/. -_:" and c != " "):
            if c in "=/. -_:":
                continue
            raise ValueError(s)
        if c == " ":
            raise ValueError(s)
    if any(c.isspace() for c in s):
        raise ValueError(s)
    return s


def identity_for_labels(labels: list[str]) -> int:
    sset = sorted({normalize_label(l) for l in labels})
    h = 0xCBF29CE484222325
    for lab in sset:
        for b in lab.encode():
            h ^= b
            h = (h * 0x100000001B3) & ((1 << 64) - 1)
        h ^= 0xFF
        h = (h * 0x100000001B3) & ((1 << 64) - 1)
    return GROUP_IDENTITY_BASE + (h & 0x7FFFFFFF)


def merge(vm: dict, groups: list[dict]) -> dict:
    allow, deny, ports = set(vm.get("allow_cidrs", [])), set(vm.get("deny_cidrs", [])), set(vm.get("allow_ports", []))
    default_allow = vm.get("default_allow", True)
    allow_icmp = vm.get("allow_icmp", False)
    mbps = vm.get("max_egress_mbps")
    pps = vm.get("max_egress_pps")
    sample = vm.get("sample_rate", 0)
    vm_labels = set(vm.get("labels", []))
    named = set(vm.get("groups", []))
    matched = []
    for g in groups:
        if g["name"] in named or (g["labels"] and set(g["labels"]).issubset(vm_labels)):
            matched.append(g)
            p = g["policy"]
            allow.update(p.get("allow_cidrs", []))
            deny.update(p.get("deny_cidrs", []))
            ports.update(p.get("allow_ports", []))
            if not p.get("default_allow", True):
                default_allow = False
            allow_icmp = allow_icmp or p.get("allow_icmp", False)
            if p.get("max_egress_mbps") is not None:
                mbps = p["max_egress_mbps"] if mbps is None else min(mbps, p["max_egress_mbps"])
            if p.get("max_egress_pps") is not None:
                pps = p["max_egress_pps"] if pps is None else min(pps, p["max_egress_pps"])
            sample = max(sample, p.get("sample_rate", 0))
    return {
        "allow_cidrs": sorted(allow),
        "deny_cidrs": sorted(deny),
        "allow_ports": sorted(ports),
        "default_allow": default_allow,
        "allow_icmp": allow_icmp,
        "max_egress_mbps": mbps,
        "max_egress_pps": pps,
        "sample_rate": sample,
        "matched": [g["name"] for g in matched],
    }


class GroupTests(unittest.TestCase):
    def test_identity_stable(self):
        a = identity_for_labels(["app=web", "env=prod"])
        b = identity_for_labels(["env=prod", "app=web"])
        self.assertEqual(a, b)
        self.assertGreaterEqual(a, GROUP_IDENTITY_BASE)

    def test_label_subset_merge(self):
        groups = [{
            "name": "web",
            "labels": ["app=web"],
            "policy": {
                "default_allow": False,
                "allow_cidrs": ["10.0.0.0/8"],
                "allow_ports": ["tcp/443"],
                "allow_icmp": True,
                "max_egress_mbps": 50,
            },
        }]
        out = merge({"labels": ["app=web", "tier=front"], "max_egress_mbps": 250}, groups)
        self.assertIn("10.0.0.0/8", out["allow_cidrs"])
        self.assertFalse(out["default_allow"])
        self.assertTrue(out["allow_icmp"])
        self.assertEqual(out["max_egress_mbps"], 50)
        self.assertEqual(out["matched"], ["web"])

    def test_named_group_without_labels(self):
        groups = [{
            "name": "egress",
            "labels": [],
            "policy": {"allow_cidrs": ["1.1.1.1/32"], "deny_cidrs": ["0.0.0.0/0"], "default_allow": False},
        }]
        out = merge({"groups": ["egress"]}, groups)
        self.assertIn("0.0.0.0/0", out["deny_cidrs"])

    def test_example_json_shape(self):
        root = Path(__file__).resolve().parents[1]
        raw = json.loads((root / "examples/security-group-web.json").read_text())
        self.assertEqual(raw["name"], "web")
        self.assertIn("app=web", raw["labels"])
        self.assertTrue(raw["policy"]["allow_icmp"])

    def test_rejects_spaces(self):
        with self.assertRaises(ValueError):
            normalize_label("app web")


if __name__ == "__main__":
    unittest.main()
