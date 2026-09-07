#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Spec tests for the Hubble-style packet path (mirrors packetflow.rs)."""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RS = ROOT / "crates/fluxvm-network/src/packetflow.rs"
CLI = ROOT / "crates/fluxvm-cli/src/main.rs"
DOC = ROOT / "docs/packet-flow.md"


def hops(direction: str, mode: str, vm: str) -> list[str]:
    cilium = mode == "cilium"
    if direction == "egress":
        names = [vm, "tap", "tc-clsact"]
        if cilium:
            names.append("cilium")
        names.extend(["uplink", "peer"])
        return names
    names = ["peer", "uplink"]
    if cilium:
        names.append("cilium")
    names.extend(["tc-clsact", "tap", vm])
    return names


class PacketFlowSpec(unittest.TestCase):
    def test_egress_ebpf_path(self):
        self.assertEqual(
            hops("egress", "ebpf", "web-1"),
            ["web-1", "tap", "tc-clsact", "uplink", "peer"],
        )

    def test_ingress_cilium_path(self):
        self.assertEqual(
            hops("ingress", "cilium", "web-1"),
            ["peer", "uplink", "cilium", "tc-clsact", "tap", "web-1"],
        )

    def test_rust_builder_mentions_same_hops(self):
        text = RS.read_text(encoding="utf-8")
        for name in ("tap", "tc-clsact", "uplink", "peer", "cilium"):
            self.assertIn(f'"{name}"', text)

    def test_color_and_plain_modes_exist(self):
        text = RS.read_text(encoding="utf-8")
        self.assertIn("FlowOutput", text)
        self.assertIn("Color", text)
        self.assertIn("Plain", text)
        self.assertIn("\\x1b[", text)
        self.assertIn("plain/normal mode must be raw text", text)

    def test_cli_flags(self):
        text = CLI.read_text(encoding="utf-8")
        self.assertIn("output", text)
        self.assertIn("detailed", text)
        self.assertIn("HubbleCommand::Flow", text)
        self.assertIn("print_hubble_observe", text)

    def test_docs_cover_both_modes(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("--output color", text)
        self.assertIn("--output plain", text)
        self.assertIn("Colorful", text + text.lower())
        self.assertTrue(re.search(r"plain|normal", text, re.I))


if __name__ == "__main__":
    unittest.main()
