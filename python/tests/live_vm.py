# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Live check of a VM sandbox against a real daemon (KVM host, golden template).

Needs the golden guest from ``scripts/setup-native-agent-template.sh`` and a
daemon with ``fluxvm_engine = "kvm"``:

    FLUXVM_LIVE_URL=http://127.0.0.1:7788 python3 -m unittest python/tests/live_vm.py
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from fluxvm import ApiError, FluxVM, NotFound  # noqa: E402

URL = os.environ.get("FLUXVM_LIVE_URL")
SPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "examples",
                    "fluxvm-native-agent.json")


@unittest.skipUnless(URL, "FLUXVM_LIVE_URL not set")
class LiveVm(unittest.TestCase):
    def test_change_set_through_the_guest_agent(self):
        fx = FluxVM(URL, timeout=60)
        with open(SPEC) as f:
            spec = json.load(f)
        spec["name"] = "live-vm-spec"
        sb = fx.create_sandbox(name="py-live-vm", ttl_seconds=900, spec=spec)
        try:
            deadline = time.time() + 180
            hostname = None
            while time.time() < deadline:
                try:
                    r = sb.run("hostname", timeout=10)
                    if r.exit_code == 0:
                        hostname = r.stdout.strip()
                        break
                except ApiError:
                    pass
                time.sleep(2)
            self.assertEqual(hostname, "native-agent", "guest agent did not answer with the NoCloud hostname")

            sb.write_file("/root/work/a.txt", "one")
            sb.write_file("/root/work/b.txt", "two")
            self.assertEqual(sb.baseline(["/root/work"]).files, 2)
            r = sb.run("echo changed > /root/work/a.txt; rm /root/work/b.txt; echo n > '/root/work/new file.txt'",
                       timeout=10)
            self.assertEqual(r.exit_code, 0, r.stderr)
            ch = sb.changes()
            self.assertEqual(ch.added, ["/root/work/new file.txt"])
            self.assertEqual(ch.modified, ["/root/work/a.txt"])
            self.assertEqual(ch.deleted, ["/root/work/b.txt"])
            self.assertEqual(sb.read_text("/root/work/a.txt").strip(), "changed")
            # Dry-run on a VM reverts memory and disk through snapshot/restore.
            dr = sb.dry_run("echo x > /root/work/dry.txt; rm /root/work/a.txt", timeout=30,
                            paths=["/root/work"])
            self.assertTrue(dr["discarded"])
            self.assertEqual(dr["reverted_via"], "snapshot")
            self.assertEqual(dr["changes"]["added"], ["/root/work/dry.txt"])
            self.assertEqual(dr["changes"]["deleted"], ["/root/work/a.txt"])
            self.assertEqual(sb.read_text("/root/work/a.txt").strip(), "changed")
            self.assertTrue(sb.run("test ! -e /root/work/dry.txt", timeout=10).exit_code == 0)
        finally:
            sb.delete()
        with self.assertRaises(NotFound):
            fx.get_sandbox(sb.id)


if __name__ == "__main__":
    unittest.main()
