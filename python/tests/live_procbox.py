# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Live check against a real daemon with ``[sandbox.procbox] enabled = true``.

    FLUXVM_LIVE_URL=http://127.0.0.1:17788 python3 -m unittest python/tests/live_procbox.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from fluxvm import ApiError, FluxVM, NotFound  # noqa: E402

URL = os.environ.get("FLUXVM_LIVE_URL")


@unittest.skipUnless(URL, "FLUXVM_LIVE_URL not set")
class LiveProcbox(unittest.TestCase):
    def test_flow(self):
        fx = FluxVM(URL, timeout=30)
        sb = fx.create_sandbox(name="py-live", ttl_seconds=300, procbox={"timeout_seconds": 20})
        try:
            sb.write_file("work/a.txt", "one")
            sb.write_file("work/b.txt", "two")
            self.assertEqual(sb.baseline(["/work"]).files, 2)
            self.assertEqual(sb.run("echo x > work/a.txt; rm work/b.txt; echo n > work/c.txt").exit_code, 0)
            ch = sb.changes()
            self.assertEqual((ch.added, ch.modified, ch.deleted),
                             (["/work/c.txt"], ["/work/a.txt"], ["/work/b.txt"]))
            out = sb.run("echo x > /tmp/py-live-escape && echo WROTE || echo BLOCKED")
            self.assertEqual(out.stdout.strip(), "BLOCKED")
            for bad in ("../../etc/passwd", "/etc/passwd", "a/../../x"):
                with self.assertRaises(ApiError):
                    sb.read_file(bad)
            dr = sb.dry_run("rm work/c.txt", paths=["/work"])
            self.assertTrue(dr["discarded"])
            self.assertEqual(dr["changes"]["deleted"], ["/work/c.txt"])
            self.assertEqual(sb.changes().added, ["/work/c.txt"])
            with self.assertRaises(ApiError) as cm:
                sb.snapshot("/tmp/x")
            self.assertEqual(cm.exception.status, 501)
        finally:
            sb.delete()
        with self.assertRaises(NotFound):
            fx.get_sandbox(sb.id)


if __name__ == "__main__":
    unittest.main()
