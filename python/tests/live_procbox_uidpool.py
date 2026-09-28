# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Live checks of the procbox uid pool against a daemon started as ROOT.

Each class needs its own daemon (see docs/procbox-backend.md, "Verified live
with a root daemon"):

    FLUXVM_LIVE_URL=http://127.0.0.1:17791 FLUXVM_UID_BASE=231000 \\
    FLUXVM_UID_COUNT=16 FLUXVM_STATE_DIR=/tmp/ws3-state \\
        python3 -m unittest python/tests/live_procbox_uidpool.py -k Pool

    FLUXVM_NOPOOL_URL=...   daemon with uid_count = 0, allow_root = false
    FLUXVM_NOPOOL_OLD_ID=... a sandbox id created earlier without a uid
    FLUXVM_ALLOWROOT_URL=... daemon with uid_count = 0, allow_root = true
"""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from fluxvm import ApiError, FluxVM  # noqa: E402

URL = os.environ.get("FLUXVM_LIVE_URL")
BASE = int(os.environ.get("FLUXVM_UID_BASE", "0"))
COUNT = int(os.environ.get("FLUXVM_UID_COUNT", "0"))
STATE = os.environ.get("FLUXVM_STATE_DIR", "")


def ids(sb):
    r = sb.run("id -u; id -g; id -G")
    assert r.exit_code == 0, r
    uid, gid, groups = r.stdout.split("\n")[:3]
    return int(uid), int(gid), groups.strip()


@unittest.skipUnless(URL and BASE and COUNT, "FLUXVM_LIVE_URL / FLUXVM_UID_BASE / FLUXVM_UID_COUNT not set")
class Pool(unittest.TestCase):
    def setUp(self):
        self.fx = FluxVM(URL, timeout=60)
        self.made = []

    def tearDown(self):
        for sb in self.made:
            try:
                sb.delete()
            except Exception:
                pass

    def make(self, **procbox):
        procbox.setdefault("timeout_seconds", 25)
        sb = self.fx.create_sandbox(name="uidpool", ttl_seconds=300, procbox=procbox)
        self.made.append(sb)
        return sb

    def test_each_sandbox_runs_as_its_own_unprivileged_uid(self):
        a, b = self.make(), self.make()
        ua, ga, groups_a = ids(a)
        ub, gb, groups_b = ids(b)
        self.assertNotEqual(ua, ub)
        for u, g, groups in ((ua, ga, groups_a), (ub, gb, groups_b)):
            self.assertTrue(BASE <= u < BASE + COUNT, u)
            self.assertEqual(g, u)
            self.assertEqual(groups, str(u), "no supplementary groups")
        self.assertEqual(ids(a)[0], ua, "the uid is stable per sandbox")
        caps = a.run("grep CapEff /proc/self/status 2>/dev/null || echo none").stdout
        self.assertTrue("none" in caps or "0000000000000000" in caps, caps)

    def test_a_sandbox_cannot_reach_another_workspace(self):
        a, b = self.make(), self.make()
        b.write_file("secret.txt", "TOP-SECRET-B")
        self.assertEqual(b.read_file("secret.txt"), b"TOP-SECRET-B")
        path = "%s/instances/%s/files/secret.txt" % (STATE, b.id)
        r = a.run("cat %s; echo rc=$?; ls %s/instances; echo rc=$?" % (path, STATE))
        self.assertNotIn("TOP-SECRET-B", r.stdout + r.stderr)
        self.assertNotIn("rc=0", r.stdout)
        # A's own files are owned by A's uid and hidden from B.
        a.write_file("mine.txt", "A-DATA")
        rb = b.run("cat %s/instances/%s/files/mine.txt" % (STATE, a.id))
        self.assertNotIn("A-DATA", rb.stdout)
        self.assertNotEqual(rb.exit_code, 0)

    def test_api_written_files_belong_to_the_sandbox_uid(self):
        a = self.make()
        a.write_file("dir/sub/f.txt", "hello", mode=0o600)
        uid = ids(a)[0]
        r = a.run("stat -c '%u %a' dir dir/sub dir/sub/f.txt")
        self.assertEqual(r.exit_code, 0, r)
        for line in r.stdout.split("\n")[:3]:
            self.assertEqual(line.split()[0], str(uid), r.stdout)
        self.assertEqual(a.run("cat dir/sub/f.txt").stdout, "hello")
        self.assertEqual(a.run("echo more >> dir/sub/f.txt").exit_code, 0)
        self.assertEqual(a.read_file("dir/sub/f.txt"), b"hello" + b"more\n")

    def test_fork_bomb_in_one_sandbox_leaves_another_working(self):
        a = self.make(max_processes=40)
        b = self.make()
        result = {}

        def bomb():
            result["a"] = a.run(
                "for i in $(seq 1 400); do (sleep 6) & done; wait; echo bomb-done", timeout=25)

        t = threading.Thread(target=bomb)
        t.start()
        time.sleep(2)
        try:
            for _ in range(5):
                r = b.run("for i in $(seq 1 30); do (sleep 0.2) & done; wait; echo b-ok")
                self.assertEqual((r.exit_code, r.stdout.strip()), (0, "b-ok"), r)
        finally:
            t.join()
        ra = result["a"]
        self.assertIn("fork", (ra.stderr + ra.stdout).lower(), "A must hit its own limit")

    def test_workspace_flow_and_escapes_still_hold(self):
        sb = self.make()
        sb.write_file("work/a.txt", "one")
        sb.write_file("work/b.txt", "two")
        self.assertEqual(sb.baseline(["/work"]).files, 2)
        self.assertEqual(sb.run("echo x > work/a.txt; rm work/b.txt; echo n > work/c.txt").exit_code, 0)
        ch = sb.changes()
        self.assertEqual((ch.added, ch.modified, ch.deleted),
                         (["/work/c.txt"], ["/work/a.txt"], ["/work/b.txt"]))
        dr = sb.dry_run("rm work/c.txt; echo z > work/z.txt", paths=["/work"])
        self.assertTrue(dr["discarded"])
        self.assertEqual(dr["changes"]["deleted"], ["/work/c.txt"])
        self.assertEqual(dr["changes"]["added"], ["/work/z.txt"])
        self.assertEqual(sb.changes().added, ["/work/c.txt"], "dry-run left the workspace alone")
        for bad in ("../../etc/passwd", "/etc/passwd", "a/../../x"):
            with self.assertRaises(ApiError) as cm:
                sb.read_file(bad)
            self.assertEqual(cm.exception.status, 400)
        # A symlink the sandbox creates cannot redirect the API outside.
        self.assertEqual(sb.run("ln -s /etc/passwd leak; ln -s /etc etcdir").exit_code, 0)
        for bad in ("leak", "etcdir/passwd"):
            with self.assertRaises(ApiError) as cm:
                sb.read_file(bad)
            self.assertIn(cm.exception.status, (400, 404))
        with self.assertRaises(ApiError):
            sb.write_file("leak", "clobber")
        out = sb.run("echo x > /etc/ws3-escape && echo WROTE || echo BLOCKED")
        self.assertEqual(out.stdout.strip(), "BLOCKED")

    def test_pool_exhaustion_is_a_503_and_deleting_frees_a_uid(self):
        for _ in range(COUNT):
            self.make()
        with self.assertRaises(ApiError) as cm:
            self.make()
        self.assertEqual(cm.exception.status, 503, cm.exception)
        self.assertIn("exhausted", str(cm.exception))
        self.made.pop(0).delete()
        again = self.make()
        self.assertTrue(BASE <= ids(again)[0] < BASE + COUNT)


@unittest.skipUnless(os.environ.get("FLUXVM_NOPOOL_URL"), "FLUXVM_NOPOOL_URL not set")
class NoPool(unittest.TestCase):
    def test_create_is_503(self):
        fx = FluxVM(os.environ["FLUXVM_NOPOOL_URL"], timeout=30)
        with self.assertRaises(ApiError) as cm:
            fx.create_sandbox(name="nopool", procbox={})
        self.assertEqual(cm.exception.status, 503, cm.exception)
        self.assertIn("root", str(cm.exception))

    @unittest.skipUnless(os.environ.get("FLUXVM_NOPOOL_OLD_ID"), "FLUXVM_NOPOOL_OLD_ID not set")
    def test_exec_on_a_uid_less_sandbox_is_503(self):
        fx = FluxVM(os.environ["FLUXVM_NOPOOL_URL"], timeout=30)
        sb = fx.get_sandbox(os.environ["FLUXVM_NOPOOL_OLD_ID"])
        with self.assertRaises(ApiError) as cm:
            sb.run("id -u")
        self.assertEqual(cm.exception.status, 503, cm.exception)


@unittest.skipUnless(os.environ.get("FLUXVM_ALLOWROOT_URL"), "FLUXVM_ALLOWROOT_URL not set")
class AllowRoot(unittest.TestCase):
    def test_allow_root_opts_back_in(self):
        fx = FluxVM(os.environ["FLUXVM_ALLOWROOT_URL"], timeout=30)
        sb = fx.create_sandbox(name="allowroot", ttl_seconds=120, procbox={"timeout_seconds": 15})
        try:
            r = sb.run("id -u; grep CapEff /proc/self/status 2>/dev/null || echo nocaps")
            self.assertEqual(r.exit_code, 0, r)
            self.assertEqual(r.stdout.split("\n")[0], "0")
            sb.write_file("f.txt", "x")
            self.assertEqual(sb.run("cat f.txt").stdout, "x")
        finally:
            sb.delete()


if __name__ == "__main__":
    unittest.main()
