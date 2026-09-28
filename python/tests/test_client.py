import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import mock_server  # noqa: E402
from fluxvm import (  # noqa: E402
    ApiError, AuthError, ConnectionFailed, ForbiddenError, FluxVM, NotFound,
    RateLimited, RequestTimeout, Volume,
)
from fluxvm.client import MAX_FILE_TRANSFER_BYTES  # noqa: E402


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.state, cls.url = mock_server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.state.sandboxes.clear()
        self.state.files.clear()
        self.state.requests.clear()
        self.state.rate_limit_next = False
        self.state.exec_delay = 0.0
        self.fx = FluxVM(self.url, token=mock_server.ADMIN, timeout=5)

    def last(self):
        return self.state.requests[-1]

    @staticmethod
    def header(headers, name):
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    # ---- create / list / auth
    def test_create_sends_only_set_fields_and_bearer_token(self):
        sb = self.fx.create_sandbox(name="demo", ttl_seconds=60, memory_mib=256,
                                    http_proxy_ports=[8080, 9090],
                                    volumes=[Volume("data", "/data"), {"name": "x", "guest_path": "/mnt/x"}],
                                    confidential="auto")
        method, path, headers, body = self.state.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/sandboxes"))
        self.assertEqual(self.header(headers, "Authorization"), "Bearer " + mock_server.ADMIN)
        sent = json.loads(body)
        self.assertEqual(sent["name"], "demo")
        self.assertEqual(sent["ttl_seconds"], 60)
        self.assertEqual(sent["http_proxy_ports"], [8080, 9090])
        self.assertEqual(sent["volumes"][0], {"name": "data", "guest_path": "/data", "read_only": False})
        self.assertEqual(sent["confidential"], "auto")
        for absent in ("template", "spec", "vcpus", "http_proxy_port"):
            self.assertNotIn(absent, sent)
        self.assertEqual(sb.info.name, "demo")
        self.assertEqual(sb.info.status, "running")
        self.assertEqual(sb.info.guest_ip, "10.0.0.2")
        self.assertEqual(sb.info.confidential["requested"], "auto")

    def test_create_rejects_bad_confidential_mode_locally(self):
        with self.assertRaises(ValueError):
            self.fx.create_sandbox(confidential="yes")
        self.assertEqual(self.state.requests, [])

    def test_server_validation_error_is_api_error_with_status_and_body(self):
        with self.assertRaises(ApiError) as cm:
            self.fx.create_sandbox(template="missing")
        self.assertEqual(cm.exception.status, 400)
        self.assertEqual(cm.exception.message, "template missing not found")
        self.assertEqual(cm.exception.body, {"error": "template missing not found"})

    def test_list_sandboxes(self):
        a = self.fx.create_sandbox(name="a")
        b = self.fx.create_sandbox(name="b")
        self.assertEqual({s.id for s in self.fx.list_sandboxes()}, {a.id, b.id})

    def test_missing_or_bad_token_is_auth_error(self):
        for token in (None, "wrong"):
            with self.assertRaises(AuthError) as cm:
                FluxVM(self.url, token=token).list_sandboxes()
            self.assertEqual(cm.exception.status, 401)
            self.assertNotIsInstance(cm.exception, ForbiddenError)

    def test_readonly_token_is_forbidden_on_admin_routes(self):
        ro = FluxVM(self.url, token=mock_server.READONLY)
        self.assertEqual(ro.list_sandboxes(), [])
        with self.assertRaises(ForbiddenError) as cm:
            ro.create_sandbox()
        self.assertEqual(cm.exception.status, 403)
        self.assertIsInstance(cm.exception, AuthError)

    def test_unauthenticated_endpoints(self):
        anon = FluxVM(self.url)
        self.assertTrue(anon.health())
        self.assertEqual(anon.openapi()["openapi"], "3.0.0")

    def test_extra_headers_are_sent(self):
        FluxVM(self.url, token=mock_server.ADMIN, headers={"X-Client-Cert-CN": "ci"}).list_sandboxes()
        self.assertEqual(self.header(self.last()[2], "X-Client-Cert-CN"), "ci")

    def test_rate_limited_exposes_retry_after(self):
        self.state.rate_limit_next = True
        with self.assertRaises(RateLimited) as cm:
            self.fx.list_sandboxes()
        self.assertEqual(cm.exception.status, 429)
        self.assertEqual(cm.exception.retry_after, 7.0)

    def test_host_confidential(self):
        self.assertFalse(self.fx.host_confidential()["launch_supported"])

    # ---- lookup / delete / context manager
    def test_get_sandbox_and_refresh(self):
        sb = self.fx.create_sandbox(name="x")
        again = self.fx.get_sandbox(sb.id)
        self.assertEqual(again.id, sb.id)
        self.assertEqual(again.refresh().status, "running")

    def test_unknown_sandbox_is_not_found(self):
        with self.assertRaises(NotFound) as cm:
            self.fx.get_sandbox("00000000-0000-0000-0000-000000000000")
        self.assertEqual(cm.exception.message, "VM not found")

    def test_context_manager_deletes_and_tolerates_already_gone(self):
        with self.fx.create_sandbox() as sb:
            sid = sb.id
            self.assertIn(sid, self.state.sandboxes)
        self.assertNotIn(sid, self.state.sandboxes)
        self.assertEqual(self.last()[:2], ("DELETE", "/v1/vms/" + sid))
        with self.fx.create_sandbox() as sb:
            del self.state.sandboxes[sb.id]  # deleted behind our back: __exit__ must not raise

    def test_delete_error_other_than_not_found_propagates(self):
        sb = self.fx.create_sandbox()
        with self.assertRaises(ForbiddenError):
            type(sb)(FluxVM(self.url, token=mock_server.READONLY), sb.info).delete()

    # ---- process
    def test_run_string_and_timeout_field(self):
        sb = self.fx.create_sandbox()
        r = sb.run("echo hi", timeout=5)
        self.assertTrue(r.ok)
        self.assertEqual(r.stdout, "hi\n")
        self.assertEqual(json.loads(self.last()[3]), {"command": "echo hi", "timeout_seconds": 5})

    def test_run_list_is_shell_quoted_and_default_timeout_omitted(self):
        sb = self.fx.create_sandbox()
        sb.run(["echo", "a b", "c'd"])
        sent = json.loads(self.last()[3])
        self.assertEqual(sent, {"command": "echo 'a b' 'c'\"'\"'d'"})

    def test_run_nonzero_exit_is_a_result_not_an_error(self):
        sb = self.fx.create_sandbox()
        r = sb.run("false")
        self.assertFalse(r.ok)
        self.assertEqual(r.exit_code, 3)
        self.assertEqual(sb.run("sleep 60", timeout=1).exit_code, 124)

    def test_guest_agent_error_is_api_error(self):
        sb = self.fx.create_sandbox()
        with self.assertRaises(ApiError) as cm:
            sb.run("agent-error")
        self.assertEqual(cm.exception.status, 400)
        self.assertIn("guest agent error", cm.exception.message)

    def test_process_on_deleted_sandbox_is_not_found(self):
        sb = self.fx.create_sandbox()
        del self.state.sandboxes[sb.id]
        with self.assertRaises(NotFound):
            sb.run("echo hi")

    # ---- files
    def test_write_read_roundtrip_bytes_str_and_mode(self):
        sb = self.fx.create_sandbox()
        blob = bytes(range(256))
        sb.write_file("/tmp/blob", blob, mode=0o600)
        sent = json.loads(self.last()[3])
        self.assertEqual(sent["mode"], 0o600)
        self.assertEqual(sb.read_file("/tmp/blob"), blob)
        self.assertEqual(sb.read_file_info("/tmp/blob").mode, 0o600)
        sb.write_file("/tmp/t.txt", "héllo")
        self.assertNotIn("mode", json.loads(self.last()[3]))
        self.assertEqual(sb.read_text("/tmp/t.txt"), "héllo")

    def test_read_missing_file_is_api_error(self):
        sb = self.fx.create_sandbox()
        with self.assertRaises(ApiError) as cm:
            sb.read_file("/nope")
        self.assertEqual(cm.exception.status, 400)

    def test_write_over_transfer_limit_is_rejected_locally(self):
        sb = self.fx.create_sandbox()
        n = len(self.state.requests)
        with self.assertRaises(ValueError):
            sb.write_file("/big", b"\0" * (MAX_FILE_TRANSFER_BYTES + 1))
        self.assertEqual(len(self.state.requests), n)

    # ---- snapshot
    def test_snapshot(self):
        sb = self.fx.create_sandbox()
        self.assertEqual(sb.snapshot("/var/lib/fluxvm/snap1"), "/var/lib/fluxvm/snap1")
        self.assertEqual(json.loads(self.last()[3]), {"path": "/var/lib/fluxvm/snap1"})

    def test_unknown_vm_answered_400_maps_to_not_found(self):
        from fluxvm.client import _error_from_response
        err = _error_from_response(400, b'{"error":"VM not found"}', {})
        self.assertIsInstance(err, NotFound)
        self.assertEqual(err.status, 400)
        self.assertNotIsInstance(_error_from_response(400, b'{"error":"bad path"}', {}), NotFound)

    def test_procbox_create_option_and_dry_run(self):
        sb = self.fx.create_sandbox(name="pb", procbox={"timeout_seconds": 5})
        self.assertEqual(json.loads(self.state.requests[0][3])["procbox"], {"timeout_seconds": 5})
        sb2 = self.fx.create_sandbox(procbox={})
        self.assertEqual(json.loads(self.state.requests[-1][3])["procbox"], {})
        out = sb.dry_run("touch x", timeout=3, paths=["/"])
        self.assertTrue(out["discarded"])
        self.assertEqual(out["changes"]["added"], ["/x"])
        self.assertEqual(json.loads(self.last()[3]), {"command": "touch x", "timeout_seconds": 3, "paths": ["/"]})

    # ---- change-set
    def test_baseline_then_changes_reports_added_modified_deleted(self):
        sb = self.fx.create_sandbox()
        sb.write_file("/workspace/keep.txt", "same")
        sb.write_file("/workspace/edit.txt", "v1")
        sb.write_file("/workspace/gone.txt", "bye")
        base = sb.baseline(["/workspace"])
        self.assertEqual((base.files, base.mode, base.paths), (3, "sha256", ["/workspace"]))
        self.assertEqual(json.loads(self.last()[3]), {"paths": ["/workspace"]})
        sb.write_file("/workspace/edit.txt", "v2")
        sb.write_file("/workspace/new.txt", "hi")
        self.state.files[sb.id].pop("/workspace/gone.txt")
        ch = sb.changes()
        self.assertEqual(ch.added, ["/workspace/new.txt"])
        self.assertEqual(ch.modified, ["/workspace/edit.txt"])
        self.assertEqual(ch.deleted, ["/workspace/gone.txt"])
        self.assertEqual(ch.unchanged, 1)
        self.assertFalse(ch.clean)
        self.assertEqual(json.loads(self.last()[3]), {})

    def test_changes_can_narrow_to_a_subset_of_paths(self):
        sb = self.fx.create_sandbox()
        sb.write_file("/a/x", "1")
        sb.write_file("/b/y", "1")
        sb.baseline(["/a", "/b"])
        sb.write_file("/a/x", "2")
        sb.write_file("/b/y", "2")
        ch = sb.changes(paths=["/a"])
        self.assertEqual(ch.modified, ["/a/x"])
        self.assertEqual(json.loads(self.last()[3]), {"paths": ["/a"]})

    def test_clean_changeset_and_missing_baseline(self):
        sb = self.fx.create_sandbox()
        with self.assertRaises(NotFound):
            sb.changes()
        sb.write_file("/w/f", "1")
        sb.baseline(["/w"])
        self.assertTrue(sb.changes().clean)

    def test_baseline_rejects_unsafe_paths_with_api_error(self):
        sb = self.fx.create_sandbox()
        with self.assertRaises(ApiError) as cm:
            sb.baseline(["relative/../x"])
        self.assertEqual(cm.exception.status, 400)

    # ---- http proxy
    def test_http_explicit_port_with_query_body_and_headers(self):
        sb = self.fx.create_sandbox()
        r = sb.http(8080, "post", "/api/items", body={"a": 1}, params={"q": "x y", "n": [1, 2]},
                    headers={"X-Test": "1"})
        self.assertEqual(self.last()[:2][0], "POST")
        self.assertTrue(self.last()[1].startswith("/v1/sandboxes/{}/http/8080/api/items?".format(sb.id)))
        seen = r.json()
        self.assertEqual(seen["port"], "8080")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(json.loads(seen["body"]), {"a": 1})
        self.assertEqual(seen["ctype"], "application/json")
        self.assertEqual(seen["x_test"], "1")
        self.assertEqual(r.headers["X-Guest"], "yes")
        self.assertIn("q=x+y", seen["query"])

    def test_http_default_port_route_and_raw_body(self):
        sb = self.fx.create_sandbox()
        r = sb.http(None, "PUT", "index.html", body="plain")
        self.assertEqual(self.last()[1], "/sandbox/{}/index.html".format(sb.id))
        self.assertEqual(r.json()["port"], "default")
        self.assertEqual(r.json()["ctype"], "text/plain; charset=utf-8")
        self.assertEqual(r.json()["body"], "plain")

    def test_http_bytes_body_is_octet_stream_and_caller_content_type_wins(self):
        sb = self.fx.create_sandbox()
        self.assertEqual(sb.http(80, "POST", "/u", body=b"\x00\x01").json()["ctype"],
                         "application/octet-stream")
        r = sb.http(80, "POST", "/u", body=b"a=1", headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(r.json()["ctype"], "application/x-www-form-urlencoded")

    def test_http_guest_status_is_returned_not_raised(self):
        sb = self.fx.create_sandbox()
        r = sb.http(80, "GET", "/missing")
        self.assertEqual(r.status, 404)
        self.assertFalse(r.ok)
        with self.assertRaises(ApiError):
            r.raise_for_status()
        proxy_err = sb.http(80, "GET", "/boom")
        self.assertEqual(proxy_err.status, 502)
        self.assertIn("timed out", proxy_err.text())

    def test_http_does_not_follow_redirects(self):
        sb = self.fx.create_sandbox()
        r = sb.http(80, "GET", "/redirect")
        self.assertEqual(r.status, 302)
        self.assertEqual(r.headers["Location"], "/elsewhere")

    def test_http_needs_admin(self):
        sb = self.fx.create_sandbox()
        ro = FluxVM(self.url, token=mock_server.READONLY)
        r = type(sb)(ro, sb.info).http(80, "GET", "/x")
        self.assertEqual(r.status, 403)

    # ---- transport failures
    def test_timeout(self):
        sb = self.fx.create_sandbox()
        with self.assertRaises(RequestTimeout):
            sb.http(80, "GET", mock_server.SLOW_PATH, timeout=0.2)

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(ConnectionFailed):
            FluxVM("http://127.0.0.1:{}".format(port), timeout=1).health()

    def test_base_url_trailing_slash_and_empty(self):
        self.assertTrue(FluxVM(self.url + "/").health())
        with self.assertRaises(ValueError):
            FluxVM("")


if __name__ == "__main__":
    unittest.main()
