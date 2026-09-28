"""In-process stand-in for the FluxVM API, mirroring crates/fluxvm-api/src/lib.rs.

Behaviour copied from the real handlers:
- ``Authorization: Bearer <token>`` -> role; missing/unknown -> 401
  ``{"error": "missing or invalid bearer token"}``; /healthz and
  /v1/openapi.json need no token.
- sandbox routes need the admin role (403 ``{"error": "admin role required"}``).
- handler failures (validation, guest agent errors) are 400 ``{"error": ...}``.
- unknown / other-tenant sandbox ids -> 404 ``{"error": "VM not found"}``.
- exec/file responses use the guest-protocol tags (``result``: exec,
  file-written, file-content).
"""

import base64
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ADMIN = "admin-token"
READONLY = "readonly-token"
SLOW_PATH = "/slow"


class MockState:
    def __init__(self):
        self.lock = threading.Lock()
        self.sandboxes = {}
        self.files = {}
        self.requests = []  # (method, path, headers dict, body bytes)
        self.rate_limit_next = False
        self.exec_delay = 0.0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state = None  # set by start()

    def log_message(self, *args):  # silence
        pass

    # ---- helpers
    def _send(self, status, body=b"", headers=None, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        if status != 204:
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if status != 204:
            self.wfile.write(body)

    def _err(self, status, message, headers=None):
        self._send(status, {"error": message}, headers)

    def _role(self):
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else None
        return {ADMIN: "admin", READONLY: "read-only"}.get(token)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _sandbox(self, sid):
        try:
            uuid.UUID(sid)
        except ValueError:
            return None
        return self.state.sandboxes.get(sid)

    # ---- dispatch
    def _handle(self, method):
        st = self.state
        parts = urlsplit(self.path)
        path = parts.path
        raw = self._body()
        with st.lock:
            st.requests.append((method, self.path, dict(self.headers.items()), raw))

        if path == "/healthz":
            return self._send(200, {"ok": True})
        if path == "/v1/openapi.json":
            return self._send(200, {"openapi": "3.0.0"})
        role = self._role()
        if role is None:
            return self._err(401, "missing or invalid bearer token")
        if st.rate_limit_next:
            st.rate_limit_next = False
            return self._err(429, "rate limit exceeded", {"Retry-After": "7"})

        if path == "/v1/host/confidential" and method == "GET":
            return self._send(200, {"sev_snp": False, "tdx": False, "launch_supported": False})

        if path == "/v1/sandboxes" and method == "GET":
            return self._send(200, {"items": list(st.sandboxes.values())})

        if path == "/v1/sandboxes" and method == "POST":
            if role != "admin":
                return self._err(403, "admin role required")
            req = json.loads(raw or b"{}")
            if req.get("template") == "missing":
                return self._err(400, "template missing not found")
            sid = str(uuid.uuid4())
            rec = {
                "id": sid,
                "name": req.get("name") or "sandbox-" + sid,
                "backend": "fluxvm",
                "status": "running",
                "pid": 4242,
                "guest_ip": "10.0.0.2",
                "created_at": "2026-09-28T10:00:00Z",
                "expires_at": None,
                "request": req,
            }
            if req.get("confidential"):
                rec["confidential"] = {"requested": req["confidential"], "active": False}
            st.sandboxes[sid] = rec
            return self._send(201, rec)

        segs = path.strip("/").split("/")
        # /v1/vms/{id}: GET / DELETE
        if len(segs) == 3 and segs[:2] == ["v1", "vms"]:
            rec = self._sandbox(segs[2])
            if rec is None:
                return self._err(404, "VM not found")
            if method == "GET":
                return self._send(200, rec)
            if method == "DELETE":
                if role != "admin":
                    return self._err(403, "admin role required")
                del st.sandboxes[segs[2]]
                return self._send(204)
            return self._err(405, "method not allowed")

        # /sandbox/{id}/{path}  (default port)
        if segs[0] == "sandbox" and len(segs) >= 3:
            return self._proxy(role, method, segs[1], "default", "/".join(segs[2:]), parts.query, raw)

        if segs[:2] == ["v1", "sandboxes"] and len(segs) >= 4:
            sid, op = segs[2], segs[3]
            if self._sandbox(sid) is None:
                return self._err(404, "VM not found")
            if op == "http" and len(segs) >= 6:
                return self._proxy(role, method, sid, segs[4], "/".join(segs[5:]), parts.query, raw)
            if method != "POST":
                return self._err(405, "method not allowed")
            if role != "admin":
                return self._err(403, "admin role required")
            body = json.loads(raw or b"{}")
            if op == "snapshot":
                return self._send(200, {"ok": True, "path": body["path"]})
            if op == "baseline" and len(segs) == 4:
                return self._baseline(sid, body)
            if op == "changes" and len(segs) == 4:
                return self._changes(sid, body)
            if op == "process" and len(segs) == 4:
                return self._process(sid, body)
            if op == "fs" and len(segs) == 5:
                return self._fs(sid, segs[4], body)
        return self._err(404, "no such route")

    # Change-set: the mock keeps {path: content} per sandbox in `state.files`
    # (written through fs/write) and diffs it, mirroring the real routes'
    # statuses: 400 bad paths, 404 no baseline.
    def _baseline(self, sid, body):
        paths = body.get("paths") or []
        if not paths or any((not p.startswith("/")) or ".." in p.split("/") for p in paths):
            return self._err(400, "invalid baseline paths")
        files = getattr(self.state, "files", {}).get(sid, {})
        snap = {f: c for f, c in files.items() if any(f.startswith(p.rstrip("/") + "/") for p in paths)}
        if not hasattr(self.state, "baselines"):
            self.state.baselines = {}
        self.state.baselines[sid] = (sorted(paths), dict(snap))
        return self._send(200, {"ok": True, "files": len(snap), "mode": "sha256", "paths": sorted(paths)})

    def _changes(self, sid, body):
        base = getattr(self.state, "baselines", {}).get(sid)
        if base is None:
            return self._err(404, "no baseline recorded for this sandbox")
        paths, before = base
        want = body.get("paths") or paths
        files = getattr(self.state, "files", {}).get(sid, {})
        def under(f):
            return any(f.startswith(p.rstrip("/") + "/") for p in want)
        now = {f: c for f, c in files.items() if under(f)}
        before = {f: c for f, c in before.items() if under(f)}
        added = sorted(f for f in now if f not in before)
        deleted = sorted(f for f in before if f not in now)
        modified = sorted(f for f in now if f in before and now[f] != before[f])
        return self._send(200, {
            "added": added, "modified": modified, "deleted": deleted,
            "unchanged": len(now) - len(added) - len(modified),
            "mode": "sha256", "paths": sorted(want), "baseline_taken_at_unix": 1790585116,
        })

    def _process(self, sid, body):
        cmd = body["command"]
        timeout = body.get("timeout_seconds")
        if self.state.exec_delay:
            time.sleep(self.state.exec_delay)
        if cmd.startswith("agent-error"):
            return self._err(400, "guest agent error: boom")
        if cmd.startswith("sleep") and timeout is not None and int(cmd.split()[1]) > timeout:
            return self._send(200, {"result": "exec", "exit_code": 124, "stdout": "", "stderr": "timed out"})
        if cmd.startswith("echo "):
            return self._send(200, {"result": "exec", "exit_code": 0,
                                    "stdout": cmd[5:] + "\n", "stderr": "",
                                    "timeout_seconds": timeout})
        return self._send(200, {"result": "exec", "exit_code": 3, "stdout": "", "stderr": "cmd: " + cmd})

    def _fs(self, sid, op, body):
        files = self.state.files.setdefault(sid, {})
        path = body["path"]
        if op == "write":
            files[path] = (base64.b64decode(body["content_base64"]), body.get("mode", 0o644))
            return self._send(200, {"result": "file-written"})
        if op == "read":
            if path not in files:
                return self._err(400, "guest agent error: no such file: " + path)
            data, mode = files[path]
            return self._send(200, {"result": "file-content",
                                    "content_base64": base64.b64encode(data).decode(), "mode": mode})
        return self._err(404, "no such route")

    def _proxy(self, role, method, sid, port, rest, query, raw):
        if role != "admin":
            return self._err(403, "admin role required")
        if self._sandbox(sid) is None:
            return self._err(404, "VM not found")
        if "/" + rest == SLOW_PATH:
            time.sleep(1.0)
        if rest == "redirect":
            return self._send(302, b"", {"Location": "/elsewhere"})
        if rest == "boom":
            return self._send(502, "guest upstream: connecting timed out", ctype="text/plain")
        payload = {"port": port, "method": method, "path": "/" + rest, "query": query,
                   "body": raw.decode("utf-8", errors="replace"),
                   "ctype": self.headers.get("Content-Type"),
                   "x_test": self.headers.get("X-Test")}
        status = 404 if rest == "missing" else 200
        return self._send(status, payload, {"X-Guest": "yes"})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self): self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")


def start():
    """Start a server on an ephemeral port; returns (server, state, base_url)."""
    state = MockState()
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, state, "http://127.0.0.1:{}".format(server.server_address[1])
