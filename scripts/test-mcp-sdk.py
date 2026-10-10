#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""End-to-end MCP check: drive a built `fluxctl mcp serve` with the official
MCP Python SDK client against a fake FluxVM REST API.

Usage: scripts/test-mcp-sdk.py path/to/fluxctl
Requires: pip install mcp
"""

import asyncio
import json
import os
import re
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOKEN = "ci-secret"
VM_ID = str(uuid.uuid4())
VM = {
    "id": VM_ID,
    "name": "web",
    "status": "running",
    "backend": "qemu",
    "guest_ip": "10.0.0.5",
    "request": {"vcpus": 2, "memory_mib": 1024, "labels": {"env": "dev"}},
}
STOPS = []

READ_TOOLS = {"list_vms", "get_vm", "host_status", "vm_network", "vm_logs", "backup_list", "sandbox_read_file",
              "sandbox_logs", "vm_snapshot_list", "vm_screenshot"}
WRITE_TOOLS = {
    "vm_power", "vm_capture", "vm_fork", "image_import", "vm_backup", "backup_restore",
    "pool_claim", "sandbox_create", "sandbox_exec", "sandbox_write_file",
    "vm_create", "vm_clone", "vm_exec", "vm_snapshot", "vm_snapshot_restore", "vm_snapshot_delete", "vm_delete",
    "vm_input", "vm_sign_in",
}


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        if self.headers.get("Authorization") == f"Bearer {TOKEN}":
            return True
        self.reply(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        if not self.authorized():
            return
        path = self.path.split("?")[0]
        if path == "/readyz":
            self.reply(200, {"ready": True, "kvm": True})
        elif path == "/v1/vms":
            self.reply(200, {"items": [VM]})
        elif path == f"/v1/vms/{VM_ID}":
            self.reply(200, VM)
        elif path == f"/v1/vms/{VM_ID}/logs":
            self.reply(200, b"Linux version 6.8\nlogin: ", "text/plain")
        elif m := re.fullmatch(rf"/v1/vms/{VM_ID}/network/([a-z-]+)", path):
            self.reply(200, {"kind": m.group(1), "items": [{"reason": "dns_deny", "packets": 3}]})
        else:
            self.reply(404, {"error": "not found"})

    def do_POST(self):
        if not self.authorized():
            return
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        if self.path == f"/v1/vms/{VM_ID}/stop":
            STOPS.append(VM_ID)
            self.reply(200, dict(VM, status="stopped"))
        else:
            self.reply(404, {"error": "not found"})


def attr(obj, *names):
    for n in names:
        if hasattr(obj, n):
            return getattr(obj, n)
    raise AttributeError(names[0])


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)
    print("ok:", msg)


async def call(session, name, args):
    res = await session.call_tool(name, args)
    return bool(attr(res, "is_error", "isError")), "".join(getattr(c, "text", "") for c in res.content)


async def run(binary, base, allow_write):
    env = dict(os.environ, FLUXVM_URL=base, FLUXVM_TOKEN=TOKEN, HOME=os.environ.get("RUNNER_TEMP", "/tmp"))
    args = ["mcp", "serve"] + (["--allow-write"] if allow_write else [])
    params = StdioServerParameters(command=binary, args=args, env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            init = await session.initialize()
            check(attr(attr(init, "server_info", "serverInfo"), "name") == "fluxvm", "serverInfo.name is fluxvm")
            tools = {t.name: t for t in (await session.list_tools()).tools}
            if not allow_write:
                check(set(tools) == READ_TOOLS, f"read-only tool set {sorted(tools)}")
                err, text = await call(session, "list_vms", {})
                check(not err and "10.0.0.5" in text and VM_ID in text, "list_vms returns the VM")
                err, text = await call(session, "get_vm", {"vm": "web"})
                check(not err and '"vcpus": 2' in text, "get_vm resolves by name")
                err, text = await call(session, "host_status", {})
                check(not err and '"running": 1' in text, "host_status counts VMs")
                err, text = await call(session, "vm_network", {"vm": "web", "kind": "drops", "limit": 5})
                check(not err and "dns_deny" in text, "vm_network returns drops")
                err, text = await call(session, "vm_network", {"vm": "web", "kind": "bogus"})
                check(err, "invalid kind is a tool error")
                err, text = await call(session, "vm_logs", {"vm": "web", "lines": 10})
                check(not err and "login:" in text, "vm_logs returns console")
                err, text = await call(session, "get_vm", {"vm": "missing"})
                check(err and "no VM named" in text, "unknown VM is a tool error")
                err, text = await call(session, "get_vm", {"vm": "web", "extra": 1})
                check(err, "unknown arguments rejected")
                err, text = await call(session, "vm_power", {"vm": "web", "op": "stop"})
                check(err and "--allow-write" in text and not STOPS, "write tool refused without --allow-write")
            else:
                check(set(tools) == READ_TOOLS | WRITE_TOOLS, f"write tool set {sorted(tools)}")
                err, text = await call(session, "vm_power", {"vm": "web", "op": "stop"})
                check(not err and "stopped" in text and STOPS == [VM_ID], "vm_power stops the VM")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    asyncio.run(run(binary, base, False))
    asyncio.run(run(binary, base, True))
    print("MCP SDK end-to-end: PASS")


if __name__ == "__main__":
    main()
