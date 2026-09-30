# fluxvm (Python client)

A small client for FluxVM's agent-sandbox REST API (`/v1/sandboxes`).
Standard library only (`urllib`), Python 3.8+, no runtime dependencies.

```bash
pip install ./python        # or add python/ to PYTHONPATH
```

```python
from fluxvm import FluxVM

fx = FluxVM("http://127.0.0.1:8080", token="…")   # token omitted only on an unauthenticated loopback server

with fx.create_sandbox(name="demo", ttl_seconds=600, memory_mib=512) as sb:
    r = sb.run("echo hello", timeout=10)
    print(r.exit_code, r.stdout)

    sb.write_file("/tmp/app.py", "print('hi')\n", mode=0o644)
    print(sb.read_text("/tmp/app.py"))

    resp = sb.http(8080, "GET", "/health")           # guest HTTP service through the API proxy
    print(resp.status, resp.text())
# leaving the `with` block deletes the sandbox
```

## API

| Call | Server route |
|---|---|
| `FluxVM(base_url, token=None, timeout=30, headers=None, ssl_context=None)` | – |
| `fx.create_sandbox(name, template, spec, ttl_seconds, http_proxy_port, http_proxy_ports, volumes, vcpus, memory_mib, confidential, gpus)` → `Sandbox` (`gpus`: see [sandbox-gpus.md](../docs/sandbox-gpus.md)) | `POST /v1/sandboxes` |
| `fx.list_sandboxes()` → `[SandboxInfo]` | `GET /v1/sandboxes` |
| `fx.get_sandbox(id)` → `Sandbox` | `GET /v1/vms/{id}` |
| `fx.host_confidential()`, `fx.health()`, `fx.openapi()` | `GET /v1/host/confidential`, `/healthz`, `/v1/openapi.json` |
| `sb.run(command, timeout=None)` → `ExecResult(exit_code, stdout, stderr)` | `POST /v1/sandboxes/{id}/process` |
| `sb.write_file(path, data, mode=None)` | `POST …/fs/write` |
| `sb.read_file(path)` → `bytes`; `read_text`; `read_file_info` → `FileContent(data, mode)` | `POST …/fs/read` |
| `sb.snapshot(path)` | `POST …/snapshot` |
| `sb.dry_run(command, timeout=None, paths=None)` → dict (`changes`, `discarded`, `reverted_via`, exit result); `create_sandbox(procbox={...})` for a rootless process sandbox | `POST …/dry-run` (procbox: workspace copy; native flux-vm VMs: snapshot/restore, `paths` required; other VM backends 501) |
| `sb.baseline(paths)` → `BaselineSummary`; `sb.changes(paths=None)` → `ChangeSet(added, modified, deleted, unchanged, …)` | `POST …/baseline`, `POST …/changes` (see `docs/sandbox-changes.md`) |
| `sb.http(port, method, path, body=None, headers=None, params=None, timeout=None)` → `HttpResponse` | `ANY …/http/{port}/{path}`; `port=None` uses `ANY /sandbox/{id}/{path}` |
| `sb.refresh()`, `sb.delete()`, `with sb:` | `GET` / `DELETE /v1/vms/{id}` |

Field names and shapes come from `crates/fluxvm-api/src/lib.rs` and
`crates/fluxvm-scheduler/src/sandbox.rs`; unset `create_sandbox` arguments are
omitted so the server's defaults apply.

Behaviour worth knowing:

- **Delete.** There is no `DELETE /v1/sandboxes/{id}`. A sandbox is a VM record,
  so `delete()` and the context manager use the generic `DELETE /v1/vms/{id}`
  (204). Exiting the `with` block ignores "already gone" (404) and raises
  anything else.
- **`run`.** The server takes a shell string (`/bin/sh -c`); a list argument is
  joined with `shlex.join`. `timeout` is the guest-side limit in seconds
  (server default 30). A command that exceeds it returns a non-zero
  `exit_code`; it does not raise. The HTTP call waits `timeout + 10` s.
- **Files.** Content travels base64 inside JSON; the guest agent's limit is
  64 MiB per file, enforced client-side (`ValueError`). `write_file` accepts
  `str` (UTF-8) or bytes.
- **`snapshot(path)`** writes to a path on the *server* host.
- **HTTP proxy.** Needs a guest with a routable IP (`network.mode=tap` with a
  netns). The guest's own status codes come back in `HttpResponse` and are not
  raised (`raise_for_status()` if you want that), and redirects are not
  followed. Bytes/str bodies are sent as `application/octet-stream` /
  `text/plain` unless you set `Content-Type`; dict/list bodies are sent as JSON.
- **Auth.** `Authorization: Bearer <token>` (static token or OIDC JWT). Tenant
  scoping comes from the token; other tenants' sandbox ids answer 404. Behind a
  trusted mTLS frontend pass its identity headers via `headers=`.
- All sandbox routes that reach the guest need an `admin` token.

## Errors

`FluxVMError` is the base. `ApiError(status, body, message)` covers any non-success
response (the server maps most handler failures, including guest-agent errors
and validation, to **400** with `{"error": "…"}`). Subclasses: `AuthError` (401),
`ForbiddenError` (403, also an `AuthError`), `NotFound` (404), `RateLimited`
(429, with `retry_after`). Transport failures raise `RequestTimeout` or
`ConnectionFailed`.

## Not covered yet

Interactive shell/PTY, the WebSocket proxy (`…/ws/{port}/…`), and the change-set
routes are not wrapped.

## Tests

```bash
python3 -m unittest discover -s python/tests
```

The tests run against an in-process mock that mirrors the real handlers' status
codes, auth rules and body shapes. They do not exercise a live FluxVM server.

- **Unknown VM.** The server answers `GET`/`DELETE /v1/vms/{id}` for an unknown VM
  with `400 "VM not found"`, not 404; the SDK maps that message to `NotFound`.
- **Live test.** `FLUXVM_LIVE_URL=http://127.0.0.1:PORT python3 -m unittest python/tests/live_procbox.py`
  against a daemon with `[sandbox.procbox] enabled = true`.
