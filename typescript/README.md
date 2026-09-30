# @zyvorai/fluxvm (TypeScript client)

A client for FluxVM's agent-sandbox REST API (`/v1/sandboxes`). No runtime dependencies: it uses the `fetch` built
into Node 20 or later. It mirrors the [Python client](../python/README.md) call for call.

```bash
cd typescript && npm ci && npm run build      # then depend on this folder, or copy dist/
```

```ts
import { FluxVM } from "@zyvorai/fluxvm";

const fx = new FluxVM({ baseUrl: "http://127.0.0.1:8080", token: process.env.FLUXVM_TOKEN });

await fx.withSandbox({ name: "demo", ttlSeconds: 600, memoryMib: 512 }, async (sb) => {
  const r = await sb.run("echo hello", { timeoutSeconds: 10 });
  console.log(r.exitCode, r.stdout);

  await sb.writeFile("/tmp/app.py", "print('hi')\n", 0o644);
  console.log(await sb.readText("/tmp/app.py"));

  const resp = await sb.http(8080, "GET", "/health"); // a guest HTTP service through the API proxy
  console.log(resp.status, resp.text());
}); // the sandbox is deleted here, also when the callback throws
```

## API

| Call | Server route |
|---|---|
| `new FluxVM({ baseUrl, token?, timeoutMs?, headers?, fetch? })` | – |
| `fx.createSandbox({ name, template, spec, ttlSeconds, httpProxyPort, httpProxyPorts, volumes, vcpus, memoryMib, confidential, procbox })` → `Sandbox` | `POST /v1/sandboxes` |
| `fx.listSandboxes()`, `fx.getSandbox(id)` | `GET /v1/sandboxes`, `GET /v1/vms/{id}` |
| `fx.withSandbox(opts, fn)` | create, run `fn`, then delete |
| `fx.health()`, `fx.openapi()`, `fx.hostConfidential()` | `GET /healthz`, `/v1/openapi.json`, `/v1/host/confidential` |
| `sb.run(command, { timeoutSeconds })` → `{ exitCode, stdout, stderr, ok }` | `POST /v1/sandboxes/{id}/process` |
| `sb.writeFile(path, data, mode?)`, `sb.readFile`, `sb.readText`, `sb.readFileInfo` | `POST …/fs/write`, `POST …/fs/read` |
| `sb.snapshot(path)` | `POST …/snapshot` |
| `sb.baseline(paths)`, `sb.changes(paths?)` → `{ added, modified, deleted, unchanged, clean, … }` | `POST …/baseline`, `POST …/changes` |
| `sb.dryRun(command, { timeoutSeconds, paths })` | `POST …/dry-run` |
| `sb.http(port \| null, method, path, { body, headers, params, timeoutMs })` → `HttpResponse` | `ANY …/http/{port}/{path}`, or `ANY /sandbox/{id}/{path}` for `null` |
| `sb.refresh()`, `sb.delete()` | `GET` / `DELETE /v1/vms/{id}` |

Same behaviour as the Python client:

- A sandbox is a VM record, so `delete()` uses `DELETE /v1/vms/{id}`. `withSandbox` ignores "already gone" (404).
- `run` takes a shell string (`/bin/sh -c`); an array is shell-quoted and joined. A command that exceeds its
  timeout returns a non-zero `exitCode` instead of throwing. The HTTP call waits the timeout plus 10 s.
- Files travel base64 inside JSON; the guest limit is 64 MiB, checked client-side (`RangeError`).
- `http()` returns the guest's own status codes; call `raiseForStatus()` to throw on non-2xx.
- Redirects are never followed, so a proxied guest 3xx passes through.
- Errors: `ConnectionFailed`, `RequestTimeout`, and `ApiError` with `AuthError` (401), `ForbiddenError` (403, also an
  `AuthError`), `NotFound` (404, and the server's 400 "VM not found"), `RateLimited` (429, with `retryAfter`).

## Tests

`npm test` builds and runs the unit tests against a local mock server (`test/client.test.ts`). It has not been run
against a real FluxVM daemon; the Python and Go SDKs have live tests for that (`python/tests/live_*.py`).
