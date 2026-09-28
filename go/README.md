# FluxVM Go SDK

A standard-library-only Go client for the FluxVM agent-sandbox API
(`/v1/sandboxes`). It mirrors the [Python SDK](../python/README.md): same
surface, same semantics, Go 1.21+.

```go
import "github.com/zyvorai/fluxvm/go"

c := fluxvm.NewClient("http://127.0.0.1:8080",
    fluxvm.WithToken(os.Getenv("FLUXVM_TOKEN")),
    fluxvm.WithTimeout(30*time.Second))

sb, err := c.CreateSandbox(ctx, fluxvm.CreateSandboxRequest{Template: "python"})
if err != nil { log.Fatal(err) }
defer sb.Delete(ctx)

res, _ := sb.Run(ctx, "echo hello")          // res.Stdout == "hello\n"
_ = sb.WriteFile(ctx, "/workspace/a.py", []byte("print(1)"), fluxvm.WithMode(0o644))

// What did the agent change?
_, _ = sb.Baseline(ctx, []string{"/workspace"})
// ... run the agent ...
ch, err := sb.Changes(ctx, nil)               // ch.Added / Modified / Deleted
```

## API

Every call takes a `context.Context`.

| Go | Server route |
|---|---|
| `NewClient(baseURL, opts...)`; `WithToken`, `WithTimeout`, `WithHeader`, `WithHTTPClient` | – |
| `c.CreateSandbox(ctx, CreateSandboxRequest{...})` → `*Sandbox` | `POST /v1/sandboxes` |
| `c.ListSandboxes(ctx)` → `[]SandboxInfo` | `GET /v1/sandboxes` |
| `c.GetSandbox(ctx, id)` → `*Sandbox` | `GET /v1/vms/{id}` |
| `c.HostConfidential(ctx)`, `c.Health(ctx)`, `c.OpenAPI(ctx)` | `GET /v1/host/confidential`, `/healthz`, `/v1/openapi.json` |
| `sb.Run(ctx, cmd, WithExecTimeout(d))` / `sb.RunArgs(ctx, argv)` → `*ExecResult{ExitCode, Stdout, Stderr}` | `POST …/process` |
| `sb.WriteFile(ctx, path, data, WithMode(m))` | `POST …/fs/write` |
| `sb.ReadFile(ctx, path)` → `[]byte`; `sb.ReadFileInfo` → `*FileContent{Data, Mode}` | `POST …/fs/read` |
| `sb.Snapshot(ctx, path)` | `POST …/snapshot` |
| `sb.Baseline(ctx, paths)` → `*BaselineSummary`; `sb.Changes(ctx, paths)` → `*ChangeSet` | `POST …/baseline`, `POST …/changes` (see [docs/sandbox-changes.md](../docs/sandbox-changes.md)) |
| `sb.HTTP(ctx, HTTPRequest{Port, Method, Path, Body, Header, Query, Timeout})` → `*HTTPResponse` | `ANY …/http/{port}/{path}`; `Port: 0` uses `ANY /sandbox/{id}/{path}` |
| `sb.Refresh(ctx)`, `sb.Delete(ctx)` | `GET` / `DELETE /v1/vms/{id}` |

Request and response shapes come from `crates/fluxvm-api/src/lib.rs` and
`crates/fluxvm-scheduler/src/sandbox.rs`. Unset `CreateSandboxRequest` fields
are omitted so the server's defaults apply.

## Errors

A non-success answer is an `*APIError` (`Status`, `Message`, raw `Body`,
`RetryAfter` for 429). It also matches sentinels with `errors.Is`:

| Sentinel | Matches |
|---|---|
| `ErrAuth` | 401 and 403 |
| `ErrForbidden` | 403 (the token's role can't call this route; guest-reaching routes need `admin`) |
| `ErrNotFound` | 404 (also another tenant's sandbox, and `Changes` with no baseline) |
| `ErrRateLimited` | 429 |
| `ErrTimeout` | client timeout or context deadline (also matches `context.DeadlineExceeded`) |
| `ErrConnection` | could not reach the API |
| `ErrFileTooLarge` | `WriteFile` above 64 MiB, returned without a request |

A caller-cancelled context returns `context.Canceled`, not `ErrTimeout`.

```go
if _, err := sb.Changes(ctx, nil); errors.Is(err, fluxvm.ErrNotFound) {
    // no baseline yet: call sb.Baseline first
}
```

## Behaviour worth knowing

- **Delete.** There is no `DELETE /v1/sandboxes/{id}`; a sandbox is a VM
  record, so `Delete` uses `DELETE /v1/vms/{id}` (204) and `Refresh`/`GetSandbox`
  use `GET /v1/vms/{id}`. Unlike the Python SDK there is no context-manager;
  use `defer sb.Delete(ctx)`.
- **`Run`.** The server takes a shell string (`/bin/sh -c`); `RunArgs` quotes
  each argument like `shlex.join`. `WithExecTimeout` is the guest-side limit in
  whole seconds (server default 30). A command that exceeds it returns a
  non-zero `ExitCode`, not an error. The HTTP call waits the limit plus 10 s,
  so a short client `WithTimeout` does not cut a long command off.
- **Files** travel base64 inside JSON; the guest agent's limit is 64 MiB.
- **`HTTP`** relays the guest's own status codes (a 4xx/5xx is a normal
  `*HTTPResponse`; call `RaiseForStatus` to turn it into an error) and never
  follows redirects. A 401/403 from the API itself is indistinguishable from a
  guest 401/403 here. The sandbox needs a routable guest IP (`network.mode=tap`
  with a netns).
- **`Snapshot(path)`** writes to a path on the *server* host.
- **`WithHTTPClient`** copies your `http.Client`; the copy never follows
  redirects and your original is left untouched.
- **`Changes`** reports changes only. To roll a sandbox back use snapshot and
  restore.

## Tests

```bash
cd go && go vet ./... && go test ./... -race
```

The tests run against an in-process `httptest` server that copies the real
handlers' status codes, auth rules and body shapes (a port of the Python SDK's
`tests/mock_server.py`). Nothing here has run against a live FluxVM server.
