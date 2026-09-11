# REST API reference

Start the server:

```bash
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml serve
```

Default bind address:

```text
127.0.0.1:7788
```

## Endpoints

```text
GET    /healthz
GET    /readyz
GET    /metrics
POST   /v1/vms
GET    /v1/vms
GET    /v1/vms?name=<name>
GET    /v1/vms?tenant=<tenant>
GET    /v1/vms/{uuid}
POST   /v1/vms/{uuid}/start
POST   /v1/vms/{uuid}/start-from-snapshot
POST   /v1/vms/{uuid}/snapshot
POST   /v1/vms/{uuid}/stop
POST   /v1/vms/{uuid}/pause
POST   /v1/vms/{uuid}/resume
POST   /v1/vms/{uuid}/resources
GET    /v1/vms/{uuid}/cpuset
POST   /v1/vms/{uuid}/freeze
POST   /v1/vms/{uuid}/thaw
GET    /v1/vms/{uuid}/frozen
GET    /v1/vms/{uuid}/stats
GET    /v1/vms/{uuid}/pressure
GET    /v1/vms/{uuid}/logs
GET    /v1/vms/{uuid}/console
POST   /v1/vms/{uuid}/agent
POST   /v1/vms/{uuid}/agent/put-file
POST   /v1/vms/{uuid}/agent/get-file
DELETE /v1/vms/{uuid}
POST   /v1/images/build
GET    /v1/images/catalog
POST   /v1/images/catalog
DELETE /v1/images/catalog/{name}
POST   /v1/images/catalog/{name}/rename
POST   /v1/images/catalog/{name}/clone
POST   /v1/images/catalog/{name}/export
POST   /v1/images/catalog/{name}/read-only
POST   /v1/images/catalog/clean
POST   /v1/pools
GET    /v1/pools
GET    /v1/pools/{name}
DELETE /v1/pools/{name}
POST   /v1/pools/{name}/claim
POST   /v1/sandboxes
GET    /v1/sandboxes
POST   /v1/sandboxes/{id}/snapshot
POST   /v1/sandboxes/{id}/fs/read
POST   /v1/sandboxes/{id}/fs/write
POST   /v1/sandboxes/{id}/process
ANY    /v1/sandboxes/{id}/http/{port}/{*path}
ANY    /sandbox/{id}/{*path}
GET    /v1/vms/{uuid}/network/policy
POST   /v1/vms/{uuid}/network/policy
GET    /v1/vms/{uuid}/network/effective
GET    /v1/vms/{uuid}/network/status
GET    /v1/vms/{uuid}/network/stats
GET    /v1/vms/{uuid}/network/flows
GET    /v1/network/groups
POST   /v1/network/groups
GET    /v1/network/groups/{name}
DELETE /v1/network/groups/{name}
GET    /v1/network/cnp
POST   /v1/network/cnp
GET    /v1/network/cnp/{name}
DELETE /v1/network/cnp/{name}
GET    /v1/network/identities
GET    /v1/network/observe
GET    /v1/network/health
GET    /v1/network/ipcache
POST   /v1/network/refresh-dns
GET    /console
```

Sandbox routes are the agent-sandbox surface on the FluxVm backend — see
[agent-sandbox-gaps.md](agent-sandbox-gaps.md) and the README's
[Feature highlights](../README.md#feature-highlights).

`GET /v1/vms?name=<name>` exact-matches on `VmRecord.name` server-side. `POST /v1/vms/{uuid}/start`
relaunches a `Stopped` VM from its existing disk/seed, skipping the image-clone/cloud-init/token-inject
work `create` does — for a name-keyed register-then-start caller that already has a VM on disk it just
needs running again.

`GET /metrics` returns Prometheus text-exposition-format gauges: `fluxvm_vms_total{status="..."}`,
`fluxvm_vms_by_backend{backend="..."}`, and `fluxvm_vms_agent_enabled` — point a Prometheus
`scrape_config` at it directly, no exporter needed.

`GET /v1/vms/{uuid}/logs?lines=N&follow=true` streams the VM's captured console output (raw serial,
no per-line structure) as chunked plain text — `lines` (default 100) controls how much history to
send before either ending (default) or switching to a live tail (`follow=true`, polling the log file
every 300ms for new lines). Verified against a real booting VM: both the initial tail and the live
follow stream return real, growing boot output.

## Auth / RBAC

`[[auth.tokens]]` entries in the config (see `config.example.toml`) enable bearer-token auth on every
route except `GET /healthz` and `GET /readyz` (liveness vs readiness). Absent or empty `auth.tokens`
(the default) leaves the API exactly as open as the pre-auth MVP — every request is treated as
`admin`. Two roles:

- `admin` — everything: create/stop/pause/resume/exec/delete/build-image/resources/freeze/thaw.
- `read-only` — any `GET` route (`/v1/vms`, `/v1/vms/{uuid}`, `/metrics`, `/frozen`, `/stats`,
  `/pressure`, pool list/get) only; any mutating route (including `resources`/`freeze`/`thaw`) returns 403.

Optional per-token `tenant` is authoritative on create (inherited when the body omits it;
mismatch → 403) and scopes list/get/mutate to that tenant.
List with `GET /v1/vms?tenant=acme`. Reserved keys `auth.oidc_issuer` /
`auth.oidc_audience` are placeholders for a future OIDC exchange — bearer tokens remain the GA path.

```bash
curl -sS http://127.0.0.1:7788/v1/vms -H 'Authorization: Bearer <token>'
curl -sS 'http://127.0.0.1:7788/v1/vms?tenant=acme' -H 'Authorization: Bearer <token>'
curl -sS http://127.0.0.1:7788/readyz   # no token; "ok" requires state_dir (+ dataplane if required)
```

No token, or a token not in the config, gets 401. A `read-only` token on a mutating route gets 403.
Token comparison is constant-time. Verified on real hardware: 401 with no/wrong token, 200 for
`read-only` on `GET /v1/vms`, 403 for `read-only` on `POST /v1/vms`, 400 for `admin` on the same route
with an invalid body (proving auth let it through to the actual handler), 200 on `/healthz` and
`/readyz` with no token at all even with auth enabled.

Create through REST:

```bash
curl -sS http://127.0.0.1:7788/v1/vms \
  -H 'content-type: application/json' \
  --data-binary @examples/qemu.json | jq
# Production-shaped example (tenant + tap/netns):
curl -sS http://127.0.0.1:7788/v1/vms \
  -H 'content-type: application/json' \
  --data-binary @examples/create-vm-prod.json | jq
```

Whole-stack production checklist: [PRODUCTION.md](PRODUCTION.md) ·
`./scripts/release-checklist.sh`.

Exec through REST (`agent.enabled: true` required, see [operations.md](operations.md)):

```bash
curl -sS http://127.0.0.1:7788/v1/vms/<uuid>/agent \
  -H 'content-type: application/json' \
  -d '{"command": "echo hello", "timeout_seconds": 30}' | jq
```

## VM JSON contract

`backend` is one of `"qemu"`, `"cloud-hypervisor"`, `"firecracker"`, or `"auto"` (see
[Auto backend selection](operations.md#auto-backend-selection) — the persisted/returned record
always shows the resolved concrete backend, never `"auto"`).

```json
{
  "name": "job-123",
  "tenant": "acme",
  "backend": "qemu",
  "image": "/var/lib/fluxvm/images/ubuntu.qcow2",
  "vcpus": 2,
  "memory_mib": 2048,
  "disk_size_gib": 20,
  "network": {
    "mode": "user",
    "forwards": [
      {"host_port": 2222, "guest_port": 22, "protocol": "tcp"}
    ]
  },
  "cloud_init": {
    "hostname": "job-123",
    "user": "zyvor",
    "ssh_authorized_keys": ["ssh-ed25519 AAAA..."],
    "packages": ["curl"],
    "runcmd": ["echo hello > /tmp/hello"]
  },
  "agent": {"enabled": true, "port": 17777},
  "ttl_seconds": 600,
  "extra_args": [],
  "storage": "default"
}
```

Optional `tenant` is a first-class string for multi-team hosts (`GET /v1/vms?tenant=`). See
`examples/create-vm-prod.json`.

`agent.enabled` turns on the vsock guest agent (`fluxvm exec`) for this VM — the guest image must
have `fluxvm-guest-agent` installed and enabled (see the README's
[Quick start](../README.md#quick-start) section and [build-image-tutorials.md](build-image-tutorials.md)).
`agent.port` is the AF_VSOCK port the guest listens on (not a host TCP port); it defaults to `17777`
and rarely needs changing, since each VM already gets its own host-unique vsock CID.

`storage` is one of `"default"` (the implicit default when the field is omitted entirely — qcow2/raw,
exactly as before this existed), `"lvm-thin"`, `"nbd"`, or `"ceph-rbd"` — see
[Storage backends](operations.md#storage-backends).

### Networking modes

`none`:

```json
{"mode":"none"}
```

QEMU user networking:

```json
{
  "mode":"user",
  "forwards":[{"host_port":2222,"guest_port":22,"protocol":"tcp"}]
}
```

TAP/bridge (all VMMs):

```json
{
  "mode":"tap",
  "bridge":"vmbr0",
  "mac":"06:00:AC:10:00:02"
}
```

When `tap_name` is omitted, the manager creates one from the VM UUID.

macvtap (QEMU and Cloud Hypervisor only — see below):

```json
{
  "mode": "macvtap",
  "parent": "eth0",
  "macvtap_mode": "bridge",
  "mac": "52:54:00:aa:bb:cc"
}
```

Gives the VM its own MAC directly on `parent`'s link — no host bridge involved. `macvtap_mode` is
the macvtap link mode: `bridge` (default — siblings on the same parent can reach each other, but
not the parent itself directly), `vepa`, `private`, or `passthru`. The manager creates a per-VM
macvtap device on `parent`, opens its `/dev/tapN` character device, and passes that file descriptor
directly to the VMM (`-netdev tap,fd=N` for QEMU, `--net fd=N` for Cloud Hypervisor) — there's no
persistent named tap the VMM opens itself, which is why **Firecracker doesn't support this mode**:
its API only accepts a host device name it opens via `/dev/net/tun`, with no fd-passing option.
