# REST API reference

Start the server:

```bash
sudo /usr/local/bin/fluxctl --config /etc/fluxvm.toml serve
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
GET    /v1/openapi.json                  # OpenAPI 3.1, VM surface (no auth)
POST   /v1/vms                           # ?ready=exec adds first_command_ms + phases; Idempotency-Key honored
GET    /v1/vms
GET    /v1/vms?name=<name>
GET    /v1/vms?tenant=<tenant>
GET    /v1/vms?label=<selector>          # env=prod,team!=x,gpu,!tmp
GET    /v1/vms/{uuid}
PATCH  /v1/vms/{uuid}                    # {"name": "...", "labels": {"k": "v", "gone": null}}
POST   /v1/vms/{uuid}/start
POST   /v1/vms/{uuid}/restart
POST   /v1/vms/{uuid}/clone              # {"name": "..."}; source must be stopped
POST   /v1/vms/{uuid}/fork               # {"count": 1-32, "namePrefix": "..."}; admin; running flux-vm source; 201 {"items": [...], "elapsed_ms": n}; ?ready=exec; Idempotency-Key honored
POST   /v1/vms/{uuid}/backup             # {"name": "...", "compress": bool, "all_disks": bool, "quiesce": "auto"|"required"|"never"}
POST   /v1/vms/{uuid}/restore-backup     # {"name": "..."}; VM must be stopped
GET    /v1/backups                       # newest first
DELETE /v1/backups/{name}
GET    /v1/backups/{name}/root           # the backup's standalone root qcow2 (download)
POST   /v1/vms/{uuid}/start-from-snapshot
POST   /v1/vms/{uuid}/snapshot           # Idempotency-Key honored
POST   /v1/vms/{uuid}/restore            # {"tag": "..."}; admin; running flux-vm restores in place (memory + disk)
GET    /v1/vms/{uuid}/snapshots
DELETE /v1/vms/{uuid}/snapshots/{tag}
GET    /v1/vms/{uuid}/disks
POST   /v1/vms/{uuid}/disks              # {"name": "data", "size_gib": 10}, {"name": "pvc", "path": "/dev/rbd0"} or {"name": "disk1", "backing": "/var/lib/fluxvm/images/imported/web01/disk1.raw"} (qcow2 overlay)
PATCH  /v1/vms/{uuid}/disks/{name}       # {"size_gib": 20}; name "root" = boot disk
DELETE /v1/vms/{uuid}/disks/{name}       # deletes the file (or overlay); only unlinks a path-attached disk
POST   /v1/vms/{uuid}/cdroms/{name}/eject # remove install media (live when running); the empty drive stays
GET    /v1/vms/{uuid}/serial             # websocket, raw serial bytes (QEMU)
POST   /v1/vms/{uuid}/stop
POST   /v1/vms/{uuid}/pause
POST   /v1/vms/{uuid}/resume
POST   /v1/vms/{uuid}/resources
POST   /v1/vms/{uuid}/hotplug/cpu
POST   /v1/vms/{uuid}/hotplug/memory
POST   /v1/vms/{uuid}/hotplug/nic
POST   /v1/vms/{uuid}/hotplug/nic/unplug # {"mac": ...} or {"tap": ...}; extra NICs only
POST   /v1/vms/{uuid}/hotplug/share
GET    /v1/vms/{uuid}/cpuset
POST   /v1/vms/{uuid}/freeze
POST   /v1/vms/{uuid}/thaw
GET    /v1/vms/{uuid}/frozen
GET    /v1/vms/{uuid}/stats
GET    /v1/vms/{uuid}/pressure
GET    /v1/vms/{uuid}/balloon            # flux-vm KVM engine; {memory_mib, target_mib, actual_mib}
POST   /v1/vms/{uuid}/balloon            # {"balloon_mib": N}; admin; 0 deflates
GET    /v1/vms/{uuid}/memory             # VMM-process PSS/private/shared + balloon; see memory-density.md
GET    /v1/vms/{uuid}/logs
GET    /v1/vms/{uuid}/console
POST   /v1/vms/{uuid}/agent              # {"command", "timeout_seconds"?, "policy"?}; see guest-exec-policy.md
POST   /v1/vms/{uuid}/agent/ping
POST   /v1/vms/{uuid}/agent/put-file
POST   /v1/vms/{uuid}/agent/get-file
GET    /v1/vms/{uuid}/qga/network-interfaces
DELETE /v1/vms/{uuid}                    # Idempotency-Key honored
GET    /v1/vm-templates
POST   /v1/vm-templates                  # {"name", "description"?, "spec", "replace"?}
GET    /v1/vm-templates/{name}
DELETE /v1/vm-templates/{name}
POST   /v1/vm-templates/{name}/instantiate   # {"name": "vm-1", "labels"?: {...}}
GET    /v1/events                        # ?vm=&event=<prefix>&since=<rfc3339>&limit=
GET    /v1/events/stream                 # Server-Sent Events, same filters
GET    /v1/quotas/me
POST   /v1/images/build
POST   /v1/images/import                 # {"source": "/path/vm.ova", "name": "...", "repair": true, "remove_vmware_tools": false}; admin; 201; see import-vmware.md
GET    /v1/images/catalog
POST   /v1/images/catalog
DELETE /v1/images/catalog/{name}
POST   /v1/images/catalog/{name}/rename
POST   /v1/images/catalog/{name}/clone
POST   /v1/images/catalog/{name}/export
POST   /v1/images/catalog/{name}/read-only
POST   /v1/images/catalog/clean
GET    /v1/oci/images                    # cached OCI rootfs images for vz sandboxes; see oci-sandboxes.md
POST   /v1/oci/images                    # {"image": "alpine:3.22", "platform"?: "linux/amd64"}; admin; pull and build the rootfs
DELETE /v1/oci/images/{digest|reference} # admin
POST   /v1/oci/prune                     # admin; drop images no sandbox was started from, and unused blobs
GET    /v1/vznets                        # private vz networks (apple.networks): subnet, members, switch_running; see macos.md
POST   /v1/pools
GET    /v1/pools
GET    /v1/pools/{name}
DELETE /v1/pools/{name}
POST   /v1/pools/{name}/claim            # ?ready=exec adds first_command_ms + phases
POST   /v1/pools/{name}/resize
POST   /v1/sandboxes                     # optional volumes: [{name, guest_path, read_only}] (QEMU template or oci); vz: "oci": {"image", "ports"?, "restart"?, "healthcheck"?, ...} (oci-sandboxes.md)
GET    /v1/sandboxes
POST   /v1/sandboxes/{id}/snapshot
POST   /v1/sandboxes/{id}/fs/read
POST   /v1/sandboxes/{id}/fs/write
POST   /v1/sandboxes/{id}/process        # {"command", "timeout_seconds"?, "policy"?} or {"process": {"argv", "env"?, "cwd"?}} (no shell; agent); see guest-exec-policy.md
GET    /v1/sandboxes/{id}/logs           # ?lines=N (200); console tail + container exit_code / init_error / restarts / health
POST   /v1/sandboxes/{id}/dry-run        # {"command", "paths"}; procbox: workspace copy; flux-vm/qemu/firecracker: snapshot/restore
POST   /v1/sandboxes/{id}/speculate      # {"command", "timeout_seconds"?, "paths"?, "ttl_seconds"?}; admin; returns a pending changeset
GET    /v1/sandboxes/{id}/changesets     # {"items": [...]}, newest first
GET    /v1/sandboxes/{id}/changesets/{cs}
POST   /v1/sandboxes/{id}/changesets/{cs}/approve
POST   /v1/sandboxes/{id}/changesets/{cs}/reject
POST   /v1/sandboxes/{id}/changesets/{cs}/apply   # approved only; 409 on conflict
POST   /v1/sandboxes/{id}/grants         # credential broker grant; admin; 201 GrantInfo
GET    /v1/sandboxes/{id}/grants         # {"grants": [...]}, no secrets
DELETE /v1/sandboxes/{id}/grants         # revoke all; {"revoked": bool}
DELETE /v1/sandboxes/{id}/grants/{grant_id}   # revoke one; 404 if unknown
ANY    /v1/sandboxes/{id}/http/{port}/{*path}
ANY    /sandbox/{id}/{*path}
GET    /v1/vms/{uuid}/network/policy
POST   /v1/vms/{uuid}/network/policy
GET    /v1/vms/{uuid}/network/effective
GET    /v1/vms/{uuid}/network/status
GET    /v1/vms/{uuid}/network/stats
GET    /v1/vms/{uuid}/network/flows
POST   /v1/vms/{uuid}/network/edge          # Kairon VM-edge spec (admin); enforced and persisted, see vm-edge-contract.md
GET    /v1/vms/{uuid}/network/conntrack     # live conntrack export (admin); empty entries when not attached
POST   /v1/vms/{uuid}/network/conntrack     # restore (admin); identity mismatch is rejected, applied on attach if not attached
GET    /v1/vms/{uuid}/network/learned-ip    # {"ip","source"}: arp|nd from the datapath, else dhcp|fluxvm
GET    /v1/vms/{uuid}/network/drops?limit=N # attributed drops with Kairon reason names (default 100, max 4096)
POST   /v1/vms/{uuid}/network/capture       # starts a 1-30s tcpdump capture on the VM edge (admin)
GET    /v1/vms/{uuid}/network/capture       # capture sessions and their state (admin)
GET    /v1/vms/{uuid}/network/capture/{token}  # the finished pcap; 409 while running (admin)
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
GET    /v1/network/ipam
POST   /v1/network/refresh-dns
GET    /console                          # web dashboard (static, no auth; it asks for a token)
```

Sandbox routes are the agent-sandbox surface on the FluxVm backend — see
[agent-sandbox-gaps.md](agent-sandbox-gaps.md) and the
[Feature highlights](index.md#feature-highlights).

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

### Day-2 VM routes

Semantics, limits and CLI equivalents for restart, PATCH/labels, snapshots,
clone, disks, serial, backup, scheduled snapshots, VM templates and events are
in [operations.md → Day-2 VM operations](operations.md#day-2-vm-operations).
Highlights:

- `GET /v1/vms/{uuid}/serial` is a websocket to the QEMU serial port: binary
  and text frames are written to the guest verbatim, guest output comes back
  as binary frames. One client at a time; no guest agent needed.
- `POST /v1/vms/{uuid}/backup` always writes under `state_dir/backups/` (the
  API never takes a destination path) and returns `{name, path, size_bytes,
  live, quiesced, disks[]}`. An optional `name` replaces the default
  `<vm>-<utc>` so callers can find their backup again after a timeout.
  `all_disks` skips linked images and block devices, which FluxVM doesn't
  own. `quiesce` (default `auto`) freezes the guest's
  filesystems through QGA around the snapshot when the agent answers;
  `required` fails without it. `GET /v1/backups` lists backups with that
  metadata; `POST /v1/vms/{uuid}/restore-backup` copies one back into a
  stopped VM, in the disk's own format. Any engine, on default storage or a
  `shared` disk file; a running VM can be backed up only on QEMU with default
  storage.
- `POST /v1/vm-templates/{name}/instantiate` goes through the same tenant,
  `created_by_token` and token-quota handling as `POST /v1/vms`. VM templates
  are separate from the sandbox `/v1/templates` routes.
- `POST /v1/vms/{uuid}/fork` snapshots a running flux-vm VM once and starts
  `count` children from that snapshot. Children share the read-only memory
  file and get a copy-on-write copy of the disk, a new CID, vsock socket and
  tap. They keep the parent's MAC and guest IP, so the source must use
  `network = none`, `user`, or `tap` with a per-VM netns, and no extra NICs.
  Either all children start or none are left behind. Token quotas are
  charged per child. `scripts/bench-fork.sh` times it.
- `GET /v1/events/stream` emits `event: <name>` / `data: <json>` frames;
  tenant-scoped tokens only see their tenant's VMs.
- `GET /v1/openapi.json` is exempt from auth, like `/healthz` and `/readyz`.

## Auth / RBAC

`[[auth.tokens]]` entries in the config (see `config.example.toml`) enable bearer-token auth on every
route except `GET /healthz`, `GET /readyz` (liveness vs readiness) and `GET /v1/openapi.json`. Absent or empty `auth.tokens`
(the default) leaves the API exactly as open as the pre-auth MVP — every request is treated as
`admin`. Two roles:

- `admin` — everything: create/stop/pause/resume/exec/delete/build-image/resources/hotplug/freeze/thaw.
- `read-only` — any `GET` route (`/v1/vms`, `/v1/vms/{uuid}`, `/metrics`, `/frozen`, `/stats`,
  `/pressure`, pool list/get) only; any mutating route (including `resources`/`hotplug`/`freeze`/`thaw`) returns 403.

`POST /v1/egress/check` is admin-only despite looking like a read-only diagnostic. It returns
`{"allow": bool, "reason": "..."}` for a host. A matching `[sandbox] credential_vault`
`inject_authorization` secret is **not** echoed back: the field is `skip_serializing`, and its
`Debug` output is `[redacted]`, so the response cannot leak it. The route stays admin-only because
it reveals the egress allowlist decision for arbitrary hosts, and an earlier version had no role check
at all (see CHANGELOG). Per-sandbox credentials use a separate mechanism, see
[credential-broker.md](credential-broker.md).

Optional per-token `tenant` is authoritative on create (inherited when the body omits it;
mismatch → 403) and scopes list/get/mutate to that tenant.
List with `GET /v1/vms?tenant=acme`. Reserved keys `auth.oidc_issuer` /
`auth.oidc_audience` are placeholders for a future OIDC exchange — bearer tokens remain the GA path.

The same tenant scoping applies to `/v1/sandboxes` (a sandbox is a `VmRecord` like any other):
`POST /v1/sandboxes` inherits/enforces the caller's token `tenant` on the resolved spec exactly
like `POST /v1/vms` does (a `template`'s own tenant, if any, is subject to the same check as an
explicit `spec.tenant` would be), `GET /v1/sandboxes` only ever returns the caller's own tenant's
sandboxes, and every `/v1/sandboxes/{id}/...` route (snapshot, `fs/read`, `fs/write`, `process`)
404s for a different tenant's token exactly like `/v1/vms/{id}/...` already did — this was
previously missing entirely (see CHANGELOG).

`/v1/pools` gets the same treatment, name-keyed rather than `Uuid`-keyed: `POST /v1/pools`
inherits/enforces the caller's token `tenant` on `template.tenant` (every member ever backfilled
from that pool inherits it unchanged), `GET /v1/pools` only returns the caller's own tenant's
pools, and `GET`/`DELETE /v1/pools/{name}`, `POST /v1/pools/{name}/claim`, and
`POST /v1/pools/{name}/resize` all 404 for a different tenant's token — also previously missing
entirely (see CHANGELOG).

`POST /v1/pools/{name}/resize` (admin-only, body `{"size": N}`) changes a pool's target size after
creation — previously the only way to change a running pool's size at all was to `DELETE` it
(discarding every still-ready warm member) and `POST /v1/pools` again from the same spec. Growing
only updates the stored target and fires the same background backfill `create`/`claim` already use
(the reaper's own per-tick top-up is the backstop, as always); shrinking deletes excess ready
members immediately and synchronously, not on the next reaper tick — a caller asking for a smaller
pool is asking to give resources back right away. See `docs/operations.md`'s "Warm VM pools"
section for a worked example.

Every pool-returning route (`POST`/`GET /v1/pools`, `GET`/`POST .../resize /v1/pools/{name}`)
returns a `PoolView`, not the bare stored record: alongside `size` (the target) and `members` (ids
of members ready right now) it adds `ready` (`members.len()`, named explicitly so you don't have to
know that's what `members` counts), `pending` (`size` minus `ready`, floored at 0), and
`claimed_total` (a lifetime count of members this pool has actually handed out via
`POST .../claim`). All three are additive — nothing existing was renamed or removed.

`POST /v1/pools/{name}/claim` accepts `name`, `ttl_seconds` and `pod_uid` (all optional). `pod_uid` is
the Kubernetes Pod UID a Secure Containers claim is for: it is recorded as the VM's `request.pod_uid`,
so the dataplane attached when the NIC is hot-added mints the Pod's eBPF identity (Pod-scoped network
policy, `POST /v1/vms/{id}/network/pod-policy`) exactly as for a VM created for the Pod. It must be 1–128
characters of `[A-Za-z0-9._-]` (400 otherwise, checked before a member is taken from the pool).

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

Optional `data_disks` (QEMU only), e.g. `[{"name": "disk1", "backing": "/var/lib/fluxvm/images/imported/web01/disk1.raw"}]`,
creates each disk as a per-VM qcow2 overlay on `backing` before the first boot. `backing` is
checked like a `POST /v1/vms/{uuid}/disks` `path` and never written to. An image import's
`suggested` body fills it for every disk after the boot disk.

Optional `cdroms` (QEMU only, at most 4), e.g.
`[{"name": "install", "path": "/var/lib/fluxvm/images/win2022.iso"}, {"name": "virtio", "path": "/var/lib/fluxvm/images/virtio-win.iso"}]`,
attaches each ISO read-only as a SATA CD-ROM on the q35 AHCI controller (`ide.0`, `ide.1`, …), so
Windows Setup sees it with no extra drivers. `path` is checked like a data disk `backing`. No boot
order is forced: firmware skips a blank root disk and boots the first CD-ROM, and once an OS is
installed it boots from the disk. To install onto a blank disk, point `image` at an empty raw or
qcow2 file and set `disk_size_gib`.

**Ejecting install media.** A VM with media in a CD-ROM can't be live-migrated, because the ISO
path is host-local. Once the OS is installed, eject the medium:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:7788/v1/vms/$ID/cdroms/install/eject
```

- Needs an admin-role token and is tenant-scoped like every `/v1/vms/{uuid}` route (a tenant token
  can eject only its own tenant's VMs).
- If the VM is running on QEMU, the medium is removed live over QMP: `blockdev-open-tray` (forced,
  so a guest lock doesn't block it), `blockdev-remove-medium`, `blockdev-close-tray`, then the
  read-only `cd-<name>` block node is deleted. The guest sees an empty drive. Nothing is hot-unplugged.
- The drive is recorded as empty (`"path": ""` in `cdroms[]`). Later starts, restarts and migration
  receivers create a bare `ide-cd` device with no medium, so the guest's device layout (and Windows
  drive letters) stays the same.
- Ejecting an already-empty drive succeeds and changes nothing. An unknown name returns 400
  `cdrom "<name>" not found`.
- The response is the updated VM record. The action is audited as `vm.cdrom.eject`.
- Creating a VM with an empty `path` is still rejected (`cdrom "<name>" needs a path`). An empty
  drive comes only from an eject.

Live migration rejects only CD-ROMs that still hold media, with
`eject cdrom "<name>" first (POST /v1/vms/{id}/cdroms/{name}/eject)`. Inserting new media into an
empty drive isn't supported yet; recreate the VM with the ISO instead.

`agent.enabled` turns on the vsock guest agent (`fluxctl exec`) for this VM — the guest image must
have `fluxvm-guest-agent` installed and enabled (see the
[Quick start](getting-started.md#quick-start) section and [build-image-tutorials.md](build-image-tutorials.md)).
`agent.port` is the AF_VSOCK port the guest listens on (not a host TCP port); it defaults to `17777`
and rarely needs changing, since each VM already gets its own host-unique vsock CID.

`storage` is one of `"default"` (the implicit default when the field is omitted entirely — qcow2/raw,
exactly as before this existed), `"lvm-thin"`, `"nbd"`, `"ceph-rbd"`, or `"ceph-rbd-in-place"` — see
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

Direct — bridge-less tap (opt-in; [direct-datapath.md](direct-datapath.md)):

```json
{
  "mode": "tap",
  "mac": "02:00:00:00:0a:0a",
  "direct": {"outer": "enp1s0", "mode": "l2-uplink", "guest_ips": ["192.168.1.50"]}
}
```

An eBPF redirect pairs the VM's tap with `outer` instead of a bridge. `mode` is `l2-uplink` (a physical
NIC that is not a bridge/bond port; frames are steered by destination MAC, and ARP requests by the
declared `guest_ips`) or `peer-veth` (a Pod's veth, with `netns_path` naming the Pod network namespace
the tap is created in; used by the Secure Containers shim). `bridge`, `netns: true` and `extra` NICs
cannot be combined with `direct`. It requires `sandbox.dataplane.mode = "ebpf"` or `"cilium"`
(`legacy` is rejected), a failed dataplane attach fails the create, and the tap is handed to QEMU or
Cloud Hypervisor (by name, or as a descriptor when it lives in another namespace); **Firecracker and the
native hypervisor accept only the host-namespace form** because they cannot take a descriptor.
`Policy.allowed_network_modes` sees it as `tap`.

### NIC hotplug (QEMU)

`POST /v1/vms/{uuid}/hotplug/nic` (admin) attaches a NIC to a running VM, used by Secure Containers after
a warm-pool claim (the pool template boots with `network.mode=none`). On a `netns: true` VM, QEMU runs
inside the namespace, so the daemon opens the new bridge tap and passes it over QMP (`getfd`); on
relaunch every extra NIC's tap is inherited as `-netdev tap,fd=`. Send **either** a bridged NIC:

```json
{"bridge": "fvbhab12cd", "mac": "02:00:00:00:00:01"}
```

**or** a bridge-less one (the daemon creates the tap, applies the dataplane, then passes the tap to QEMU
over QMP with `getfd` + `netdev_add fd=` on one session):

```json
{"mac": "02:00:00:00:00:01",
 "direct": {"outer": "eth0", "netns_path": "/run/netns/fvcni-ab12cd", "mode": "peer-veth"}}
```

`bridge` and `direct` are mutually exclusive (400 otherwise). A direct hotplug needs a VM booted with
`network.mode=none`; on any failure the daemon removes the tap and dataplane it created.

`POST /v1/vms/{uuid}/hotplug/nic/unplug` (admin) removes an extra bridged NIC from a running VM, named
by `{"mac": "..."}` or `{"tap": "..."}`, and deletes its tap. The guest has 10 s to release the device.
The primary NIC can't be hot-removed.

### Share hotplug (QEMU)

`POST /v1/vms/{uuid}/hotplug/share` (admin) hot-adds a virtiofs share to a running VM, so a warm-pool
member (which keeps its template's shares) can receive a Pod's rootfs and volumes after a claim:

```json
{"host_path": "/var/lib/fluxvm/some/dir", "read_only": false}
```

The reply is `{"tag": "fs<N>"}`, N being the share's index in the VM's `shared_folders`; mount it in the
guest with `mount -t virtiofs fs<N> <dir>`. The path must be absolute, without `..`, and a directory the
**daemon** can see (a sandboxed daemon with `PrivateTmp` does not see `/tmp`). The VM must have been created with
`"shared_memory": true` (vhost-user-fs needs shareable guest memory); up to four shares can be hot-added
(reserved root ports). On failure the `virtiofsd` is killed and nothing is recorded.

## Speculation, grants, exec policy and memory density

These routes came with the crash-safe lifecycle work. They are implemented and unit tested; none has
been run end-to-end on real VMs yet (each guide has a status table). The OpenAPI document served at
`GET /v1/openapi.json` is generated by `openapi::spec()` in `crates/fluxvm-api/src/openapi.rs`; it
has **not** been updated for these routes, headers or query parameters, and there is no
hand-maintained spec file. Until it is, this page is the contract.

Every route here needs an `admin` token except `GET /v1/vms/{uuid}/balloon` and
`GET /v1/vms/{uuid}/memory`. They are tenant-scoped like the rest of `/v1/vms/{uuid}` and
`/v1/sandboxes/{id}`.

### Speculation and changesets

Guide: [speculative-execution.md](speculative-execution.md).

`POST /v1/sandboxes/{id}/speculate` runs a command in an isolated copy and returns a pending
changeset. The sandbox is started on demand like other sandbox routes.

```json
{"command": "make build", "timeout_seconds": 120, "paths": ["/work"], "ttl_seconds": 600}
```

- `command` (required).
- `timeout_seconds` (optional) bounds the command.
- `paths` (optional for procbox sandboxes, default `["/"]`; **required** for VM sandboxes, 400
  otherwise) limits the diff to those directories.
- `ttl_seconds` (optional) is how long the changeset stays decidable: default 3600, clamped to 1..=86400.

The response is a changeset. The same shape is returned by `GET .../changesets/{cs}` and by approve,
reject and apply:

```json
{
  "id": "5b0f6c1e-0f0e-4a63-9f58-0b2f1e0f7a11",
  "sandbox_id": "0c1d2e3f-0000-4000-8000-000000000001",
  "state": "pending",
  "created_at": 1790000000,
  "updated_at": 1790000000,
  "expires_at": 1790000600,
  "command": "make build",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "paths": ["/work"],
  "run_via": "fork",
  "changes": {"added": ["/work/out.bin"], "modified": [], "deleted": [], "unchanged": 41},
  "side_effects": {
    "egress": "blocked",
    "destinations": [],
    "replayable": ["1 file change(s) under /work"],
    "non_replayable": []
  },
  "base_files": 42,
  "staged": {"/work/out.bin": {"blob": "000000", "mode": 33188, "size": 1048576}},
  "unstaged": [],
  "apply_started_at": null,
  "error": null
}
```

Timestamps are Unix seconds. `run_via` is `workspace-copy` (procbox), `fork` or `snapshot` (VM
sandboxes). `side_effects.egress` is `blocked`, `allow_listed` or `unrestricted`, and is **declared,
not enforced** (see the guide). `stdout` and `stderr` are capped at 64 KiB each, with a
`[truncated N bytes]` marker.

- `GET /v1/sandboxes/{id}/changesets` returns `{"items": [changeset, ...]}`, newest first.
- `POST .../changesets/{cs}/approve` and `.../reject` decide a `pending` changeset; no body.
- `POST .../changesets/{cs}/apply` writes an `approved` changeset's file changes into the real sandbox.

Status codes: 404 unknown changeset (or one that belongs to another sandbox); 409 invalid state
transition, conflict (the real files changed since the changeset's base; nothing is written), expired,
or another request is already working on that changeset; 422 the changeset cannot be applied (for
example files that could not be staged); 403 a non-admin token.

### Credential grants

Guide: [credential-broker.md](credential-broker.md).

`POST /v1/sandboxes/{id}/grants` returns 201:

```json
{"secret_ref": "github-token", "hosts": ["api.github.com"], "ttl_seconds": 900}
```

- `secret_ref` (required, 1-128 chars). Without `value`, the daemon reads
  `FLUXVM_SECRET_GITHUB_TOKEN` from its own environment.
- `value` (optional, write-only): the full header value, for example `"Bearer abc"`. Never returned.
- `hosts` (required, at least one): bare host names, exact or domain suffix. `*`, `/`, `:`, `@`, `?`
  and whitespace are rejected.
- `ttl_seconds` (1..=86400, default 3600) or `expires_at` (RFC 3339, at most 24 h ahead). If both are
  sent, `expires_at` wins.
- At most 32 live grants per sandbox.

Response (`GrantInfo`, which has no secret field):

```json
{
  "id": "7e0f0c52-5d57-4b35-8d3f-6a1a3d2b9c10",
  "sandbox_id": "0c1d2e3f-0000-4000-8000-000000000001",
  "secret_ref": "github-token",
  "hosts": ["api.github.com"],
  "created_at": "2026-10-08T12:00:00Z",
  "expires_at": "2026-10-08T12:15:00Z",
  "bound": true
}
```

`bound: false` means the sandbox has no known guest IP, so the grant cannot match any traffic.

- `GET /v1/sandboxes/{id}/grants` returns `{"grants": [GrantInfo, ...]}` (live grants only).
- `DELETE /v1/sandboxes/{id}/grants` revokes all and returns `{"revoked": true|false}`.
- `DELETE /v1/sandboxes/{id}/grants/{grant_id}` revokes one and returns `{"revoked": true}`, or 404.

Every verb is admin-only, `GET` included. Validation failures (bad host, bad TTL, unresolvable
`secret_ref`, more than 32 grants) return 400.

### Balloon and memory

Guide: [memory-density.md](memory-density.md).

`GET /v1/vms/{uuid}/balloon`, and `POST /v1/vms/{uuid}/balloon` (admin) with `{"balloon_mib": 256}`
(`0` deflates), both return:

```json
{"memory_mib": 1024, "target_mib": 256, "actual_mib": 192}
```

`target_mib` is what was requested; `actual_mib` is what the guest driver has reached so far. Only a
running VM on the flux-vm backend's KVM engine or the vz backend has a balloon; anything else returns 400, as does a
balloon that would leave the guest under 64 MiB.

`GET /v1/vms/{uuid}/memory`:

```json
{
  "vm_id": "0c1d2e3f-0000-4000-8000-000000000001",
  "configured_mib": 1024,
  "usage": {"rss_kib": 310000, "pss_kib": 180000, "private_kib": 120000, "shared_kib": 190000, "swap_kib": 0},
  "balloon": {"memory_mib": 1024, "target_mib": 0, "actual_mib": 0}
}
```

`usage` is `null` when the VM has no VMM process or `/proc/<pid>/smaps_rollup` is unreadable;
`balloon` is `null` when the VM has no balloon.

### First-command latency: `?ready=exec`

`POST /v1/vms`, `POST /v1/vms/{uuid}/fork` and `POST /v1/pools/{name}/claim` accept `?ready=exec` (or
`?wait_first_command=true`). The call then blocks until a trivial guest-agent exec (`true`) succeeds,
which needs the guest agent enabled, and adds timings measured from the start of the request. For
create and claim they are merged into the VM record:

```json
{"id": "...", "first_command_ms": 412, "phases": {"create_done_ms": 180, "agent_wait_ms": 231, "first_exec_ms": 412}}
```

`create_done_ms` is when create or claim returned, `agent_wait_ms` the extra wait for the first
successful exec, and `first_exec_ms` the total. For fork, the body keeps `items` and `elapsed_ms` and
adds `first_command_ms` (the slowest child) and `first_command` (one
`{first_command_ms, phases}` object per child). A `vm.first_command` event is recorded for each VM.
`scripts/bench-first-command.sh` uses it.

### Idempotency-Key

`POST /v1/vms`, `DELETE /v1/vms/{uuid}`, `POST /v1/vms/{uuid}/snapshot` and
`POST /v1/vms/{uuid}/fork` honor an `Idempotency-Key` request header (1-255 visible ASCII characters,
else 400). Other routes ignore it, and requests without it behave as before.

- The key is scoped by token tenant (or caller) and by method plus path.
- The first 2xx response is fsynced under `<state_dir>/idempotency` before it is returned. A retry
  with the same key and an identical method, path and body gets the stored status and body back with
  the response header `Idempotent-Replayed: true`, and nothing runs again.
- Same key with a different method, path or body: 422.
- Same key while the first request is still running: 409.
- Only 2xx responses are stored, so a failed attempt can be retried under the same key.
- Records expire after 24 hours. Request bodies over 16 MiB get 413. A response over 8 MiB returns
  500 and is not stored.
- The tenant guard runs before a stored response is replayed.

### Exec `policy` and `enforcement`

Guide: [guest-exec-policy.md](guest-exec-policy.md). `POST /v1/vms/{uuid}/agent` and
`POST /v1/sandboxes/{id}/process` accept an optional `policy` object (the procbox policy shape) next
to `command` and `timeout_seconds`. With a policy, the guest confines the command with Landlock and
seccomp, and the exec response carries `enforcement`:

```json
{"command": "ls /usr", "policy": {"read": ["/bin", "/usr", "/lib", "/lib64"]}}
```

```json
{"result": "exec", "exit_code": 0, "stdout": "...", "stderr": "", "enforcement": {"landlock_abi": 3, "filesystem": true, "not_enforced": []}}
```

If the policy cannot be enforced, the command is not run and the response is an error. Procbox
sandboxes reject a per-exec `policy` (400). Without `policy`, the response is unchanged and has no
`enforcement` key.
