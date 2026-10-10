# Agent sandboxes on a Mac

The sandbox API (`POST /v1/sandboxes`, `/process`, `/fs/read`, `/fs/write`, and the MCP tools `sandbox_create`, `sandbox_exec`,
`sandbox_read_file`, `sandbox_write_file`) works on the `vz` backend. An agent gets a disposable Linux VM, runs commands and moves files
in and out, and the VM disappears when its TTL runs out or it is deleted.

```bash
fluxctl serve &                                     # or: brew services start fluxvm
curl -s -X POST localhost:7788/v1/sandboxes -d '{"ttl_seconds": 600}' -H 'Content-Type: application/json'
# -> {"id": "…", "backend": "vz", "status": "running", …}   (returns once commands can run, about 8 s)
curl -s -X POST localhost:7788/v1/sandboxes/$ID/process -d '{"command": "uname -a; exit 3"}' -H 'Content-Type: application/json'
# -> {"result":"exec","exit_code":3,"stdout":"Linux … aarch64 …\n","stderr":""}
```

With no `template` and no `spec`, a Mac creates a 2-vCPU, 2 GiB Debian 13 VM (`image: "debian-13"`). Pass a `spec` (with
`"backend": "auto"`, which resolves to `vz` on a Mac) to choose the image and size. `fluxctl mcp serve --allow-write` offers the same
operations to an agent over MCP.

## Fast starts: the warm pool

A cold sandbox takes about 8 s. The daemon keeps `sandbox.warm_slots` (default 2 on a Mac, 0 elsewhere) warm VMs ready: stopped VMs
with a `warm` snapshot, labelled `fluxvm.pool=sandbox`. A default-shaped create (no `template`, no `spec`, no volumes, no resource
overrides, not tenant-scoped) restores one of them, which takes about 2 s, and that VM simply becomes the sandbox (it keeps its
`warm` snapshot; deleting the sandbox deletes it). The first create cold-boots and starts filling the pool in the background; every
create that claims a slot starts a refill. If no slot is free, or a restore fails (for example on a locked screen), the create
cold-boots as before.

Why a pool and not one snapshot restored many times: a saved VM state is tied to the MAC address and machine identifier it was saved
with (restoring with another MAC or identifier fails with "invalid argument"), and two VMs restored from one snapshot share a MAC and
so an address on the Mac's NAT; the Mac then reaches one or the other at random. Each slot therefore has its own MAC and snapshot, so
the number of sandboxes that can start fast at once is `warm_slots`.

```toml
[sandbox]
warm_slots = 4   # 0 turns the pool off
```

Slots show up in `fluxctl list` as `sandbox-slot-…`. They cost disk (an APFS clone of the image plus a few hundred MB of saved memory
each), and no memory while stopped. Restoring needs an unlocked login session.

For many sandboxes on one Mac (sizes such as `"profile": "tiny"`, admission on macOS memory pressure, idle pause and hibernate,
`POST /v1/sandboxes/warm` and `GET /v1/sandboxes/density`), see [agent-density.md](agent-density.md).

## How it differs from Linux

- **SSH unless the image has the agent.** Linux sandboxes talk to a guest agent over vsock. Stock cloud images (`debian-13`) have no
  agent, so the daemon uses SSH with its own key (`<state_dir>/sandbox_ed25519`, created on first use and authorised by cloud-init as
  user `sandbox`). A file is moved with `cat`/`chmod`, so the limits are 32 MiB per file and a normal Linux userland in the guest.
  Sandboxes on the `agent-micro` image use the agent over vsock and fall back to SSH; see [vsock-proxy.md](vsock-proxy.md).
- **Per-exec policy only with the agent.** `policy` (Landlock/seccomp confinement of one command) needs the agent and is refused on
  guests without it.
- **Network is not isolated by default.** A sandbox on `network.mode = "user"` has full outbound access through the Mac's NAT, and
  Virtualization.framework gives no way to filter it.
- **Offline sandboxes are.** `{"offline": true}` (MCP: `sandbox_create` with `offline`) attaches no network card at all, so there is
  nothing for the guest to route through; it has only `lo`. Commands and files still work: the daemon reaches the guest's sshd over
  **vsock** (stock Debian 13 images have `sshd-vsock.socket` on port 22) through the runner, using a built-in relay
  (`fluxctl vsock-proxy`, ssh's ProxyCommand). They cold-boot (about 6 s, no warm pool). For sandboxes that need *some* network, see below.
- **Allow-listed egress.** `{"allow_hosts": ["example.com", "*.pypi.org"]}` (MCP: `sandbox_create` with `allow_hosts`) implies `offline`:
  the guest has no card, and its only way out is an HTTP(S) proxy the runner serves over vsock (guest to host, port 3128). A small
  forwarder in the guest (`fluxvm-egress.service`, written by cloud-init) exposes it on `127.0.0.1:3128`, and `/etc/environment` plus an
  apt config point shells, curl and apt at it. The host decides: names are matched in the runner (exact, or `*.suffix`), only ports 80
  and 443, and a name that resolves to a loopback, private, link-local or CGNAT address is refused so an allowed name cannot be aimed at
  the Mac or the LAN. Refusals are `403` naming the host. A program that ignores the proxy settings simply has no route.
  Limits: HTTP and HTTPS only (no raw TCP, no UDP; DNS is done by the host), tools must honour `http_proxy`, the allow-list is fixed at
  creation, and these sandboxes cold-boot. HTTPS is tunnelled (CONNECT), not inspected.
- **The pool follows the base image.** Each warm slot is labelled with the build of `debian-13` it was made from
  (`fluxvm.image-id`). When a newer build is downloaded (the vendor's list is checked at most once a day), slots from the old one are
  never restored: the next sandbox cold-boots, the old slots are deleted, and the pool is rebuilt from the new image. `fluxctl run`
  warm templates are not covered yet; delete a `warm-*` VM to rebuild it.
- Sandboxes of any other shape (a `spec`, a `template`, volumes, a different size) always cold-boot.
- **Speculate and changesets work.** `POST /v1/sandboxes/{id}/speculate {"command", "paths": [...]}` snapshots the running sandbox, runs
  the command, records which files under `paths` were added, modified or deleted (with their contents), then puts the VM back by
  relaunching it from the snapshot. The result is a pending changeset; `approve` then `apply` writes it into the sandbox, refusing
  with a conflict if those files changed meanwhile. Measured: about 5 s for a small command. `paths` is required (the guest root is too
  large to scan). Limits: it needs an **unlocked login session** (it uses snapshot restore), the VM restarts its processes' memory
  state back to the snapshot (anything the command did in memory is discarded too), and only file changes are captured: network
  calls the command made really happened (the changeset's `side_effects` says whether the sandbox could reach out).
- Not yet on `vz`: volumes, GPUs.

## Verified

On an Apple M4 (macOS 27.2): create with no body, exec with exit code and output, file write and read with awkward paths and a mode,
a missing file reported cleanly, an offline sandbox with only `lo` (DNS and routes fail) still running commands and file transfers, the TTL removing the sandbox, no runner left behind, and the same through the MCP server over stdio.
With the pool: 2 warm slots built in about 15 s after the first create; two concurrent creates took 1.7 s and 3.6 s (7.6 s cold), got
different addresses and did not see each other's files; a create after the pool was consumed and refilled took 1.9 s.
`scripts/macos-live-test.sh` covers the REST path.
