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

## How it differs from Linux

- **SSH, not the vsock agent.** Linux sandboxes talk to a guest agent over vsock. `vz` guests run stock cloud images with no agent, so
  the daemon uses SSH with its own key (`<state_dir>/sandbox_ed25519`, created on first use and authorised by cloud-init as user
  `sandbox`). A file is moved with `cat`/`chmod`, so the limits are 32 MiB per file and a normal Linux userland in the guest.
- **No per-exec policy.** `policy` (Landlock/seccomp confinement of one command) needs the agent and is refused on `vz`.
- **Network is not isolated.** A sandbox on `network.mode = "user"` (the default) has full outbound access through the Mac's NAT, and
  Virtualization.framework gives no way to filter it. Use `"network": {"mode": "none"}` for a sandbox that cannot reach anything, but
  note that it also cannot be reached over SSH, so exec and file access do not work on it yet. An allow-listed egress proxy is planned.
- Sandboxes of any other shape (a `spec`, a `template`, volumes, a different size) always cold-boot.
- Not yet on `vz`: speculate/changesets, snapshots through the sandbox endpoints, volumes, GPUs.

## Verified

On an Apple M4 (macOS 27.2): create with no body, exec with exit code and output, file write and read with awkward paths and a mode,
a missing file reported cleanly, the TTL removing the sandbox, no runner left behind, and the same through the MCP server over stdio.
With the pool: 2 warm slots built in about 15 s after the first create; two concurrent creates took 1.7 s and 3.6 s (7.6 s cold), got
different addresses and did not see each other's files; a create after the pool was consumed and refilled took 1.9 s.
`scripts/macos-live-test.sh` covers the REST path.
