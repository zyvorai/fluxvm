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

## How it differs from Linux

- **SSH, not the vsock agent.** Linux sandboxes talk to a guest agent over vsock. `vz` guests run stock cloud images with no agent, so
  the daemon uses SSH with its own key (`<state_dir>/sandbox_ed25519`, created on first use and authorised by cloud-init as user
  `sandbox`). A file is moved with `cat`/`chmod`, so the limits are 32 MiB per file and a normal Linux userland in the guest.
- **No per-exec policy.** `policy` (Landlock/seccomp confinement of one command) needs the agent and is refused on `vz`.
- **Network is not isolated.** A sandbox on `network.mode = "user"` (the default) has full outbound access through the Mac's NAT, and
  Virtualization.framework gives no way to filter it. Use `"network": {"mode": "none"}` for a sandbox that cannot reach anything, but
  note that it also cannot be reached over SSH, so exec and file access do not work on it yet. An allow-listed egress proxy is planned.
- Not yet on `vz`: speculate/changesets, snapshots through the sandbox endpoints, volumes, GPUs.

## Verified

On an Apple M4 (macOS 27.2): create with no body, exec with exit code and output, file write and read with awkward paths and a mode,
a missing file reported cleanly, the TTL removing the sandbox, no runner left behind, and the same through the MCP server over stdio.
`scripts/macos-live-test.sh` covers the REST path.
