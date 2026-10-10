# The guest agent on the vz backend

`fluxvm-guest-agent` (`crates/fluxvm-guest-agent`) is the in-guest agent the Linux backends already use for `exec`, file transfer, the
interactive shell and identity reset. It also runs in Linux guests on the `vz` backend, where it replaces SSH for sandbox commands and
files: no SSH handshake per command, and it works the same with or without a network card.

## How the daemon reaches it

```
daemon ── unix socket ──> fluxvm-vz-runner ── VZVirtioSocketDevice.connect(toPort: 17777) ──> fluxvm-guest-agent
         "CONNECT 17777\n"  <── "OK 17777\n"  then one JSON line each way
```

The runner already serves a Firecracker-style vsock proxy on `vm.vsock_socket` (it is how offline sandboxes reach the guest's sshd on
port 22). `fluxvm_vsock_client::call` dials it for `Vz` exactly as it does for Firecracker and Cloud Hypervisor, so the daemon has one
agent client for every backend. The daemon never links Virtualization.framework.

## Protocol

The shared crate `fluxvm-guest-protocol`: one JSON object per line, one request and one response per connection.

```json
{"token": "…", "op": "exec", "command": "uname -a", "timeout_seconds": 30}
{"result": "exec", "exit_code": 0, "stdout": "Linux …\n", "stderr": ""}

{"token": "…", "op": "put-file", "path": "/tmp/a", "content_base64": "aGk=", "mode": 420}
{"result": "file-written"}

{"token": "…", "op": "get-file", "path": "/tmp/a"}
{"result": "file-content", "content_base64": "aGk=", "mode": 420}

{"token": "…", "op": "ping"}
{"result": "pong"}
```

Errors are `{"result": "error", "message": "…"}`. Files are capped at 64 MiB per transfer.

## Turning it on

A VM opts in with `"agent": {"enabled": true}` (port 17777 by default). The daemon generates a token for it. On Linux hosts the
token is written into the guest's disk before boot; guestkit cannot open a disk on macOS, so on `vz` the token travels in cloud-init
instead (`write_files`, `/etc/fluxvm-guest-agent.token`, mode 0600). The agent refuses every request without a matching token.

The guest image must contain the agent and its unit: `/usr/local/bin/fluxvm-guest-agent` (a static aarch64 build) and
[systemd/fluxvm-guest-agent.service](../systemd/fluxvm-guest-agent.service), ordered after `cloud-init.service` so the token is in
place when the agent starts. The [agent-micro](agent-micro.md) image is built that way. Stock cloud images (`debian-13`) do not have
it, so sandboxes on them keep using SSH.

`agent.enabled` is refused for macOS guests: the agent is a Linux binary.

## Sandboxes

See [vsock-proxy.md](vsock-proxy.md) for how sandbox `exec` and file operations pick the agent and fall back to SSH.
