# Sandbox commands over vsock on the vz backend

How `POST /v1/sandboxes/{id}/process`, `/fs/read`, `/fs/write` (and the MCP tools) reach a `vz` guest.

## Which path

1. **Guest agent, over vsock.** When the sandbox has the agent enabled, the daemon connects to the runner's vsock socket
   (`vm.vsock_socket`, mode 0600), sends `CONNECT 17777`, and exchanges one [guest-protocol](vsock-agent.md) request and response.
   The runner relays the bytes to the guest with `VZVirtioSocketDevice.connect(toPort:)`. No host or guest network port is involved.
2. **SSH, as before.** When the agent is not enabled, or it does not answer (not installed, not started yet, wrong token file),
   the same request goes over SSH: to the guest's address, or for an offline guest to its sshd on vsock port 22 through the same
   runner socket.

An answer from the agent is final, including an error it reports (a missing file, a non-zero exit). Only a failure to reach it falls
back. A per-exec `policy` (Landlock and seccomp confinement) and an argv `process` need the agent; without it the request is
refused.

## Which sandboxes have the agent

- `"image": "agent-micro"` (see [agent-micro.md](agent-micro.md)): enabled automatically.
- A `spec` or `template` with `"agent": {"enabled": true}`: enabled with the caller's port.
- A [container sandbox](oci-sandboxes.md) (`oci`): always, and **only** the agent. The image has no sshd, so there is no fallback;
  an agent that does not answer is an error that says so. Readiness is an agent `ping`, not SSH.
- Everything else, including the default `debian-13` and warm slots: SSH only.

The daemon generates the token and cloud-init writes it to `/etc/fluxvm-guest-agent.token` in the guest (container sandboxes get it
on their read-only `fluxvm-meta` share instead). A warm or hibernated
sandbox keeps its agent running across the restore, so it answers at once.

## Metrics

`/metrics` has `fluxvm_vz_agent_calls_total` (answered by the agent) and `fluxvm_vz_agent_ssh_fallbacks_total` (agent enabled but
unreachable). A rising fallback count on `agent-micro` sandboxes means the agent is not starting in the image.

## Runner

The runner's relay copies both directions until each side has finished, then closes the unix socket and releases the vsock
connection. (Before, every relayed connection stayed open for the life of the VM, which one connection per command would have run
into the descriptor limit.) The same relay serves the TCP forwards between guests and the allow-listed egress proxy.
