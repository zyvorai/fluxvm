# The agent-micro image

`agent-micro` is Debian 13's arm64 cloud image with the [guest agent](vsock-agent.md) installed and enabled. A sandbox on it runs
commands and moves files over vsock instead of SSH, which is quicker per command and the same with or without a network card. It is
meant for many small sandboxes on one Mac (see [agent-density.md](agent-density.md)).

| Property     | Value                                                                      |
|--------------|----------------------------------------------------------------------------|
| Base         | `debian-13-generic-arm64` (partitions and EFI boot unchanged)               |
| Added        | `/usr/local/bin/fluxvm-guest-agent` (static, aarch64), its systemd unit     |
| Agent port   | vsock 17777, token from cloud-init                                          |
| cloud-init   | NoCloud only (FluxVM always attaches a seed)                                |
| Fallback     | sshd stays, so SSH works if the agent does not answer                       |

## Build

On Linux (it needs loop devices; on a Mac, use a Linux VM):

```bash
rustup target add aarch64-unknown-linux-musl
GUEST_AGENT_TARGET=aarch64-unknown-linux-musl scripts/build-guest-agent-static.sh
sudo scripts/build-agent-micro.sh out/          # downloads and verifies debian-13, writes out/agent-micro-arm64.raw + .sha256
```

`BASE=/path/disk.raw` starts from a local Debian 13 disk instead of downloading one. `TRIM=1` (arm64 builders only) purges packages
a sandbox does not need. The unit is ordered after `cloud-init.service`, because the agent reads its token once at start.

## Register it on the Mac

The image is a catalog entry, not a built-in download (there is no published build yet):

```bash
fluxctl catalog add agent-micro --source /path/agent-micro-arm64.raw --format raw
```

`catalog.path` must be set in `fluxvm.toml`. The entry is pinned to the file's SHA-256; sign it with `fluxctl catalog sign` if
`catalog.trusted_signers` is configured.

## Use

```json
{"name": "micro-agent", "image": "agent-micro", "profile": "tiny", "offline": true, "ttl_seconds": 600}
```

`image` (with neither `template` nor `spec`) replaces `debian-13` in the default sandbox spec. See
[examples/sandbox-agent-micro.json](../examples/sandbox-agent-micro.json). Sandboxes on `agent-micro` cold-boot; the warm pool holds
`debian-13` slots.

## Not measured yet

The image has not been built and booted in CI; its boot time and size on a Mac are not measured. It is about the size of
`debian-13` (a few hundred MB used in a sparse 3 GiB disk), not a minimal rootfs.
