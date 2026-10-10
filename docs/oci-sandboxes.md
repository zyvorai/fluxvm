# Container sandboxes on a Mac (OCI images on `vz`)

A sandbox can be a container image instead of a Debian VM. Each container gets its own lightweight Linux VM on
Virtualization.framework: a small kernel boots straight into `fluxvm-oci-init`, which mounts the image as the root filesystem and
runs its entrypoint. There is no Docker, no shared Linux VM and no SSH. The sandbox is still an ordinary FluxVM sandbox, with a TTL,
quotas, an egress policy, exec and file transfer, and the REST, MCP and `fluxctl` APIs.

```bash
fluxctl sandbox run alpine:3.22 --rm -- sh -c 'echo hello from $(hostname); exit 3'
# hello from alpine-1a2b3c
echo $?   # 3

curl -s -X POST localhost:7788/v1/sandboxes -H 'Content-Type: application/json' \
  -d '{"ttl_seconds": 600, "profile": "tiny", "oci": {"image": "python:3.13-alpine", "command": ["sleep", "infinity"]}}'
curl -s -X POST localhost:7788/v1/sandboxes/$ID/process -d '{"command": "python3 -V"}' -H 'Content-Type: application/json'
curl -s localhost:7788/v1/sandboxes/$ID/logs?lines=50        # console tail, exit_code once the process has exited
```

MCP: `sandbox_create` with `oci_image` (plus optional `oci_command` and `oci_env`), then `sandbox_exec`, `sandbox_read_file` and
`sandbox_write_file` as for any sandbox. `sandbox_logs` returns the console and the exit code.

## Compared with Apple's `container`

Apple's `container` tool also runs one Linux VM per container. FluxVM's difference is that the container becomes a governed sandbox:

| | Apple `container` | FluxVM container sandbox |
|---|---|---|
| Isolation | One VM per container | One VM per container |
| Lifetime | Until stopped | TTL, quotas, memory-pressure admission ([agent-density.md](agent-density.md)) |
| Network | NAT | NAT, `offline` (no network card), or an egress allow-list enforced on the host |
| Access | CLI on the Mac | REST, MCP, `fluxctl`, with tokens, tenants and audit |
| Exec | Through its own agent | Through the FluxVM guest agent over vsock, with argv exec for images without a shell |
| Fleet | One Mac | The same sandbox API as every FluxVM host; container sandboxes are placed on Macs (`vz`) |
| Image build | `container build` | Not provided: use images built elsewhere |

## Request

`POST /v1/sandboxes` with an `oci` object. `ttl_seconds`, `profile`, `vcpus`, `memory_mib`, `offline`, `allow_hosts`,
`http_proxy_port(s)` and `name` apply as for other sandboxes. `template`, `spec`, `image`, `procbox`, `volumes`, `gpus` and
`confidential` are refused with `oci`. Without a profile or size the VM gets 1 vCPU and 512 MiB.

| Field | Default | Meaning |
|---|---|---|
| `image` | (required) | `alpine:3.22`, `ghcr.io/org/app:1.2`, `nginx@sha256:…`. Docker Hub names are expanded (`alpine` → `docker.io/library/alpine:latest`). |
| `command` | the image's `Cmd` | Replaces `Cmd`. |
| `entrypoint` | the image's `Entrypoint` | Replaces `Entrypoint` and drops the image's `Cmd`, as `docker run --entrypoint` does. |
| `env` | `[]` | `KEY=value`, added to or replacing the image's `Env`. |
| `workdir` | the image's `WorkingDir`, else `/` | Created if missing. |
| `user` | the image's `User`, else `65534:65534` | `uid[:gid]` or `name[:group]`, resolved against the image's `/etc/passwd` and `/etc/group`. |
| `read_only_root` | `true` | `false` mounts the sandbox's own copy of the image read-write; it is kept until the sandbox is deleted. |
| `exit_policy` | `keep` | `keep` leaves the VM up for exec after the process exits; `poweroff` stops it. `fluxctl sandbox run` uses `poweroff`. |

`fluxctl sandbox run IMAGE [--profile P] [--offline | --allow-host H…] [-e K=V…] [-w DIR] [-u USER] [--entrypoint "…"]
[--writable-root] [--rm] [--name N] -- CMD…` creates the sandbox with `exit_policy: poweroff`, prints its console as it goes and
exits with the container's exit code. It works locally and with `--server`.

`POST /v1/sandboxes/{id}/process` takes `{"process": {"argv": [...], "env"?, "cwd"?}}` as well as `{"command": "..."}`, so commands
run in images that have no `/bin/sh` (distroless). Commands run through the guest agent, as root, with the agent's environment.
They do not inherit the image's `Env` or the proxy settings.

## How it boots

1. **Pull** (host, pure Rust): resolve the reference, pick `linux/arm64` from an index, and download the manifest, config and layers
   into `state_dir/oci/blobs/sha256/`. Every blob is checked against its digest. Anonymous token auth is used by default;
   `[[apple.oci_registry_credentials]]` adds per-registry credentials.
2. **Build the rootfs once per manifest digest**: a short-lived *builder VM* boots the same kernel and initramfs in `unpack` mode.
   It has the blobs on a read-only virtiofs share, a blank target disk, and no network card. It runs `mke2fs`, then applies the
   layers in order with OCI whiteouts and opaque directories, keeping owners, modes, xattrs and device nodes. It checks each
   layer's `diff_id` and prints `FLUXVM-UNPACK-OK` on its console. The result is cached as `state_dir/oci/rootfs/<digest>.ext4`,
   with metadata in `<digest>.json`. Its size is the larger of 1 GiB and four times the compressed layers plus 512 MiB; the file
   is sparse, so it uses less disk than that. Concurrent requests for the same digest wait for one build. A build times out
   after 15 minutes.
3. **Clone**: each sandbox gets an APFS clone of the cached image (copy-on-write, so it takes almost no time or space).
4. **Boot**: `VZLinuxBootLoader` loads `oci-kernel` and `oci-initrd` directly; there is no firmware or bootloader. The kernel
   command line defaults to `console=hvc0 loglevel=4 panic=-1`. The disks are the root clone (`/dev/vda`) and nothing else. A
   read-only virtiofs share tagged `fluxvm-meta`, kept in the VM's workspace, holds `config.json` and the agent token (mode 0600).
5. **`fluxvm-oci-init` (PID 1)**:
   - Mounts the root. With `read_only_root`, this is an overlay of the read-only ext4 and a tmpfs, remounted read-only, so the
     image cannot be changed.
   - Sets the hostname and writes `/etc/hosts` and `/etc/resolv.conf`.
   - Brings up `eth0` with its own DHCP client, unless the sandbox is offline.
   - Moves into the new root and starts the guest agent from `/.fluxvm` (a read-only bind of the initramfs tools).
   - Runs the process with the resolved user, supplementary groups dropped and `no_new_privs`. Its output goes to the
     console, which is the VM's log.
   - Reaps zombies. When the process exits, it prints `FLUXVM-EXIT <code>`. A startup failure (unknown user, missing
     binary) prints `FLUXVM-INIT-ERR <reason>` instead.
6. **Ready**: create returns when the guest agent answers a ping over vsock (port 17777), or when the process has already exited.
   An init error fails the create at once, and the VM is deleted.

`GET /v1/sandboxes/{id}/logs?lines=N` returns `{status, oci, exit_code, init_error, log}`. The markers are searched in the whole log;
`log` is only the tail.

## Security defaults

- One VM per container: a kernel exploit inside the container is still contained by the hypervisor.
- The root is read-only. `/tmp` and `/run` are tmpfs (`nosuid,nodev`); `/proc` and `/sys` are mounted `nosuid,nodev,noexec`, and
  `/sys` is read-only.
- The process runs as `65534:65534` unless the image or the request names a user, with `no_new_privs`.
- There is no SSH server, and none is needed: exec and files go only through the guest agent, authenticated with a per-VM token.
  OCI sandboxes have no SSH fallback.
- Networking: by default the VM has NAT access like other `vz` sandboxes. `offline: true` attaches no network card at all.
  `allow_hosts` also attaches no card. Instead, init relays `127.0.0.1:3128` over vsock to the runner's allow-list proxy on the
  host and sets `http_proxy`/`https_proxy` for the process. Host matching, port limits (80 and 443) and the refusal of private
  addresses are the same as for other sandboxes ([macos-sandboxes.md](macos-sandboxes.md)).
- The builder VM never has a network card. Its blob share is read-only, and layer paths are joined securely (no `..`, no escape
  through symlinks).
- Boot artifacts given as files are checked against their `.sha256` sidecars when present.

## Managing images

```bash
fluxctl oci pull alpine:3.22     # POST   /v1/oci/images   (admin)
fluxctl oci ls                    # GET    /v1/oci/images
fluxctl oci rm alpine:3.22        # DELETE /v1/oci/images/{digest|reference} (admin)
fluxctl oci prune                 # POST   /v1/oci/prune   (admin): images no VM uses, and unreferenced blobs
```

Sandboxes are labelled `fluxvm.oci=<manifest digest>` and `fluxvm.oci.image=<reference>`; `prune` keeps any image a VM still uses.

## Configuration

```toml
[apple]
oci_kernel = "oci-kernel"            # catalog name, absolute path, or a file in state_dir/oci/boot
oci_initrd = "oci-initrd"
oci_cmdline = "console=hvc0 loglevel=4 panic=-1"
oci_builder_memory_mib = 1024

[[apple.oci_registry_credentials]]
registry = "ghcr.io"
username = "me"
password = "…"
```

`policy.require_catalog_names` accepts only signed catalog names for VM images, so it refuses container sandboxes, whose root is a
cached rootfs path.

## Boot artifacts

`scripts/build-oci-boot.sh` runs on Linux arm64 and writes `dist/oci-boot/oci-kernel` and `oci-initrd`, each with a `.sha256`
file. The `oci-boot` CI workflow on `ubuntu-24.04-arm` builds and uploads them.

- **Kernel**: Linux 6.12 built from `crates/fluxvm-hypervisor/guest/oci-vz.config.fragment`, starting from `allnoconfig`. It
  includes virtio-pci, vsock, virtio-fs, ext4, overlayfs, cgroups, namespaces, seccomp and the PL031 clock, with no modules.
  The script fails if any requested `=y` option does not survive Kconfig.
- **Initramfs**: zstd-compressed, containing:
  - static musl builds of `fluxvm-oci-init` (as `/init`) and `fluxvm-guest-agent`;
  - a static `mke2fs` (e2fsprogs 1.47.1).
- **Source downloads**: the kernel and e2fsprogs sources are checked against kernel.org's sha256 sums.

Put the two files in `state_dir/oci/boot`, register them as catalog entries, or point `apple.oci_kernel` and `apple.oci_initrd`
at them.

## Limits

- `linux/arm64` images only; there is no x86 emulation for containers.
- No image building (`docker build`); pull images built elsewhere.
- No volumes, GPUs, Rosetta or port publishing yet. Reach a server in the sandbox with `/v1/sandboxes/{id}/http/{port}/…`, as for
  other sandboxes.
- The first use of an image pulls it and builds its rootfs (seconds to minutes, depending on its size). Later sandboxes from the
  same digest only clone it.
- There is no warm pool for container sandboxes yet; each one cold-boots. Hibernation uses the generic `vz` path and has not been
  tested on container sandboxes.
- A process's output beyond 10,000 lines between two polls is skipped by `fluxctl sandbox run`. The full console stays in the VM's
  `console.log` until the sandbox is deleted.
- Exec does not inherit the image's environment (see above).

## Verified

Unit tests cover:

- reference parsing, platform selection, digest checks and token auth;
- layer application with whiteouts, opaque directories and diff_id checks;
- user resolution and process resolution (Docker's entrypoint and cmd rules);
- the DHCP message parser and the console markers;
- the request validation and the VM request built for a container;
- the capability rules for tagged shares and `init_config`;
- the meta share contents.

CI builds the boot artifacts and runs `clippy -D warnings` and the tests for the init on Linux arm64.

`scripts/oci-live-test.sh` covers the following on Apple silicon. It has **not been run on hardware yet**, so the cold-start time
target (under 2 s with a cached rootfs) is not measured.

- exit codes, a read-only root with a writable `/tmp`, and uid 65534;
- argv exec in a distroless image;
- offline mode, an allow-list, and TTL expiry;
- the cold-start time.
