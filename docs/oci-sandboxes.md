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

```bash
# A web server with a published port, a persistent volume, restarts and a health check
fluxctl sandbox run nginx:alpine -p 8080:80 -v site:/usr/share/nginx/html --restart always \
  --health-cmd "wget -q -O /dev/null http://127.0.0.1" --health-interval 5
curl localhost:8080
```

MCP: `sandbox_create` with `oci_image` (plus optional `oci_command`, `oci_env` and `oci_ports`), then `sandbox_exec`,
`sandbox_read_file` and `sandbox_write_file` as for any sandbox. `sandbox_logs` returns the console and the exit code.

Several containers that work together (a database and an app, say) are a stack: see
[macos-stacks.md](macos-stacks.md#container-services), which can also import a `docker-compose.yml`.

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
`http_proxy_port(s)`, `volumes` and `name` apply as for other sandboxes. `template`, `spec`, `image`, `procbox`, `gpus` and
`confidential` are refused with `oci`. Without a profile or size the VM gets 1 vCPU and 512 MiB.

| Field | Default | Meaning |
|---|---|---|
| `image` | (required) | `alpine:3.22`, `ghcr.io/org/app:1.2`, `nginx@sha256:…`. Docker Hub names are expanded (`alpine` → `docker.io/library/alpine:latest`). |
| `platform` | `linux/arm64` | `linux/amd64` runs an x86-64 image under Rosetta. See [x86-64 images](#x86-64-images-rosetta). |
| `command` | the image's `Cmd` | Replaces `Cmd`. |
| `entrypoint` | the image's `Entrypoint` | Replaces `Entrypoint` and drops the image's `Cmd`, as `docker run --entrypoint` does. |
| `env` | `[]` | `KEY=value`, added to or replacing the image's `Env`. Stored in the VM record and returned by `GET /v1/vms/{id}`. |
| `secret_env` | `{}` | `{"NAME": "value"}` added to the process environment but never stored in the VM record or returned (write-only; at most 64 entries, 64 KiB). See [Security defaults](#security-defaults). |
| `workdir` | the image's `WorkingDir`, else `/` | Created if missing. |
| `user` | the image's `User`, else `65534:65534` | `uid[:gid]` or `name[:group]`, resolved against the image's `/etc/passwd` and `/etc/group`. |
| `read_only_root` | `true` | `false` mounts the sandbox's own copy of the image read-write; it is kept until the sandbox is deleted. |
| `exit_policy` | `keep` | `keep` leaves the VM up for exec after the process exits; `poweroff` stops it. `fluxctl sandbox run` uses `poweroff`. |
| `ports` | `[]` | Published TCP ports, `HOST:CONTAINER` (or `PORT`, optionally `/tcp`): the Mac's `127.0.0.1:HOST` reaches the container. See [Published ports](#published-ports). |
| `expose` | `[]` | Container ports other sandboxes and VMs on this Mac reach at the NAT gateway, same number on both sides. Used by stacks. |
| `gateway_hosts` | `[]` | Host names written into the container's `/etc/hosts`, pointing at the NAT gateway. Used by stacks so `db` resolves. |
| `restart` | `no` | `no`, `on-failure` or `always`. See [Restarts and health checks](#restarts-and-health-checks). |
| `max_restarts` | unlimited | Stop restarting after this many restarts. |
| `healthcheck` | none | `{"command": [argv…], "interval_seconds": 30, "timeout_seconds": 5, "retries": 3, "start_period_seconds": 0}`. |

`fluxctl sandbox run IMAGE [--platform linux/amd64] [--profile P] [--offline | --allow-host H…] [-e K=V…] [--secret-env NAME…] [-w DIR] [-u USER] [--entrypoint "…"]
[--writable-root] [-p HOST:CONTAINER…] [-v NAME:/path[:ro]…] [--restart POLICY] [--max-restarts N] [--health-cmd "…"
[--health-interval S]] [--rm] [--name N] -- CMD…` creates the sandbox with `exit_policy: poweroff`, prints its console as it goes
and exits with the container's exit code. It works locally and with `--server`.

### Published ports

`ports` uses the same runner forwards as `fluxctl run -p` for VMs: the runner listens on `127.0.0.1:HOST` on the Mac and connects
to the container's port. The runner learns the container's address from init, which prints `VELORA-IP <address>` on the console
after its DHCP lease. Host ports must be 1024 or higher (the daemon does not run as root), each host port may be published once,
and a host port another VM on this Mac already publishes is refused. Only TCP. Ports, `expose` and `gateway_hosts` need the
network card, so they cannot be combined with `offline` or `allow_hosts`.

### x86-64 images (Rosetta)

`"platform": "linux/amd64"` (`fluxctl sandbox run --platform linux/amd64`, `fluxctl oci pull --platform linux/amd64`, `platform` in
a stack file or a compose service, MCP `oci_platform`) pulls the image's amd64 variant and runs it under Rosetta for Linux:

```bash
fluxctl sandbox run --platform linux/amd64 alpine:3.22 --rm -- uname -m   # x86_64
```

- The VM gets the runner's Rosetta share (`apple.rosetta`). Before the container starts, init mounts it at `/fluxvm/rosetta` (seen
  as `/.fluxvm/rosetta` in the container) and registers it with `binfmt_misc` for x86-64 ELF files, with the `F` flag (the
  interpreter is opened at registration, so it works in any mount namespace) and `C` (credentials from the binary). The kernel and
  init are still arm64; only the image's binaries are translated.
- The amd64 and arm64 variants of one tag have different manifest digests, so each gets its own cached rootfs, and
  `fluxctl oci ls` shows each entry's `architecture`.
- Rosetta must be installed on the Mac: `softwareupdate --install-rosetta --agree-to-license`. Without it, create fails with that
  hint before anything is pulled.
- Translated code is slower than native, and Rosetta's ahead-of-time cache (`rosettad`) is not set up yet, so each process translates
  on first run. Images that need AVX-512 or other x86 instructions Rosetta does not translate will not run.

### Private networks

`networks: [{"name", "address"?}]` joins private networks shared only with the other guests on them (see "Private networks between
guests" in [macos.md](macos.md)); init gives the card its `10.89.N.H/24` address by MAC. `hosts: [{"ip", "names"}]` adds
`/etc/hosts` lines, for example the other members' names. Works with `offline` (the sandbox then reaches only the other guests on
its networks), but not with `allow_hosts`.

```bash
curl -s -X POST localhost:7788/v1/sandboxes -d '{"offline": true, "oci": {"image": "redis:7-alpine", "networks": [{"name": "lab"}]}}'
fluxctl vznet ls
```

### Volumes

`volumes: [{"name", "guest_path", "read_only"?}]` attaches named, persistent directories. They live in
`<volumes_dir or state_dir/volumes>/<tenant>/<name>` on the Mac and survive the sandbox. They are passed as virtiofs shares tagged
`fluxvm-vol<N>`, which init mounts at `guest_path` (`nosuid,nodev`, plus `ro` when read-only) before it switches into the image's
root, so no cloud-init is involved. Names follow the QEMU sandbox volume rules, with at most 4 per sandbox, and a volume attached
to another VM is refused. Unlike VM volumes, `guest_path` may be anywhere in the image (`/var/lib/postgresql/data`,
`/etc/nginx/conf.d`) except `/`, `/proc`, `/sys`, `/dev`, `/tmp`, `/run` and `/.fluxvm`, which init manages.

### Restarts and health checks

Init supervises the process. With `restart: on-failure` it starts the process again after a non-zero exit, a signal, or being
stopped as unhealthy; with `always`, after any exit. Restarts back off from 1 s, doubling up to 60 s, and stop after
`max_restarts`. Each restart prints `FLUXVM-RESTART <n> <exit code>`; `FLUXVM-EXIT` is printed only when the process will not be
started again.

A `healthcheck` command runs inside the container every `interval_seconds`, as the process's user with its environment, without a
shell (use `["/bin/sh", "-c", "…"]` for one). A run that exceeds `timeout_seconds` fails. After `retries` consecutive failures
(ignoring failures during `start_period_seconds` after a start) init prints `FLUXVM-HEALTH unhealthy`; the next success prints
`FLUXVM-HEALTH healthy`. When the process is unhealthy and `restart` is not `no`, init sends `SIGTERM` to its process group,
`SIGKILL` 10 s later, and restarts it under the policy.

`POST /v1/sandboxes/{id}/process` takes `{"process": {"argv": [...], "env"?, "cwd"?}}` as well as `{"command": "..."}`, so commands
run in images that have no `/bin/sh` (distroless). Commands run through the guest agent, as root, with the agent's environment.
They do not inherit the image's `Env` or the proxy settings.

## How it boots

1. **Pull** (host, pure Rust): resolve the reference, pick `linux/arm64` (or `linux/amd64`) from an index, and download the manifest, config and layers
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
   - Brings up `eth0` with its own DHCP client, unless the sandbox is offline, prints `VELORA-IP <address>`, and adds the
     `gateway_hosts` to `/etc/hosts`.
   - Mounts the volumes.
   - Moves into the new root and starts the guest agent from `/.fluxvm` (a read-only bind of the initramfs tools).
   - Runs the process with the resolved user, supplementary groups dropped and `no_new_privs`. Its output goes to the
     console, which is the VM's log.
   - Reaps zombies, runs the health check and applies the restart policy. When the process has exited for good, it prints
     `FLUXVM-EXIT <code>`. A startup failure (unknown user, missing binary) prints `FLUXVM-INIT-ERR <reason>` instead.
6. **Ready**: create returns when the guest agent answers a ping over vsock (port 17777), or when the process has already exited.
   An init error fails the create at once, and the VM is deleted.

`GET /v1/sandboxes/{id}/logs?lines=N` returns `{status, oci, exit_code, init_error, restarts, health, log}`. The markers are
searched in the whole log; `log` is only the tail.

## Warm pool

With `apple.oci_warm_slots` above 0, the daemon keeps that many container VMs per size in `apple.oci_warm_sizes` booted and
waiting. A matching sandbox takes one instead of cold-booting:

```toml
[apple]
oci_warm_slots = 2
oci_warm_sizes = ["1x512", "2x1024"]   # VCPUSxMEMORY_MIB
```

- **A slot** is a running VM whose init is in `wait` mode. The kernel has booted, the network card holds its DHCP lease, and init
  listens on vsock port 1026 and prints `FLUXVM-WARM-READY`. Its root disk is a 1 MiB placeholder, it has a USB controller, and its
  four volume shares (`fluxvm-vol0..3`) point at an empty directory. Slots are labelled `fluxvm.oci-warm=<size>` and have the
  Rosetta share when Rosetta is installed.
- **Claiming** happens when a create matches a ready slot's size:
  1. The daemon clones the image's rootfs into the slot's workspace and writes the sandbox's boot config, under a new file name,
     and its secrets to the meta share.
  2. It points each volume share at the volume (`share-set` on the runner's control socket).
  3. It hot-attaches the rootfs as USB mass storage.
  4. It sends `{"config", "disk": "/dev/sda"}` over vsock. Init mounts the disk and continues exactly as on a cold boot.
  5. The VM record is rewritten as an ordinary sandbox whose disk is the rootfs, so a restart cold-boots it normally.
- **Eligible sandboxes**: the NAT network with no `ports` or `expose`, no `allow_hosts`, no `offline`, no private `networks`,
  at most four volumes, and the exact size. `linux/amd64` needs a slot built with Rosetta. Anything else cold-boots, and so does a
  create when no slot is ready.
- **Failures**: if a claim fails (for example a kernel built without USB storage), the slot is deleted, the sandbox cold-boots,
  and the pool is not refilled for 10 minutes.
- **Refill**: after each claim or miss, and on the AutoPause scan (`sandbox.autopause_scan_secs`). Slots that stopped, for
  example after a daemon restart, are replaced.
- **Needs** macOS 15 for USB hot-attach, and a kernel with the USB options in `oci-vz.config.fragment` (built by
  `scripts/build-oci-boot.sh` from this release on).

`GET /v1/sandboxes/density` reports `oci_warm_slots_ready`, `oci_warm_slots_booting`, `oci_warm_resident_mib`, `oci_warm_hits`,
`oci_warm_misses` and `oci_warm_last_claim_ms` (picking the slot to the container's agent answering). Each waiting slot holds its
memory, so size the pool to what you create in bursts.

Hibernating a claimed sandbox saves a VM whose root is on USB. If the saved state does not restore, waking falls back to a cold
boot from the same rootfs.

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
- Secrets: the request, including `env` and the agent token, is part of the VM record that `GET /v1/vms/{id}` returns to any
  token allowed to read the VM. Put credentials in `secret_env` instead: the daemon writes them to a 0600 `secrets.json` on the
  read-only `fluxvm-meta` share and init adds them to the process environment; they are not in the record, the API or the logs.
  The file stays in the VM's workspace, so later boots and restarts keep them, until the sandbox is deleted. `fluxctl sandbox run
  --secret-env NAME` takes the value of `NAME` from its own environment.

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
oci_warm_slots = 0                   # pre-booted VMs per size; see "Warm pool"
oci_warm_sizes = ["1x512"]

[[apple.oci_registry_credentials]]
registry = "ghcr.io"
username = "me"
keychain_service = "fluxvm-ghcr"     # or: password = "…"
```

With `keychain_service`, the password is not stored in the config: the daemon reads it from the login Keychain at pull time with
`security find-generic-password -s <service> -a <username> -w`. Store it once with
`security add-generic-password -s fluxvm-ghcr -a me -w` (it prompts for the token). Setting both `password` and
`keychain_service` is an error. The daemon runs as your user, so the login Keychain must be unlocked (it is while you are logged
in); macOS may ask once to allow `security` to read the item.

`policy.require_catalog_names` accepts only signed catalog names for VM images, so it refuses container sandboxes, whose root is a
cached rootfs path.

## Boot artifacts

`scripts/build-oci-boot.sh` runs on Linux arm64 and writes `dist/oci-boot/oci-kernel` and `oci-initrd`, each with a `.sha256`
file. The `oci-boot` CI workflow on `ubuntu-24.04-arm` builds and uploads them.

- **Kernel**: Linux 6.12 built from `crates/fluxvm-hypervisor/guest/oci-vz.config.fragment`, starting from `allnoconfig`. It
  includes virtio-pci, vsock, virtio-fs, ext4, overlayfs, cgroups, namespaces, seccomp, the PL031 clock, `binfmt_misc` and
  XHCI with USB mass storage (for the warm pool), with no modules.
  The script fails if any requested `=y` option does not survive Kconfig.
- **Initramfs**: zstd-compressed, containing:
  - static musl builds of `fluxvm-oci-init` (as `/init`) and `fluxvm-guest-agent`;
  - a static `mke2fs` (e2fsprogs 1.47.1).
- **Source downloads**: the kernel and e2fsprogs sources are checked against kernel.org's sha256 sums.

Put the two files in `state_dir/oci/boot`, register them as catalog entries, or point `apple.oci_kernel` and `apple.oci_initrd`
at them.

## Limits

- `linux/arm64` and `linux/amd64` (under Rosetta) only; no 32-bit or other architectures.
- No image building (`docker build`); pull images built elsewhere.
- No GPUs. Only TCP ports can be published, on the Mac's `127.0.0.1`; a server is also reachable through
  `/v1/sandboxes/{id}/http/{port}/…`, as for other sandboxes.
- Volumes are named directories managed by FluxVM; there are no bind mounts of arbitrary Mac paths into a container.
- The first use of an image pulls it and builds its rootfs (seconds to minutes, depending on its size). Later sandboxes from the
  same digest only clone it.
- The warm pool serves only plain NAT sandboxes of a configured size (see [Warm pool](#warm-pool)); the rest cold-boot.
  Hibernation uses the generic `vz` path and has not been tested on container sandboxes.
- A process's output beyond 10,000 lines between two polls is skipped by `fluxctl sandbox run`. The full console stays in the VM's
  `console.log` until the sandbox is deleted.
- Exec does not inherit the image's environment (see above).

## Verified

Unit tests cover:

- reference parsing, platform selection, digest checks and token auth;
- layer application with whiteouts, opaque directories and diff_id checks;
- user resolution and process resolution (Docker's entrypoint and cmd rules);
- the DHCP message parser and the console markers;
- the restart backoff and health-check counting, volume mount targets and host names;
- the request validation (ports, expose, volumes, health checks) and the VM request built for a container;
- the capability rules for tagged shares and `init_config`;
- the meta share contents.

CI builds the boot artifacts and runs `clippy -D warnings` and the tests for the init on Linux arm64.

`scripts/oci-live-test.sh` covers the following on Apple silicon. It has **not been run on hardware yet**, so the cold-start time
target (under 2 s with a cached rootfs) is not measured.

- exit codes, a read-only root with a writable `/tmp`, and uid 65534;
- argv exec in a distroless image;
- offline mode, an allow-list, and TTL expiry;
- the cold-start time.
