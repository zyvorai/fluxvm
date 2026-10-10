# Stacks: the VMs a project needs, in one file

A `fluxvm.toml` next to your code describes several VMs. `fluxctl up` brings them up in dependency order, `fluxctl down` removes
them, `fluxctl ps` lists them. A full example is in [`examples/fluxvm.toml`](../examples/fluxvm.toml).

```bash
fluxctl up            # create what is missing, start what is stopped, recreate what changed
fluxctl up db         # just db and what it depends on
fluxctl ps            # service, VM name, status, address
fluxctl ssh demo-app  # a stack VM is an ordinary VM: ssh, logs, snapshot… all work on demo-app
fluxctl down          # delete the stack's VMs, last-started first (--keep only stops them)
```

## The file

```toml
name = "demo"                    # stack name; VMs are called demo-<service>
[defaults]                       # image, cpus, memory_mib, user: used by every service unless it sets its own
[service.db]
packages = ["postgresql"]        # cloud-init, first boot
run = ["…"]                      # cloud-init commands, first boot
ports = ["5432:5432"]            # 127.0.0.1:HOST -> guest port (TCP)
expose = [5432]                  # ports other services may connect to
volumes = ["./:/srv/app"]        # HOST:GUEST[:ro]; relative paths are relative to the file
depends_on = ["db"]              # start order, and "recreate me if it is recreated"
ready = "pg_isready"             # must succeed in the guest before dependents start
after_up = ["…"]                 # run over SSH once all services are up, only for services created by this `up`
```

Unknown keys are errors. Names are `a-z`, `0-9` and `-`.

## Container services

A service with `container = "IMAGE"` runs that OCI image as a container sandbox: its own small VM, booted straight into the image,
with no SSH and no cloud-init ([oci-sandboxes.md](oci-sandboxes.md)). Container and VM services can be mixed in one stack.

```toml
name = "shop"
[service.db]
container = "postgres:17"
env = ["POSTGRES_PASSWORD=dev"]
expose = [5432]                            # reachable by other services as db:5432
volumes = ["pgdata:/var/lib/postgresql/data"]   # NAME:/path[:ro]: a named, persistent volume
ready = "pg_isready -U postgres"           # health check inside the container; dependents wait for it
restart = "always"                         # no (default), on-failure, always
[service.web]
container = "ghcr.io/acme/web:1"
command = ["gunicorn", "app:app", "-b", "0.0.0.0:8000"]
ports = ["8000:8000"]
depends_on = ["db"]
```

- `command`, `entrypoint`, `env` and `restart` are for container services only; `image`, `user`, `packages`, `run` and `after_up`
  are for VM services only. Mixing them is an error.
- `volumes` are named volumes (`NAME:/path[:ro]`, kept in the daemon's volumes directory) rather than folders from your checkout.
- `ready` becomes the container's health check, run as `/bin/sh -c "<ready>"` every 2 s; `up` waits until it reports healthy. An
  image without `/bin/sh` cannot use `ready`.
- The root filesystem is writable, as in Docker. `cpus` and `memory_mib` default to 1 and 512 MiB unless set here or in
  `[defaults]`.
- The services a container `depends_on` resolve by name inside it (both `db` and `shop-db`), through `/etc/hosts` entries init
  writes. VM services get every service name through the `/etc/hosts` block described below, so they reach container services too.

### Importing a docker-compose.yml

```bash
fluxctl import-compose docker-compose.yml --out fluxvm.toml   # or without --out to print it
```

`import-compose` converts the parts of Compose that map onto container services: `image`, `command`, `entrypoint`,
`environment`, `ports`, `expose`, named `volumes`, `depends_on`, `restart` (`unless-stopped` becomes `always`), `healthcheck`
(becomes `ready`), `cpus` and `mem_limit`. It prints a warning for everything it drops: bind mounts, UDP ports, ports bound to
an address other than `127.0.0.1`, exposed ports below 1024, and keys it does not know (`privileged`, `secrets`, …). `build` is
an error: build and push the image first. Service names are lower-cased and `_` becomes `-`. The stack name comes from `--name`,
the Compose `name:`, or the directory. Review the result before `fluxctl up`; in particular, Compose services reach each other
on any port, while here only `expose`d ports (1024 and up) are relayed.

## How services find each other

VMs on the Mac's NAT **cannot reach each other directly** (Virtualization.framework isolates them; each can reach only the Mac, at the
NAT gateway, `192.168.64.1`). So FluxVM relays through the Mac:

- Every service lists the TCP ports others may use in `expose`. The runner listens on exactly those ports **on the NAT gateway
  address only** (not on your LAN) and relays them to the service.
- After all services are up, `up` writes a block into each VM's `/etc/hosts` pointing every service name (`demo-db` and `db`) at the
  gateway. So `db:5432` from the app reaches the db.
- Consequences: exposed port numbers must be unique across the stack (checked), ports below 1024 are not allowed, only TCP, and only
  exposed ports are reachable. The `/etc/hosts` block is rewritten on every `up`, so it stays correct when addresses change.
- If the macOS application firewall is on, it may ask to allow incoming connections for `fluxvm-vz-runner` the first time.

## What `up` does on a second run

Each VM carries labels `fluxvm.stack`, `fluxvm.service` and `fluxvm.spec-hash` (a hash of the service's resolved definition). `up`:
leaves running, unchanged services alone; starts stopped ones; deletes and recreates a service whose definition changed, and any
service that depends on a recreated one (its `after_up` runs again). A service removed from the file is reported; `down` deletes it.
State lives in the daemon's VM labels, so it also works with `--server` and does not depend on the checkout.

## Limits

- Stack VMs cold-boot (about 10 s each; independent services start in parallel). They do not use the warm snapshots `fluxctl run` uses.
- No secrets or build steps. Restarts and health checks are for container services only. `run` only runs at first boot; use
  `after_up` for steps that need other services.
- A container service only resolves the names of the services it `depends_on`. The names are fixed when it is created.
- Verified on an Apple M4 with the `vz` backend only.
