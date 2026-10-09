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
- No health-check restarts, secrets, or build steps. `run` only runs at first boot; use `after_up` for steps that need other services.
- Verified on an Apple M4 with the `vz` backend only.
