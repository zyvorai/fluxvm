# Using FluxVM through zyvor-fabric

[zyvor-fabric](../../zyvor-fabric) is the other primary consumer of FluxVM, and the older/more
direct of the two integrations: unlike Ragnarok's Kubernetes CRD approach (see
[ragnarok.md](ragnarok.md)), zyvor-fabric talks straight to a host's `fluxvm serve` REST API
(`backend/crates/fluxvm-driver` + `fluxvm-client` hand-mirror FluxVM's own DTOs rather than
depending on this crate directly — see zyvor-fabric's `docs/guides/vm-drivers/fluxvm.md`), the same
API documented in [api.md](api.md). Fabric's VM lifecycle is FluxVM-only (`driver.fluxvm_url`);
there is no `machinectl` / systemd-machined backend.

## Getting zyvor-fabric

zyvor-fabric's own repo is private, so its build is published here instead, as a self-contained Linux
(x86_64) tarball — no cargo/npm required on the target machine — attached to this repo's
[`zyvor-fabric-vX.Y.Z`-tagged releases](https://github.com/zyvorai/fluxvm/releases). No container
image is published; install directly on the host:

```bash
curl -LO https://github.com/zyvorai/fluxvm/releases/download/zyvor-fabric-v0.1.0/zyvor-fabric-0.1.0-linux-x86_64.tar.gz
tar xzf zyvor-fabric-0.1.0-linux-x86_64.tar.gz
cd zyvor-fabric-0.1.0-linux-x86_64
sudo ./install.sh --start
```

The [release](https://github.com/zyvorai/fluxvm/releases/tag/zyvor-fabric-v0.1.0) also carries an
`INSTALL.md` with a full getting-started tutorial (first login, creating your first VM, networking,
verifying the install, upgrading). The tarball itself bundles `zyvor-fabricd`/`zyvorctl`, a matching
FluxVM build, guestkit's vendor agents, the web dashboard, systemd units for both
`zyvor-fabricd.service` and `fluxvm.service`, and default configs — `install.sh` wires all of it up
(see zyvor-fabric's own `scripts/build-dist.sh` for exactly what goes into the package and
`scripts/dist-install.sh` for what the installer does). This release build carries a 30-day
evaluation trial (existing VMs and read access stay available after it lapses; new writes need a
current trial or license — check remaining days via `GET /api/license` on the running daemon).
