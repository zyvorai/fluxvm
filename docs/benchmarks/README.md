# FluxVM sandbox benchmarks

Reproduce rough cold-start numbers for the FluxVM hypervisor (`backend: flux-vm`) track.

## Prerequisites

- Linux x86_64 host with `/dev/kvm`
- `fluxvm serve` running (default `127.0.0.1:7788`)
- Bootable image + kernel (script defaults / env):

```bash
export IMAGE="${IMAGE:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
export KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
# Optional: FLUXVM_TOKEN=… when auth.require is on
```

## Run

```bash
chmod +x scripts/bench-sandbox.sh
IMAGE=/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4 \
  KERNEL=/var/lib/fluxvm/kernels/vmlinux \
  FLUXVM_API=http://127.0.0.1:7788 BENCH_N=10 \
  FLUXVM_TOKEN=… ./scripts/bench-sandbox.sh
```

## Engine comparison

Set the host config engine before `serve`:

```toml
fluxvm_engine = "firecracker"   # default — Firecracker child under fluxvm-hypervisor
# fluxvm_engine = "kvm"         # pure in-tree KVM (no Firecracker child)
```

Restart `fluxvm serve` between runs and compare `avg_create_ms`.

## Lab results (2026-09-07 · `sus@80.79.5.173`)

`BENCH_N=5`, image `bionic-fabric-rootfs.ext4`, kernel `vmlinux`, network `none`.
Numbers are API create round-trip (not steady-state density / snapshot claim).

| Engine      | avg_create_ms | notes |
|-------------|---------------|-------|
| firecracker | **6905**      | production density engine; memory snapshots OK |
| kvm         | **5783**      | lab only — pause/resume real; memory snapshots still FC-only |

Do **not** treat kvm create latency as a density win over Firecracker warm pools /
snapshots — see [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md). virtio-blk + userspace
+ pause are Done on kvm; Phase **3c** memory snapshot restore remains FC.
