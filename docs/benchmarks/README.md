# FluxVM sandbox benchmarks

Reproduce rough cold-start numbers for the FluxVM hypervisor (`backend: flux-vm`) track.

## Prerequisites

- Linux x86_64 host with `/dev/kvm`
- `fluxvm serve` running (default `127.0.0.1:7788`)
- A bootable sandbox rootfs/kernel referenced in the create spec (adjust the script for your lab image)

## Run

```bash
chmod +x scripts/bench-sandbox.sh
FLUXVM_API=http://127.0.0.1:7788 BENCH_N=10 ./scripts/bench-sandbox.sh
```

## Engine comparison

Set the host config engine before `serve`:

```toml
fluxvm_engine = "firecracker"   # default — Firecracker child under fluxvm-hypervisor
# fluxvm_engine = "kvm"         # pure in-tree KVM (no Firecracker child)
```

Restart `fluxvm serve` between runs and compare `avg_create_ms`.

## Placeholder results (no CI KVM)

| Engine        | avg create (ms) | Notes                          |
|---------------|-----------------|--------------------------------|
| firecracker   | ~TBD            | Lab: run bench, paste below    |
| kvm           | ~TBD            | Lab only — not production density |

**How to fill:** on a KVM host with a bootable `/var/lib/fluxvm/images/base.raw`
(or edit the script image path), restart `fluxvm serve` once with each engine:

```bash
# firecracker (default)
FLUXVM_API=http://127.0.0.1:7788 BENCH_N=10 ./scripts/bench-sandbox.sh | tee /tmp/bench-fc.txt
# then set fluxvm_engine = "kvm", restart serve
FLUXVM_API=http://127.0.0.1:7788 BENCH_N=10 ./scripts/bench-sandbox.sh | tee /tmp/bench-kvm.txt
```

Paste `avg_create_ms` into the table. Do **not** claim density until Phase-2
virtio-blk works — see [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md).

### Lab notes (YYYY-MM-DD)

| Engine | avg_create_ms | host | notes |
|--------|---------------|------|-------|
| | | | |
