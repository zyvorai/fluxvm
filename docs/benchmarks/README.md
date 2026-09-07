# FluxVM sandbox benchmarks

Reproduce cold-start numbers for FluxVM sandboxes and MicroVM create→Running
on a KVM lab host.

## Prerequisites

- Linux x86_64 host with `/dev/kvm`
- `fluxvm serve` running (default `127.0.0.1:7788`)
- For MicroVM: k3s/`kubectl`, CRDs, and `fluxvm-microvm` controller + node-agent
- Boot assets (script defaults / env):

```bash
export IMAGE="${IMAGE:-/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4}"
export KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
# Optional: FLUXVM_TOKEN=… when auth.require is on
```

## Sandbox (REST `/v1/sandboxes`)

```bash
chmod +x scripts/bench-sandbox.sh
IMAGE=/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4 \
  KERNEL=/var/lib/fluxvm/kernels/vmlinux \
  FLUXVM_API=http://127.0.0.1:7788 BENCH_N=5 \
  FLUXVM_TOKEN=… ./scripts/bench-sandbox.sh
```

### Engine comparison

Set the host config engine before `serve`:

```toml
fluxvm_engine = "firecracker"   # default — Firecracker child under fluxvm-hypervisor
# fluxvm_engine = "kvm"         # pure in-tree KVM (no Firecracker child)
```

Restart `fluxvm serve` between runs and compare `avg_create_ms`.

## MicroVM (Kubernetes create → Running)

```bash
chmod +x scripts/bench-microvm.sh
# controller + node-agent must already be running against the cluster
BENCH_N=5 IMAGE=/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2 \
  ./scripts/bench-microvm.sh
```

Reports `avg_scheduled_ms`, `avg_running_ms`, and `p50_running_ms` (API apply →
`status.phase=Running`).

Lab one-shot (sandbox + MicroVM):

```bash
./scripts/run-lab-benches.sh
```

## Lab results (2026-09-08 · `sus@80.79.5.173`)

Host: Ubuntu 24.04 · Xeon E-2336 (12 threads) · 31 GiB RAM · k3s + FluxVM
`:7788`. `BENCH_N=5`. Numbers are wall-clock create latency, **not** steady-state
density or warm-pool claim.

### Sandbox (`backend: flux-vm`, network `none`)

Default engine (`fluxvm_engine` unset → **firecracker**). Image
`bionic-fabric-rootfs.ext4`, kernel `vmlinux`.

| Metric | Value |
|--------|-------|
| samples | 5348, 5721, 6448, 4775, 4932 ms |
| **avg_create_ms** | **5444** |

Earlier same-lab snapshot (2026-09-07): firecracker **6905** ms avg, kvm
**5783** ms avg — see history below.

### MicroVM (`backend: qemu`, `networkMode: user`, qcow2)

Image `fluxvm-lifecycle-test.qcow2`. Shadow Pod + node-agent → local `fluxvm
serve`.

| Metric | Value |
|--------|-------|
| avg_scheduled_ms | **1475** |
| **avg_running_ms** | **2655** |
| **p50_running_ms** | **2736** |
| samples (running_ms) | 1881, 2736, 1332, 3698, 3632 |

### How to read these

- Sandbox and MicroVM rows use **different** images/backends — do not treat the
  faster MicroVM wall time as “QEMU beats Firecracker density.”
- MicroVM time includes kube-apiserver + shadow Pod bind + agent `POST /v1/vms`.
- Do **not** treat kvm create latency as a density win over Firecracker warm
  pools / snapshots — see [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md).

## Earlier lab results (2026-09-07)

`BENCH_N=5`, image `bionic-fabric-rootfs.ext4`, kernel `vmlinux`, network `none`.

| Engine      | avg_create_ms | notes |
|-------------|---------------|-------|
| firecracker | **6905**      | production density engine; memory snapshots OK |
| kvm         | **5783**      | lab only — pause/resume real; memory snapshots still FC-only |
