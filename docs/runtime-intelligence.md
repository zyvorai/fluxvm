# FluxVM eBPF Runtime Intelligence v1

Runtime Intelligence is a node-local VM observability plane. It deliberately complements, rather than replaces, FluxVM Network Fabric and Zyvor Fabric.

## What v1 ships

- Stable 64-bit VM identity derived from the full FluxVM UUID.
- Userspace VM/TGID/TID registration in FluxVM-owned bpffs maps.
- KVM entry/exit tracepoints: exit count and accumulated guest-run nanoseconds.
- Scheduler wakeup/switch/migrate tracepoints: wakeups, runnable delay total/max, thread migrations.
- Procfs fallback: faults, CPU ticks, context switches, I/O bytes and thread count.
- cgroup-v2 PSI attribution for CPU, memory and I/O when the VM record has a cgroup path.
- Node-local REST: `/v1/intelligence/status`, `/v1/intelligence/vms`, `/v1/intelligence/vms/{uuid}`.
- Prometheus endpoint: `:7790/metrics`.
- A libbpf link-pinning loader; no permanent perf-event userspace process is required after attach.

## Ownership and safety

The BPF object owns only `/sys/fs/bpf/fluxvm/intelligence`. It reads scheduling/KVM telemetry and writes only its own maps. It does not inspect guest memory, packet payloads, Cilium maps, Kubernetes CNI maps, or VM disks.

## Build

```bash
sudo apt-get install clang llvm libbpf-dev pkg-config linux-tools-common linux-tools-$(uname -r)
./scripts/build-runtime-intelligence.sh
```

## Run

```bash
sudo ./dist/bin/fluxvm-intelligence-loader --load \
  ./dist/bpf/fluxvm_intelligence.bpf.o /sys/fs/bpf/fluxvm/intelligence

sudo env FLUXVM_API_URL=http://127.0.0.1:7788 \
  ./dist/bin/fluxvm-intelligence daemon
```

When FluxVM API auth is enabled set `FLUXVM_API_TOKEN` in the service environment.

```bash
curl -s http://127.0.0.1:7790/v1/intelligence/status | jq
curl -s http://127.0.0.1:7790/v1/intelligence/vms | jq
curl -s http://127.0.0.1:7790/metrics
```

## Direct host debugging

```bash
fluxvm-intelligence probe
sudo fluxvm-intelligence register <vm-uuid> <vmm-pid>
sudo fluxvm-intelligence snapshot <vm-uuid> <vmm-pid>
```

## Test gates

`./scripts/test-runtime-intelligence-static.sh` is unprivileged and runs Cargo/BPF/loader compilation when the toolchain is present. `sudo ./scripts/test-runtime-intelligence-host.sh` loads the BPF object and proves real scheduler event attribution. KVM counters require `/dev/kvm` plus an active KVM VM.

## v2 follow-ons

The ABI intentionally leaves room for KVM exit-reason histograms, block request latency, vhost/virtio queue attribution, TCP retransmit/drop correlation, TCX/BPF-link Network Fabric upgrades, migration state handoff, and optional BPF-LSM VMM guard.
