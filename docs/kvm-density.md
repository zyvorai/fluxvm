# In-tree KVM density (`fluxvm_engine=kvm`)

Production sandbox density remains **Firecracker**. The in-tree KVM engine
is for lab packing experiments.

```toml
fluxvm_engine = "kvm"
```

Dense guest RAM (pre-fault + `mlock`):

```bash
export FLUXVM_KVM_LOCK_MEM=1
```

Requires `LimitMEMLOCK=infinity` on the systemd unit. MAP_POPULATE avoids
first-touch latency; mlock stops the host from reclaiming sandbox pages.

## Memory snapshots (lab)

Pause the guest, then `snapshot_save` / `snapshot_restore` on the hypervisor
control socket. The in-tree engine writes:

- `*.mem` — raw guest RAM (mmap dump)
- `*.vmstate` — `FLUXKVM1` header + GPRs + sregs (not Firecracker-compatible)

```bash
./scripts/test-kvm-snapshot-smoke.sh
./scripts/test-kvm-pause-smoke.sh
```

In-tree smokes use `init=/bin/sleep -- 3600` so the guest stays alive without
mounting root. Pass an **extensionless** snapshot path — the hypervisor appends
`.mem`, `.vmstate`, and `.rootfs` via `with_extension`. Pause and snapshot
promptly after boot (a delayed panic tears down the vCPU). VmLck / density checks
need matching `virtio_mmio.device=…` kernel args (same as the pause smoke).

Device (virtio) live state is not captured; restore re-attaches disks/TAP from
boot config and reloads RAM + CPU state. Use Firecracker for production
warm-pool snapshots.

## Concurrent density

```bash
BENCH_N=8 ./scripts/bench-density.sh
```

See [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md) and [benchmarks](benchmarks/README.md).
