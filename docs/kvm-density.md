# In-tree KVM density (`fluxvm_engine=kvm`)

Production sandbox density remains **Firecracker**. The in-tree KVM engine
is for lab packing experiments and is past late-boot hang / root-mount
issues (Firecracker-matched TSS/MSRs/FPU/LAPIC/serial + auto `virtio_mmio.device=`).

```toml
fluxvm_engine = "kvm"
```

Dense guest RAM (pre-fault + `mlock`):

```bash
export FLUXVM_KVM_LOCK_MEM=1
# optional hugepage backing:
export FLUXVM_HUGEPAGES=1
```

Requires `LimitMEMLOCK=infinity` on the systemd unit. MAP_POPULATE avoids
first-touch latency; mlock stops the host from reclaiming sandbox pages.

## Memory snapshots (lab)

Pause the guest, then `snapshot_save` / `snapshot_restore` on the hypervisor
control socket. The in-tree engine writes:

- `*.mem` — raw guest RAM (mmap dump)
- `*.vmstate` — `FLUXKVM1` **v2**: all vCPU regs/sregs + virtio watermark
  (not Firecracker-compatible)

```bash
./scripts/test-kvm-snapshot-smoke.sh
./scripts/test-kvm-pause-smoke.sh
```

In-tree smokes can use a real rootfs (`root=/dev/vda`); the VMM appends
`virtio_mmio.device=…` automatically. Pass an **extensionless** snapshot path —
the hypervisor appends `.mem`, `.vmstate`, and `.rootfs` via `with_extension`.

Virtio **backend** live state is not fully serialized; restore re-attaches
disks/TAP/vsock from boot config and reloads RAM + all vCPU state. Use
Firecracker for production warm-pool snapshots.

## Concurrent density

```bash
BENCH_N=8 ./scripts/bench-density.sh
```

See [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md) and [benchmarks](benchmarks/README.md).
