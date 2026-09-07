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

Snapshots on this engine are still Firecracker-shaped when the child engine
is Firecracker. Pure KVM snapshots dump guest RAM from the mmap and are
lab-only (`crates/fluxvm-hypervisor/src/snapshot.rs` + memory clone).

See [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md) and [benchmarks](benchmarks/README.md).
